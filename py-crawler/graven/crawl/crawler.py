"""
File: crawler.py
Description: Crawl maven central repo for urls

@author Derek Garcia
"""
import queue
import re
from concurrent.futures import ThreadPoolExecutor
from queue import LifoQueue, Queue
from threading import Event, Thread
from time import sleep
from typing import Tuple

import requests
from requests import RequestException

from db.cve_breadcrumbs_database import BreadcrumbsDatabase, Stage
from log.logger import logger
from shared.heartbeat import Heartbeat
from shared.utils import DEFAULT_MAX_CONCURRENT_REQUESTS, Timer

DEFAULT_MAX_RETRIES = 3
DEFAULT_TIMEOUT = 1
MAVEN_HTML_REGEX = re.compile(
    "href=\"(?!\\.\\.)(?:(.*?/)|(.*?jar))\"(?:.*</a>\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2})|)")
# non-jars that can be skipped
SKIP_JAR_SUFFIXES = ("sources", "javadoc", "javadocs", "tests", "with-dependencies",
                     "shaded", "minimal", "all", "android", "native", "no-deps", "bin", "api", "sp", "release", "full")


class CrawlerWorker:
    def __init__(self, database: BreadcrumbsDatabase, max_retries: int, max_concurrent_requests: int):
        """
        Create a new crawler worker that asynchronously and recursively parses the maven central file tree

        :param database: The database to store any error messages in
        :param max_retries: Max number of retries to get a url from the crawl queue before exiting
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once
        """
        self._database = database
        self._crawl_queue = LifoQueue()
        self._download_queue = Queue()
        self._crawler_done_flag = Event()
        self._max_retries = max_retries
        self._max_concurrent_requests = max_concurrent_requests
        self._heartbeat = Heartbeat("Crawler")
        self._timer = Timer()
        self._urls_seen = 0

    def _parse_html(self, url: str, html: str) -> None:
        """
        Parse the html and add new crawl and download urls to their respective queues

        :param url: URL source of html
        :param html: html content
        """
        # parse each match in the html
        for match in re.finditer(MAVEN_HTML_REGEX, html):
            self._urls_seen += 1
            # new crawl url
            if match.group(1):
                crawl_url = f"{url}{match.group(1)}"
                self._crawl_queue.put(crawl_url)
                logger.debug_msg(f"Found crawl url | {crawl_url}")
                continue
            # new download url
            if match.group(2) and not match.group(2).removesuffix(".jar").lower().endswith(SKIP_JAR_SUFFIXES):
                download_url = f"{url}{match.group(2)}"
                self._download_queue.put((download_url, match.group(3).strip()))  # save jar url and timestamp
                logger.debug_msg(f"Found jar url | {download_url}")

    def _download_html(self, url: str) -> str:
        """
        Download page and return the html content

        :param url: URL to download
        :return: HTML content
        """
        try:
            with requests.get(url) as response:
                response.raise_for_status()
                return response.text
        except RequestException as e:
            # failed to get url
            logger.error_exp(e)
            if hasattr(e, 'response'):
                self._database.log_error(Stage.CRAWLER, f"{e.response.status_code} | {str(e)}", url)
            else:
                self._database.log_error(Stage.CRAWLER, "Failed to download page", url)
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(Stage.CRAWLER, f"{type(e).__name__} | {e.__str__()}", url)

    def _process_url(self, url: str) -> None:
        """
        Wrapper task for submitting to thread pool
        Downloads the html and parses it for crawl and download urls

        :param url: URL to process
        """
        self._parse_html(url, self._download_html(url))
        self._crawl_queue.task_done()

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the crawler
        """
        logger.info(f"Crawler completed in {self._timer.format_time()}")
        logger.info(
            f"Crawler has seen {self._urls_seen} urls ({self._timer.get_count_per_second(self._urls_seen):.01f} urls/s)")

    def _crawl(self, root_url: str) -> None:
        """
       Continuously download and parse urls until the crawl urls is empty and retries exceeded

       :param root_url: Root url to start the crawler at
       """
        # init crawler
        logger.info(f"Initializing crawler. . .")
        root_url = root_url if root_url.endswith("/") else f"{root_url}/"  # check for '/'
        self._crawl_queue.put(root_url)
        logger.info(f"Starting crawler at '{root_url}'")
        # crawl until no urls left
        self._timer.start()
        cur_retries = 0
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_concurrent_requests) as exe:
            while cur_retries < self._max_retries:
                try:
                    url = self._crawl_queue.get_nowait()  # If the queue is empty, will error
                    tasks.append(exe.submit(self._process_url, url))
                    self._heartbeat.beat(self._crawl_queue.qsize())
                    cur_retries = 0
                except queue.Empty:
                    # sleep and try again
                    cur_retries += 1
                    logger.warn(f"No urls left in crawl queue, retrying ({cur_retries}/{self._max_retries}). . .")
                    sleep(DEFAULT_TIMEOUT)
        logger.warn(f"Exceeded retries. Waiting for remaining tasks to finish. . .")
        for task in tasks:
            task.result()
        # done
        self._crawler_done_flag.set()  # signal no more urls
        self._timer.stop()
        self.print_statistics_message()

    def start(self, root_url: str) -> Thread:
        """
        Spawn and start the crawler worker thread

        :param root_url: Root url to start the crawler at
        :return: Crawler thread
        """
        thread = Thread(target=self._crawl, args=(root_url,))
        thread.start()
        return thread

    def get_download_queue(self) -> Queue[Tuple[str, str]]:
        """
        :return: URL download queue
        """
        return self._download_queue

    def get_crawler_done_flag(self) -> Event:
        """
        :return: Crawler done flag
        """
        return self._crawler_done_flag
