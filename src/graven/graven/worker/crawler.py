import concurrent
import queue
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from queue import LifoQueue, Queue
from threading import Event
from typing import List

import requests
from requests import RequestException

from db.cve_breadcrumbs_database import BreadcrumbsDatabase, Stage
from qmodel.message import Message
from shared.logger import logger
from shared.utils import Timer

"""
File: crawler.py
Description: Crawl maven central repo for urls

@author Derek Garcia
"""

MAVEN_HTML_REGEX = re.compile(
    "href=\"(?!\\.\\.)(?:(.*?/)|(.*?jar))\"(?:.*</a>\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2})|)")
# non-jars that can be skipped
SKIP_JAR_SUFFIXES = ("sources", "javadoc", "javadocs", "tests", "with-dependencies",
                     "shaded", "minimal", "all", "android", "native", "no-deps", "bin", "api", "sp", "full")


class CrawlerWorker:
    def __init__(self, database: BreadcrumbsDatabase,
                 download_queue: Queue[Message],
                 crawler_done_flag: Event,
                 update: bool,
                 max_concurrent_requests: int):
        """
        Create a new crawler worker that recursively parses the maven central file tree

        :param database: The database to store any error messages in
        :param download_queue: The shared queue to place jar urls once found
        :param crawler_done_flag: Flag to indicate to rest of pipeline that the crawler is finished
        :param update: Add jar url to download queue even if already in the database
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once
        """
        self._database = database
        self._update = update
        self._crawl_queue = LifoQueue()
        self._download_queue = download_queue
        self._crawler_done_flag = crawler_done_flag
        self._max_concurrent_requests = max_concurrent_requests
        self._timer = Timer()
        self._urls_seen = 0
        self._run_id = None

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
                # Skip if seen the url and not updating
                if not self._update and self._database.has_seen_jar_url(download_url):
                    logger.warn(f"Found jar url, but already seen. Skipping. . . | {download_url}")
                    continue

                # save jar url and timestamp
                message = Message(download_url, datetime.strptime(match.group(3).strip(), "%Y-%m-%d %H:%M"))
                self._download_queue.put(message)
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
                self._database.log_error(self._run_id, Stage.CRAWLER, url, e,
                                         comment="Failed to download page",
                                         details={'status_code': e.response.status_code})
            else:
                self._database.log_error(self._run_id, Stage.CRAWLER, url, e, "Failed to download page")
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.CRAWLER, url, e, "Error in crawl")

    def _process_url(self, url: str) -> None:
        """
        Wrapper task for submitting to thread pool
        Downloads the html and parses it for crawl and download urls

        :param url: URL to process
        """
        self._parse_html(url, self._download_html(url))
        self._crawl_queue.task_done()

    def _crawl(self, root_url: str, seed_urls: List[str] = None) -> None:
        """
       Continuously download and parse urls until the crawl urls is empty and retries exceeded

       :param root_url: Root url to start the crawler at
       :param seed_urls: Optional list of urls to restart crawler at once root has been exhausted
       """
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_concurrent_requests) as exe:
            # crawl until no urls left
            while True:
                try:
                    url = self._crawl_queue.get_nowait()
                    # Skip if seen the url and not updating
                    if not self._update and self._database.has_seen_domain_url(url):
                        logger.warn(f"Domain has already been explored. Skipping. . . | {url}")
                        self._crawl_queue.task_done()
                        continue
                    tasks.append(exe.submit(self._process_url, url))
                except queue.Empty:
                    # wait for task to finish to be absolutely sure no urls left
                    logger.warn(f"Queue is empty, ensuring tasks are done. . .")
                    concurrent.futures.wait(tasks)
                    # if there were urls left, retry
                    if not self._crawl_queue.empty():
                        logger.info(f"Found new urls to crawl, restarting")
                        continue
                    # report that this domain was searched
                    self._database.save_domain_url_as_seen(self._run_id, root_url, datetime.now(timezone.utc))
                    # restart with seed url if any left
                    if seed_urls:
                        new_root = seed_urls.pop(0)
                        new_root = new_root if new_root.endswith("/") else f"{new_root}/"  # check for '/'
                        logger.info(f"Crawler exhausted '{root_url}'. Restarting with '{new_root}'")
                        root_url = new_root
                        self._crawl_queue.put(root_url)
                        continue
                    # else exit
                    break

        logger.warn(f"Exhausted search space, waiting for remaining tasks to finish. . .")
        concurrent.futures.wait(tasks)

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the crawler
        """
        logger.info(f"Crawler completed in {self._timer.format_time()}")
        logger.info(
            f"Crawler has seen {self._urls_seen} urls ({self._timer.get_count_per_second(self._urls_seen):.01f} urls/s)")

    def start(self, run_id: int, root_url: str, seed_urls: List[str] = None) -> None:
        """
        Spawn and start the crawler worker thread

        :param run_id: ID of run
        :param root_url: Root url to start the crawler at
        :param seed_urls: Optional list of urls to restart crawler at once root has been exhausted
        """
        self._run_id = run_id
        # init crawler
        logger.info(f"Initializing crawler. . .")
        root_url = root_url if root_url.endswith("/") else f"{root_url}/"  # check for '/'
        self._crawl_queue.put(root_url)
        logger.info(f"Starting crawler at '{root_url}'")
        self._timer.start()
        # crawl
        self._crawl(root_url, seed_urls)
        # done
        self._crawler_done_flag.set()  # signal no more urls
        self._timer.stop()
        self.print_statistics_message()
