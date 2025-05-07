import concurrent
import re
from abc import ABC
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime, timezone
from queue import LifoQueue
from threading import Event
from typing import Any, Literal

import requests
from requests import RequestException

from db.graven_database import GravenDatabase, Stage, CrawlStatus
from qmodel.message import Message
from shared.logger import logger
from shared.utils import DEFAULT_MAX_CONCURRENT_REQUESTS
from worker.worker import Worker

"""
File: crawler.py
Description: Crawl maven central repo for urls

@author Derek Garcia
"""

MAVEN_HTML_REGEX = re.compile(
    "href=\"(?!\\.\\.)(?:(.*?/)|(.*?jar))\"(?:.*</a>\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2})|)")


class CrawlerWorker(Worker, ABC):
    def __init__(self, master_terminate_flag: Event, database: GravenDatabase,
                 crawler_first_hit_flag: Event | None,
                 crawler_done_flag: Event | None = None,
                 update_domain: bool = False,
                 update_jar: bool = False, max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS):
        """
        Create a new crawler worker that recursively parses the maven central file tree

        :param master_terminate_flag:: Master event to exit if keyboard interrupt
        :param database: The database to store any error messages in
        :param crawler_first_hit_flag: Flag to indicate that the crawler added a new URL if using crawler (Default: None)
        :param crawler_done_flag: Flag to indicate that the crawler is finished if using crawler (Default: None)
        :param update_domain: Update a domain if already seen (Default: False)
        :param update_jar: Update a jar if already seen (Default: False)
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once
        """
        super().__init__(master_terminate_flag, database, consumer_queue=LifoQueue())
        self._crawler_first_hit_flag = crawler_first_hit_flag
        self._crawler_done_flag = crawler_done_flag
        self._update_domain = update_domain
        self._update_jar = update_jar
        self._max_concurrent_requests = max_concurrent_requests
        self._urls_seen = 0
        # set at runtime
        self._current_domain = None
        self._seed_urls = None

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
                self._consumer_queue.put(crawl_url)
                logger.debug_msg(f"Found crawl url | {crawl_url}")
                continue
            # new download url
            if match.group(2):
                download_url = f"{url}{match.group(2)}"
                # Skip if seen the url and not updating
                if self._database.has_seen_jar_url(download_url) and not self._update_jar:
                    logger.warn(f"Found jar url, but already seen. Skipping. . . | {download_url}")
                    continue

                # save domain, jar url, and timestamp
                self._database.upsert_jar(self._run_id,
                                          download_url,
                                          datetime.strptime(match.group(3).strip(), "%Y-%m-%d %H:%M"))
                # set if first hit
                if self._crawler_first_hit_flag and not self._crawler_first_hit_flag.is_set():
                    self._crawler_first_hit_flag.set()
                logger.debug_msg(f"{'[STOP ORDER RECEIVED] | ' if self._master_terminate_flag.is_set() else ''}"
                                 f"Found jar url | {download_url}")

    def _download_html(self, url: str) -> str:
        """
        Download page and return the html content

        :param url: URL to download
        :return: HTML content
        """
        # prempt details incase of failure
        details = {
            'url': url
        }
        try:
            with requests.get(url) as response:
                response.raise_for_status()
                return response.text
        except RequestException as e:
            # failed to get url
            logger.error_exp(e)
            if hasattr(e, 'response'):
                details['status_code'] = e.response.status_code
            self._database.log_error(self._run_id, Stage.CRAWLER, e, details=details)
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.CRAWLER, e, details=details)

    def _process_url(self, url: str) -> None:
        """
        Wrapper task for submitting to thread pool
        Downloads the html and parses it for crawl and download urls

        :param url: URL to process
        """
        # skip if stop order triggered
        if self._master_terminate_flag.is_set():
            logger.debug_msg(f"[STOP ORDER RECEIVED] | Skipping crawl of {url}")
            self._consumer_queue.task_done()
            return
        self._parse_html(url, self._download_html(url))
        self._consumer_queue.task_done()

    def _handle_empty_consumer_queue(self) -> Literal['continue', 'break']:
        """
        Handle empty queue to determine when to exit

        :return: continue or break
        """
        # wait for task to finish to be absolutely sure no urls left
        logger.warn(f"Queue is empty, ensuring tasks are done. . .")
        concurrent.futures.wait(self._tasks)
        # if there were urls left, retry
        if not self._consumer_queue.empty():
            logger.info(f"Found new urls to crawl, restarting")
            return 'continue'

        # mark as complete if was progress and this run that started it
        if self._database.get_domain_status(self._current_domain) == CrawlStatus.IN_PROGRESS:
            self._database.complete_domain(self._run_id, self._current_domain, datetime.now(timezone.utc))

        # restart with seed url if any left
        if self._seed_urls:
            new_root = self._seed_urls.pop(0)
            new_root = new_root if new_root.endswith("/") else f"{new_root}/"  # check for '/'
            logger.info(f"Crawler exhausted '{self._current_domain}'. Restarting with '{new_root}'")
            self._current_domain = new_root
            # init if updating or dne
            if self._update_domain or self._database.get_domain_status(
                    self._current_domain) == CrawlStatus.DOES_NOT_EXIST:
                self._database.init_domain(self._run_id, self._current_domain)
                logger.debug_msg(f"Init crawler domain '{self._current_domain}'")
            self._consumer_queue.put(self._current_domain)
            return 'continue'
        # else exit
        return 'break'

    def _handle_message(self, message: Message | str) -> Future | None:
        """
        Handle a message from the queue and return the future submitted to the executor

        :param message: The message to handle
        """
        url = message
        if url == self._current_domain:
            crawl_status = self._database.get_domain_status(url)
            # if the crawl has not started, start it
            if crawl_status == crawl_status.NOT_STARTED:
                self._database.start_domain(url, datetime.now(timezone.utc))
                logger.debug_msg(f"Start crawler domain '{self._current_domain}'")
            # skip if already in progress or if complete and not updating
            elif crawl_status == CrawlStatus.IN_PROGRESS or (
                    crawl_status == CrawlStatus.COMPLETED and not self._update_domain):
                logger.warn(f"Domain has already been explored. Skipping. . . | {url}")
                self._consumer_queue.task_done()
                return None

        # else parse url
        return self._thread_pool_executor.submit(self._process_url, url)

    def _pre_start(self, **kwargs: Any) -> None:
        """
        Set root url and seed urls

        :param root_url: Root url to start the crawler at
        :param seed_urls: Optional list of urls to restart crawler at once root has been exhausted
        """
        # init urls
        root_url = kwargs['root_url']
        self._current_domain = root_url if root_url.endswith("/") else f"{root_url}/"  # check for '/'
        self._seed_urls = kwargs.get('seed_urls', [])
        # seed queue
        self._consumer_queue.put(self._current_domain)
        # init if updating or dne
        if self._update_domain or self._database.get_domain_status(self._current_domain) == CrawlStatus.DOES_NOT_EXIST:
            self._database.init_domain(self._run_id, self._current_domain)
            logger.debug_msg(f"Init crawler domain '{self._current_domain}'")
        logger.info(f"Starting crawler at '{self._current_domain}'")

    def _post_start(self) -> None:
        """
        Ensure flags are set correctly if in use
        """
        # indicate the crawler is finished
        if self._crawler_done_flag:
            self._crawler_done_flag.set()
        # ensure the hit flag it set if used regardless of any hits to not deadlock rest of the pipeline
        if self._crawler_first_hit_flag:
            self._crawler_first_hit_flag.set()

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the crawler
        """
        logger.info(f"Crawler completed in {self._timer.format_time()}")
        logger.info(
            f"Crawler has seen {self._urls_seen} urls ({self._timer.get_count_per_second(self._urls_seen):.01f} urls/s)")
