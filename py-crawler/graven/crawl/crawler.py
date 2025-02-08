"""
File: crawler.py
Description: Crawl maven central repo for urls

@author Derek Garcia
"""
import asyncio
import re
import time
from asyncio import Semaphore, Queue

from aiohttp import ClientSession, TCPConnector

from log.logger import logger, Level

DEFAULT_MAX_RETRIES = 3
DEFAULT_HEARTBEAT_INTERVAL = 5
DEFAULT_MAX_CONCURRENT_REQUESTS = 50

# todo - update to exclude javadocs, sources, etc
MAVEN_HTML_REGEX = re.compile(
    "href=\"(?!\\.\\.)(?:(.*?/)|(.*?jar))\"(?:.*</a>\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2})|)")


class Heartbeat:
    def __init__(self, interval: int = DEFAULT_HEARTBEAT_INTERVAL):
        """
        Create a new heartbeat to print snapshot details about the current state of the crawler
        Is disabled if logging is at debug level

        :param interval: Time in seconds between heartbeat messages
        """
        self._interval = interval
        self._last_heartbeat = None
        self._last_count = None

    def beat(self, queue_size: int) -> None:
        """
        Log a heartbeat message

        :param queue_size: Current size of the crawler queue
        """
        # skip if running in debug mode
        if logger.get_logging_level() == Level.DEBUG:
            return
            # skip if not time for heartbeat
        if self._last_heartbeat and time.time() - self._last_heartbeat < self._interval:
            return
        # calc change and print
        percent_change = ((queue_size - self._last_count) / self._last_count) * 100 if self._last_count else 100
        logger.info(f"Queue: {queue_size} ( {percent_change:.2f}% )")
        self._last_count = queue_size
        self._last_heartbeat = time.time()


class CrawlerWorker:
    def __init__(self, download_queue: Queue, max_retries: int = DEFAULT_MAX_RETRIES,
                 max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS):
        """
        Create a new crawler worker that asynchronously and recursively parses the maven central file tree

        :param download_queue: Queue to add urls of jars to download to
        :param max_retries: Max number of retries to get a url from the crawl queue before exiting (default: 3)
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once (default: 10)
        """
        self._crawl_queue = Queue()
        self._download_queue = download_queue
        self._max_retries = max_retries
        self._semaphore = Semaphore(max_concurrent_requests)
        self._heartbeat = Heartbeat("Crawler")

    async def _parse_html(self, url: str, html: str) -> None:
        """
        Parse the html and add new crawl and download urls to their respective queues

        :param url: URL source of html
        :param html: html content
        """
        # parse each match in the html
        for match in re.finditer(MAVEN_HTML_REGEX, html):
            # new crawl url
            if match.group(1):
                crawl_url = f"{url}{match.group(1)}"
                await self._crawl_queue.put(crawl_url)
                logger.debug_msg(f"Found crawl url | {crawl_url}")
                continue
            # new download url
            if match.group(2):
                download_url = f"{url}{match.group(2)}"
                await self._download_queue.put((download_url, match.group(3)))  # save jar url and timestamp
                logger.debug_msg(f"Found jar url | {download_url}")

    async def _crawl(self, session: ClientSession) -> None:
        """
        Main crawl method. Will continuously download and parse urls until the crawl urls is empty and retries exceeded

        :param session: aiohttp session to use for requesting htmls
        """
        cur_retries = 0
        while True:
            try:
                # If the queue is empty, will error
                url = self._crawl_queue.get_nowait()
                # download html
                async with self._semaphore:
                    async with session.get(url) as response:
                        response.raise_for_status()  # todo handle and log to database
                        html = await response.text()
                # update queues and continue
                await self._parse_html(url, html)
                self._crawl_queue.task_done()
                self._heartbeat.beat(self._crawl_queue.qsize())
                cur_retries = 0
            except asyncio.QueueEmpty:
                # exit if exceed retries
                if cur_retries >= self._max_retries:
                    logger.warn(f"No urls left in crawl queue, exiting. . .")
                    break
                # sleep and try again
                cur_retries += 1
                logger.warn(f"No urls left in crawl queue, retrying ({cur_retries}/{self._max_retries}). . .")
                await asyncio.sleep(1)  # todo - might need to increase?

    async def start(self, root_url: str) -> None:
        """
        Launch the crawler

        :param root_url: Root url to start the crawler at
        """
        # init crawler
        start_time = time.time()
        await self._crawl_queue.put(root_url)
        logger.info(f"Starting crawler at '{root_url}'")
        # crawl until no urls left
        async with ClientSession(connector=TCPConnector(limit=50)) as session:
            await self._crawl(session)
            await self._crawl_queue.join()

        logger.info(f"Completed crawl in {time.time() - start_time:.2f} seconds")
