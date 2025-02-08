"""
File: crawler.py
Description: Crawl maven central repo for urls

@author Derek Garcia
"""
import asyncio
import re
import time
from asyncio import Semaphore, Queue, Event
from typing import Tuple

from aiohttp import ClientSession, TCPConnector

from log.logger import logger
from shared.defaults import DEFAULT_MAX_CONCURRENT_REQUESTS, DEFAULT_MAX_RETRIES, format_time
from shared.heartbeat import Heartbeat

# todo - update to exclude javadocs, sources, etc
MAVEN_HTML_REGEX = re.compile(
    "href=\"(?!\\.\\.)(?:(.*?/)|(.*?jar))\"(?:.*</a>\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2})|)")


class CrawlerWorker:
    def __init__(self, download_queue: Queue[Tuple[str, str]], crawler_done_event: Event,
                 max_retries: int = DEFAULT_MAX_RETRIES,
                 max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS):
        """
        Create a new crawler worker that asynchronously and recursively parses the maven central file tree

        :param download_queue: Queue to add urls of jars to download to
        :param crawler_done_event: Flag to indicate to rest of pipeline that the crawler is finished
        :param max_retries: Max number of retries to get a url from the crawl queue before exiting (default: 3)
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once (default: 50)
        """
        self._crawl_queue = Queue()
        self._download_queue = download_queue
        self._crawler_done_event = crawler_done_event
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
                await self._download_queue.put((download_url, match.group(3).strip()))  # save jar url and timestamp
                logger.debug_msg(f"Found jar url | {download_url}")

    async def _crawl(self, session: ClientSession) -> None:
        """
        Main crawl method. Will continuously download and parse urls until the crawl urls is empty and retries exceeded

        :param session: aiohttp session to use for requesting htmls
        """
        cur_retries = 0
        while cur_retries < self._max_retries:
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
                # sleep and try again
                cur_retries += 1
                logger.warn(f"No urls left in crawl queue, retrying ({cur_retries}/{self._max_retries}). . .")
                await asyncio.sleep(1)  # todo - might need to increase?

        logger.warn(f"Exceeded retries, exiting. . .")
        self._crawler_done_event.set()  # signal no more urls

    async def start(self, root_url: str) -> None:
        """
        Launch the crawler

        :param root_url: Root url to start the crawler at
        """
        # init crawler
        start_time = time.time()
        await self._crawl_queue.put(root_url if root_url.endswith("/") else f"{root_url}/")  # check for '/'
        logger.info(f"Starting crawler at '{root_url}'")
        # crawl until no urls left
        async with ClientSession(connector=TCPConnector(limit=50)) as session:
            await self._crawl(session)

        logger.info(f"Completed crawl in {format_time(time.time() - start_time)}")
