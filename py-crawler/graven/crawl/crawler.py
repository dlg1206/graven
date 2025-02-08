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

from log.logger import logger

DEFAULT_MAX_CONCURRENT_REQUESTS = 10
DEFAULT_MAX_RETRIES = 3

# todo - update to exclude javadocs, sources, etc
MAVEN_HTML_REGEX = re.compile(
    "href=\"(?!\\.\\.)(?:(.*?/)|(.*?jar))\"(?:.*</a>\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2})|)")


class CrawlerWorker:
    def __init__(self, download_queue: Queue, max_retries: int,
                 max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS):
        self._crawl_queue = Queue()
        self._download_queue = download_queue
        self._max_retries = max_retries
        self._semaphore = Semaphore(max_concurrent_requests)

    async def _process_html(self, url: str, html: str) -> None:

        for match in re.finditer(MAVEN_HTML_REGEX, html):
            # new dir
            if match.group(1):
                crawl_url = f"{url}{match.group(1)}"
                await self._crawl_queue.put(crawl_url)
                logger.debug_msg(f"Found crawl url | {crawl_url}")
                continue
            # save jar url and timestamp
            if match.group(2):
                download_url = f"{url}{match.group(2)}"
                await self._download_queue.put((download_url, match.group(3)))
                logger.debug_msg(f"Found jar url | {download_url}")

    async def _crawl(self, session: ClientSession) -> None:
        cur_retries = 0
        while True:
            try:
                url = self._crawl_queue.get_nowait()

                async with self._semaphore:
                    async with session.get(url) as response:
                        response.raise_for_status()  # todo handle
                        html = await response.text()

                await self._process_html(url, html)
                self._crawl_queue.task_done()
                cur_retries = 0
            except asyncio.QueueEmpty:
                if cur_retries > self._max_retries:
                    logger.warn(f"No urls left in crawl queue, exiting. . .")
                    break
                logger.warn(f"No urls left in crawl queue, retrying ({cur_retries}/{self._max_retries}). . .")
                cur_retries += 1
                await asyncio.sleep(1)  # todo - might need to increase?

    async def start(self, root_url: str) -> None:
        start_time = time.time()
        await self._crawl_queue.put(root_url)
        logger.info(f"Starting crawler at '{root_url}'")
        async with ClientSession(connector=TCPConnector(limit=50)) as session:
            await self._crawl(session)
            await self._crawl_queue.join()
        logger.info(f"Completed crawl in {time.time() - start_time:.2f} seconds")
