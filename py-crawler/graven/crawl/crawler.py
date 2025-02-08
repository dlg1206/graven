"""
File: crawler.py
Description: Crawl maven central repo for urls

@author Derek Garcia
"""
import asyncio
import re
from asyncio import Semaphore, Queue

from aiohttp import ClientSession, TCPConnector

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
                await self._crawl_queue.put(f"{url}{match.group(1)}")
                print(f"found {url}{match.group(1)}")
                continue
            # save jar url and timestamp
            if match.group(2):
                await self._download_queue.put((f"{url}{match.group(2)}", match.group(3)))
                print(f"found {url}{match.group(2)}")

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
                if cur_retries >= self._max_retries:
                    print(f"Exceed max retries")
                    break
                print(f"Queue is empty, retrying...")
                cur_retries += 1
                await asyncio.sleep(0)  # todo - might need to increase?

        print(f"| done")

    async def start(self, root_url: str) -> None:
        await self._crawl_queue.put(root_url)
        async with ClientSession(connector=TCPConnector(limit=50)) as session:
            await self._crawl(session)
            await self._crawl_queue.join()
