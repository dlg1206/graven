"""
File: downloader.py

Description: 

@author Derek Garcia
"""
import asyncio
import time
from asyncio import Semaphore, Queue
from typing import Tuple

from aiohttp import ClientSession, TCPConnector

from log.logger import logger
from shared.analysis_task import AnalysisTask
from shared.defaults import DEFAULT_MAX_RETRIES, DEFAULT_MAX_CONCURRENT_REQUESTS, format_time
from shared.heartbeat import Heartbeat


class DownloaderWorker:
    def __init__(self, download_queue: asyncio.Queue[Tuple[str, str]], analyze_queue: asyncio.Queue[AnalysisTask],
                 max_retries: int = DEFAULT_MAX_RETRIES,
                 max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS):
        """
        Create a new downloader worker that asynchronously downloads jars from the maven central file tree

        :param download_queue: Queue to pop urls of jars to download from
        :param analyze_queue: Queue of paths to jars to analyze to push to
        :param max_retries: Max number of retries to get a url from the crawl queue before exiting (default: 3)
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once (default: 10)
        """
        self._download_queue = download_queue
        self._analyze_queue = analyze_queue
        self._max_retries = max_retries
        self._semaphore = Semaphore(max_concurrent_requests)
        self._heartbeat = Heartbeat()

    async def _download(self, session: ClientSession, download_limit: Semaphore) -> None:
        """
        Main download method. Will continuously download urls until the download urls is empty and retries exceeded

        :param session: aiohttp session to use for requesting jars
        :param download_limit: Semaphore to limit the number of jars to be downloaded at one time
        """
        first_download = True
        cur_retries = 0
        while cur_retries < self._max_retries:
            analysis_task = None
            try:
                # if first download, wait until jar to download
                if first_download:
                    logger.info("Downloader idle until download queue is populated")
                    url, timestamp = await self._download_queue.get()
                    first_download = False
                    logger.info("Jar url added; Downloader starting")
                else:
                    # If the queue is empty, will error
                    url, timestamp = self._download_queue.get_nowait()

                self._heartbeat.beat(self._download_queue.qsize())
                # limit to prevent the number of jars downloaded at one time, release after analysis
                await download_limit.acquire()

                async with self._semaphore:
                    async with session.get(url) as response:
                        response.raise_for_status()  # todo handle and log to database
                        analysis_task = AnalysisTask(url, timestamp, download_limit)
                        await analysis_task.save_file(response)
                logger.debug_msg(f"Downloaded {url}")
                # update queues and continue
                await self._analyze_queue.put(analysis_task)
                self._download_queue.task_done()
                cur_retries = 0

            except asyncio.QueueEmpty:
                # sleep and try again
                # todo - replace retry with signal
                cur_retries += 1
                logger.warn(f"No urls left in download queue, retrying ({cur_retries}/{self._max_retries}). . .")
                await asyncio.sleep(1)  # todo - might need to increase?

            except Exception as e:
                # todo error handling and reporting
                # todo replace with close method
                if analysis_task:
                    if analysis_task._tmp_dir:
                        analysis_task._tmp_dir.close()
                    download_limit.release()
                else:
                    download_limit.release()  # release if something goes wrong

        logger.warn(f"Exceeded retries, exiting. . .")

    async def start(self, download_limit: Semaphore) -> None:
        """
        Launch the downloader
        """
        start_time = time.time()
        logger.info(f"Starting downloader")
        # download until no urls left
        async with ClientSession(connector=TCPConnector(limit=50)) as session:
            await self._download(session, download_limit)

        logger.info(f"Completed download in {format_time(time.time() - start_time)}")
