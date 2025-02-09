"""
File: downloader.py

Description: Download jars into temp directories to be scanned

@author Derek Garcia
"""
import asyncio
import os
import threading
import time
from asyncio import Semaphore, Event
from typing import Tuple

from aiohttp import ClientSession, TCPConnector, ClientResponseError

from db.cve_breadcrumbs_database import BreadcrumbsDatabase, Stage
from log.logger import logger
from shared.analysis_task import AnalysisTask
from shared.defaults import DEFAULT_MAX_CONCURRENT_REQUESTS, format_time
from shared.heartbeat import Heartbeat

DEFAULT_MAX_JAR_LIMIT = 2 * os.cpu_count()  # limit the number of jars downloaded at one time


class DownloaderWorker:
    def __init__(self, database: BreadcrumbsDatabase, download_queue: asyncio.Queue[Tuple[str, str]],
                 analyze_queue: asyncio.Queue[AnalysisTask],
                 crawler_done_event: Event,
                 downloader_done_event: Event,
                 max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS):
        """
        Create a new downloader worker that asynchronously downloads jars from the maven central file tree

        :param database: The database to store any error messages in
        :param download_queue: Queue to pop urls of jars to download from
        :param analyze_queue: Queue of paths to jars to analyze to push to
        :param crawler_done_event: Flag to indicate to rest of pipeline that the crawler is finished
        :param downloader_done_event: Flag to indicate to rest of pipeline that the downloader is finished
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once (default: 10)
        """
        self._database = database
        self._download_queue = download_queue
        self._analyze_queue = analyze_queue
        self._crawler_done_event = crawler_done_event
        self._downloader_done_event = downloader_done_event
        self._semaphore = Semaphore(max_concurrent_requests)
        self._heartbeat = Heartbeat("Downloader")

    async def _download(self, session: ClientSession,
                        download_limit: threading.Semaphore,
                        download_dir_path: str) -> None:
        """
        Main download method. Will continuously download urls until the download urls is empty and retries exceeded

        :param session: aiohttp session to use for requesting jars
        :param download_limit: Semaphore to limit the number of jars to be downloaded at one time
        :param download_dir_path: Path to directory to download jars to
        """
        url = None
        # run while the crawler is still running or still tasks to process
        while not (self._crawler_done_event.is_set() and self._download_queue.empty()):
            analysis_task = None
            try:
                url, timestamp = await asyncio.wait_for(self._download_queue.get(), timeout=1)
                self._heartbeat.beat(self._download_queue.qsize())
                # limit to prevent the number of jars downloaded at one time, release after analysis
                download_limit.acquire()
                # download jar
                async with self._semaphore:
                    async with session.get(url) as response:
                        response.raise_for_status()
                        analysis_task = AnalysisTask(url, timestamp, download_limit, download_dir_path)
                        with open(analysis_task.get_file_path(), "wb") as file:
                            file.write(await response.read())
                logger.debug_msg(f"Downloaded {url}")
                # update queues and continue
                await self._analyze_queue.put(analysis_task)
                self._download_queue.task_done()
                url = None  # reset for error logging
            except asyncio.TimeoutError:
                """
                To prevent deadlocks, the forced timeout with throw this error 
                for another iteration of the loop to check conditions
                """
                continue
            except ClientResponseError as e:
                # failed to get url
                logger.error_exp(e)
                self._database.log_error(Stage.DOWNLOADER, f"{e.status} | {e.message}", url)
            except Exception as e:
                logger.error_exp(e)
                self._database.log_error(Stage.DOWNLOADER, f"{type(e).__name__} | {e.__str__()}", url)
                if analysis_task:
                    analysis_task.cleanup()
                else:
                    download_limit.release()  # release if something goes wrong

        logger.warn(f"No more jars to download, exiting. . .")
        self._downloader_done_event.set()  # signal no more jars

    async def start(self, download_limit: Semaphore, download_dir_path: str) -> None:
        """
        Launch the downloader

        :param download_limit: Semaphore to limit the number of jars to be downloaded at one time
        :param download_dir_path: Path to directory to download jars to
        """
        start_time = time.time()
        logger.info(f"Starting downloader")
        # download until no urls left
        async with ClientSession(connector=TCPConnector(limit=50)) as session:
            await self._download(session, download_limit, download_dir_path)

        logger.info(f"Completed download in {format_time(time.time() - start_time)}")
