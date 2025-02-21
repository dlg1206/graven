"""
File: downloader.py

Description: Download jars into temp directories to be scanned

@author Derek Garcia
"""
import concurrent
import queue
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Event, Semaphore, Thread
from typing import Tuple

import requests
from common.logger import logger
from cve_breadcrumbs_database import BreadcrumbsDatabase, Stage
from requests import RequestException
from shared.analysis_task import AnalysisTask
from shared.heartbeat import Heartbeat
from shared.utils import Timer, first_time_wait_for_tasks

DEFAULT_MAX_JAR_LIMIT = 100  # limit the number of jars downloaded at one time
DOWNLOAD_QUEUE_TIMEOUT = 0


class DownloaderWorker:
    def __init__(self, database: BreadcrumbsDatabase,
                 download_queue: Queue[Tuple[str, str]],
                 analyze_queue: Queue[AnalysisTask],
                 crawler_done_flag: Event,
                 max_concurrent_requests: int,
                 download_limit: int
                 ):
        """
        Create a new downloader worker that asynchronously downloads jars from the maven central file tree

        :param database: The database to store any error messages in
        :param download_queue: Queue to pop urls of jars to download from
        :param analyze_queue: Queue of paths to jars to analyze to push to
        :param crawler_done_flag: Flag to indicate to rest of pipeline that the crawler is finished
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once
        :param download_limit: Max number of jars to be downloaded at one time
        """
        self._database = database
        self._download_queue = download_queue
        self._analyze_queue = analyze_queue
        self._crawler_done_flag = crawler_done_flag
        self._downloader_done_flag = Event()
        self._max_concurrent_requests = max_concurrent_requests
        self._download_limit = Semaphore(download_limit)

        self._heartbeat = Heartbeat("Downloader")
        self._timer = Timer()
        self._downloaded_jars = 0
        self._run_id = None

    def _download_jar(self, analysis_task: AnalysisTask) -> None:
        """
        Download jar

        :param analysis_task: Task with details about jar url and download location
        """
        start_time = time.time()
        with requests.get(analysis_task.get_url()) as response:
            response.raise_for_status()
            with open(analysis_task.get_file_path(), "wb") as file:
                file.write(response.content)
        logger.debug_msg(f"Downloaded {analysis_task.get_url()} in {time.time() - start_time:.2f}s")
        self._downloaded_jars += 1

    def _process_task(self, url: str, timestamp: str, download_dir_path: str) -> None:
        """
        Wrapper task for submitting to thread pool
        Downloads jar to file and updates the analyze queue

        :param url: URL of jar to download
        :param timestamp: Timestamp jar was uploaded
        :param download_dir_path: Path to directory to download jar to
        """
        analysis_task = AnalysisTask(url, timestamp, self._download_limit, download_dir_path)
        try:
            self._download_jar(analysis_task)
            self._analyze_queue.put(analysis_task)
        except RequestException as e:
            # failed to get jar
            logger.error_exp(e)
            if hasattr(e, 'response'):
                self._database.log_error(self._run_id, Stage.DOWNLOADER, url, e,
                                         comment="Failed to download jar",
                                         details={'status_code': e.response.status_code})
            else:
                self._database.log_error(self._run_id, Stage.DOWNLOADER, url, e, "Failed to download jar")
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.DOWNLOADER, url, e, "Error in download")
            analysis_task.cleanup()  # rm and release if anything goes wrong
        finally:
            self._download_queue.task_done()

    def _download(self, download_dir_path: str) -> None:
        """
        Continuously download jars until the download urls is empty and retries exceeded

        :param download_dir_path: Path to directory to download jars to
        """
        logger.info(f"Initializing downloader. . .")
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_concurrent_requests) as exe:
            first_time_wait_for_tasks("Downloader", self._download_queue,
                                      self._crawler_done_flag)  # block until items to process
            self._timer.start()
            # run while the crawler is still running or still tasks to process
            while not (self._crawler_done_flag.is_set() and self._download_queue.empty()):
                try:
                    # limit the max number of jars on system at one time
                    if not self._download_limit.acquire(timeout=30):
                        logger.warn("Failed to acquire lock; retrying. . .")
                        continue

                    url, timestamp = self._download_queue.get_nowait()
                    self._heartbeat.beat(self._download_queue.qsize())

                    # download jar
                    tasks.append(exe.submit(self._process_task, url, timestamp, download_dir_path))

                except queue.Empty:
                    """
                    To prevent deadlocks, the forced timeout with throw this error 
                    for another iteration of the loop to check conditions
                    """
                    self._download_limit.release()  # release to try again
                    continue

        logger.warn(f"No more jars to download, waiting for remaining tasks to finish. . .")
        concurrent.futures.wait(tasks)
        logger.warn(f"All downloads finished, exiting. . .")
        self._downloader_done_flag.set()  # signal no more jars
        # done
        self._timer.stop()
        self.print_statistics_message()

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the analyzer
        """
        logger.info(f"Downloader completed in {self._timer.format_time()}")
        logger.info(
            f"Downloader has downloaded {self._downloaded_jars} jars ({self._timer.get_count_per_second(self._downloaded_jars):.01f} jars / s)")

    def start(self, run_id: int, download_dir_path: str) -> Thread:
        """
        Spawn and start the downloader worker thread

        :param run_id: ID of run
        :param download_dir_path: Path to directory to download jars to
        :return: Downloader thread
        """
        self._run_id = run_id
        thread = Thread(target=self._download, args=(download_dir_path,))
        thread.start()
        return thread

    def get_analyze_queue(self) -> Queue[AnalysisTask]:
        """
        :return: analyze queue
        """
        return self._analyze_queue

    def get_downloader_done_flag(self) -> Event:
        """
        :return: Downloader done flag
        """
        return self._downloader_done_flag
