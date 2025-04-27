import concurrent
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Event, Semaphore

import requests
from requests import RequestException

from db.graven_database import GravenDatabase, Stage, FinalStatus
from qmodel.file import JarFile
from qmodel.message import Message
from shared.logger import logger
from shared.timer import Timer
from shared.utils import DEFAULT_MAX_CONCURRENT_REQUESTS

"""
File: downloader.py

Description: Download jars into temp directories to be scanned

@author Derek Garcia
"""

DEFAULT_MAX_JAR_LIMIT = 100  # limit the number of jars downloaded at one time
DOWNLOAD_ACQUIRE_TIMEOUT = 30
RETRY_SLEEP = 10


class DownloaderWorker:
    def __init__(self, stop_flag: Event, database: GravenDatabase,
                 generator_queue: Queue[Message | None],
                 crawler_first_hit_flag: Event = None,
                 crawler_done_flag: Event = None,
                 max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
                 download_limit: int = DEFAULT_MAX_JAR_LIMIT
                 ):
        """
        Create a new downloader worker that downloads jars from the maven central file tree

        :param stop_flag: Master event to exit if keyboard interrupt
        :param database: The database to store any error messages in
        :param generator_queue: Queue of paths to jars to generate SBOMs for
        :param crawler_first_hit_flag: Flag to indicate that the crawler added a new URL if using crawler (Default: None)
        :param crawler_done_flag: Flag to indicate that the crawler is finished if using crawler (Default: None)
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once (Default: # cores)
        :param download_limit: Max number of jars to be downloaded at one time (Default: 100)
        """
        self._stop_flag = stop_flag
        self._database = database
        self._generator_queue = generator_queue
        self._crawler_first_hit_flag = crawler_first_hit_flag
        self._crawler_done_flag = crawler_done_flag
        self._max_concurrent_requests = max_concurrent_requests
        self._download_limit = Semaphore(download_limit)

        self._timer = Timer()
        self._downloaded_jars = 0
        self._run_id = None

    def _download_jar(self, jar_url: str, jar_file: JarFile) -> None:
        """
        Download jar

        :param jar_url: URL of jar to be downloaded
        :param jar_file: jar file Path to download jar to
        :return: Downloaded JarFile metadata object
        """
        start_time = time.time()
        with requests.get(jar_url) as response:
            response.raise_for_status()
            with open(jar_file.file_path, "wb") as file:
                file.write(response.content)
        logger.debug_msg(f"{'[STOP ORDER RECEIVED] | ' if self._stop_flag.is_set() else ''}"
                         f"Downloaded {jar_url} in {time.time() - start_time:.2f}s")
        self._downloaded_jars += 1

    def _process_message(self, message: Message, download_dir_path: str) -> None:
        """
        Wrapper task for submitting to thread pool
        Downloads jar to file and updates the analyze queue

        :param message: Message with download data
        :param download_dir_path: Path to directory to download jar to
        """
        # skip if stop order triggered
        if self._stop_flag.is_set():
            logger.debug_msg(f"[STOP ORDER RECEIVED] | Skipping download of {message.jar_url}")
            return
        try:
            # init jar
            message.open_jar_file(download_dir_path, self._download_limit)
            self._download_jar(message.jar_url, message.jar_file)
            self._database.update_jar_status(message.jar_id, Stage.TRN_DWN_GEN)
            self._generator_queue.put(message)
        except RequestException as e:
            # failed to get jar
            logger.error_exp(e)
            if hasattr(e, 'response'):
                self._database.log_error(self._run_id, Stage.DOWNLOADER, e,
                                         jar_id=message.jar_id,
                                         details={'status_code': e.response.status_code})
            else:
                self._database.log_error(self._run_id, Stage.DOWNLOADER, e, jar_id=message.jar_id)
            self._database.update_jar_status(message.jar_id, FinalStatus.ERROR)
            message.close()  # rm and release if anything goes wrong
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.DOWNLOADER, e, jar_id=message.jar_id)
            self._database.update_jar_status(message.jar_id, FinalStatus.ERROR)
            message.close()  # rm and release if anything goes wrong

    def _download(self, work_dir_path: str) -> None:
        """
        Continuously download jars until the download urls is empty and retries exceeded

        :param work_dir_path: Path to directory to download jars to
        """
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_concurrent_requests) as exe:
            # if using the crawler, wait until find a hit
            # todo - option to skip wait
            if self._crawler_first_hit_flag:
                logger.info("Waiting for jar url to download. . .")
                self._crawler_first_hit_flag.wait()
                logger.info("jar url found, starting. . .")

            self._timer.start()
            while not self._stop_flag.is_set():

                # limit the max number of jars on system at one time
                if not self._download_limit.acquire(timeout=DOWNLOAD_ACQUIRE_TIMEOUT):
                    logger.warn("Failed to acquire lock; retrying. . .")
                    continue

                message = self._database.get_message_for_update()
                # message is none means no more jobs
                if not message:
                    self._download_limit.release()
                    # not using the crawler or are using and done flag is set - means no more jars will be found
                    if not self._crawler_done_flag or self._crawler_done_flag.is_set():
                        break
                    # else using the crawler and more jars will come
                    logger.warn(
                        f"Found no jars to download but crawler is still running, sleeping for {RETRY_SLEEP}s. . .")
                    time.sleep(RETRY_SLEEP)
                    continue

                # download jar
                self._database.update_jar_status(message.jar_id, Stage.DOWNLOADER)
                tasks.append(exe.submit(self._process_message, message, work_dir_path))

        # log exit type
        if self._stop_flag.is_set():
            logger.warn(f"Stop order received, exiting. . .")
            concurrent.futures.wait(tasks, timeout=0)  # fail fast
        else:
            logger.warn(f"No more jars to download, waiting for remaining tasks to finish. . .")
            concurrent.futures.wait(tasks)
            logger.info(f"All downloads finished, exiting. . .")
        self._generator_queue.put(None)  # poison queue to signal stop

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the analyzer
        """
        logger.info(f"Downloader completed in {self._timer.format_time()}")
        logger.info(
            f"Downloader has downloaded {self._downloaded_jars} jars ({self._timer.get_count_per_second(self._downloaded_jars):.01f} jars / s)")

    def start(self, run_id: int, work_dir_path: str) -> None:
        """
        Spawn and start the downloader worker thread

        :param run_id: ID of run
        :param work_dir_path: Path to directory to download jars to
        """
        logger.info(f"Initializing downloader. . .")
        self._run_id = run_id
        self._download(work_dir_path)
        # done
        self._timer.stop()
        self.print_statistics_message()
