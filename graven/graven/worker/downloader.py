import tempfile
import time
from abc import ABC
from concurrent.futures import Future
from queue import Queue
from threading import Event
from typing import Any, Literal

import requests
from requests import RequestException

from db.graven_database import GravenDatabase, Stage, FinalStatus
from qmodel.message import Message
from shared.cache_manager import CacheManager, DEFAULT_MAX_CAPACITY, ExceedsCacheLimitError
from shared.logger import logger
from shared.timer import Timer
from worker.worker import Worker

"""
File: downloader.py

Description: Download jars into temp directories to be scanned

@author Derek Garcia
"""

DOWNLOAD_ACQUIRE_TIMEOUT = 30
RETRY_SLEEP = 10
DEFAULT_MAX_CONCURRENT_DOWNLOAD_REQUESTS = 20


class DownloaderWorker(Worker, ABC):
    def __init__(self, master_terminate_flag: Event, database: GravenDatabase,
                 generator_queue: Queue[Message | None],
                 crawler_first_hit_flag: Event = None,
                 crawler_done_flag: Event = None,
                 download_limit_bytes: int = DEFAULT_MAX_CAPACITY):
        """
        Create a new downloader worker that downloads jars from the maven central file tree

        :param master_terminate_flag: Master event to exit if keyboard interrupt
        :param database: The database to store any error messages in
        :param generator_queue: Queue of paths to jars to generate SBOMs for
        :param crawler_first_hit_flag: Flag to indicate that the crawler added a new URL if using crawler (Default: None)
        :param crawler_done_flag: Flag to indicate that the crawler is finished if using crawler (Default: None)
        :param download_limit_bytes: Limit the size of jars downloaded (Default: 5 GB)
        """
        super().__init__(master_terminate_flag, database, "downloader",
                         producer_queue=generator_queue)
        # crawler metadata
        self._crawler_first_hit_flag = crawler_first_hit_flag
        self._crawler_done_flag = crawler_done_flag
        # config
        self._cache_manager = CacheManager(download_limit_bytes)
        # stats
        self._downloaded_jars = 0
        # set at runtime
        self._run_id = None
        self._work_dir_path = None

    def _download_jar(self, message: Message) -> None:
        """
        Task to download jar from data in message

        :param message: Message with jar details
        """
        # skip if stop order triggered
        if self._master_terminate_flag.is_set():
            logger.debug_msg(f"[STOP ORDER RECEIVED] | Skipping download | {message.jar_url}")
            message.close()
            self._consumer_queue.task_done()
            return
        # attempt to download jar
        try:
            # init jar
            message.init_jar_file(self._cache_manager, self._work_dir_path)
            timer = Timer(True)
            with requests.get(message.jar_url) as response:
                response.raise_for_status()
                with open(message.jar_file.file_path, 'wb') as file:
                    file.write(response.content)
            # log success
            message.jar_file.open()
            logger.debug_msg(f"{'[STOP ORDER RECEIVED] | ' if self._master_terminate_flag.is_set() else ''}"
                             f"Downloaded in {timer.format_time()}s | {message.jar_url}")
            # update cache if needed
            self._cache_manager.update_space(message.jar_id, message.jar_file.get_file_size())
            self._downloaded_jars += 1
            # send downstream
            self._database.update_jar_status(message.jar_id, Stage.TRN_DWN_GEN)
            self._producer_queue.put(message)
        except (RequestException, Exception) as e:
            logger.error_exp(e)
            details = {'status_code': e.response.status_code} if hasattr(e, 'response') else None
            self._database.log_error(self._run_id, Stage.DOWNLOADER, e, jar_id=message.jar_id, details=details)
            # rm and release if anything goes wrong
            self._database.update_jar_status(message.jar_id, FinalStatus.ERROR)
            message.close()
        finally:
            # mark as done
            self._consumer_queue.task_done()

    def _handle_message(self, message: Message | str) -> Future | None:
        """
        Handle a message from the queue and return the future submitted to the executor
        Message has already been cleared for download

        :param message: The message to handle
        :return: Task if one was submitted, None otherwise
        """
        try:
            # ensure space available
            response = requests.head(message.jar_url, allow_redirects=True)
            content_length = int(response.headers.get('content-length', 0))  # todo - content is 0?
            # warn if length not present
            if not content_length:
                logger.warn(f"content-length is 0 | {message.jar_url}")
            # try to reserve space, requeue if no space
            if not self._cache_manager.reserve_space(message.jar_id, content_length):
                logger.warn("No space left in cache, trying later. . .")
                self._database.shelf_message(message.jar_id)
                return None
            # space reserved, kickoff job
            self._database.update_jar_status(message.jar_id, Stage.DOWNLOADER)
            return self._thread_pool_executor.submit(self._download_jar, message)
        except (RequestException, ExceedsCacheLimitError) as e:
            logger.error_exp(e)
            if isinstance(e, RequestException):
                # url dne - error and remove from pipeline
                details = {'status_code': e.response.status_code}
            else:
                # exceed total cache, reject
                details = {'file_size': e.file_size, 'exceeds_by': e.exceeds_by}
            # save error
            self._database.log_error(self._run_id, Stage.DOWNLOADER, e, jar_id=message.jar_id, details=details)
            self._database.update_jar_status(message.jar_id, FinalStatus.ERROR)
            message.close()

    def _handle_none_message(self) -> Literal['continue', 'break']:
        """
        Handle when get none message
        """
        # not using the crawler or are using and done flag is set - means no more jars will be found
        if not self._crawler_done_flag or self._crawler_done_flag.is_set():
            return 'break'
        # else using the crawler and more jars will come
        logger.warn(
            f"Found no jars to download but crawler is still running, sleeping for {RETRY_SLEEP}s. . .")
        time.sleep(RETRY_SLEEP)
        return 'continue'

    def _poll_consumer_queue(self) -> Message | str | None:
        """
        Get a message from the database
        """
        return self._database.get_message_for_update()

    def _pre_start(self, **kwargs: Any) -> None:
        """
        Set the working directory to download jars to

        :param root_dir: Temp root directory working in
        """
        self._work_dir_path = tempfile.mkdtemp(prefix='jar_', dir=kwargs['root_dir'])
        # if using the crawler, wait until find a hit
        # todo - option to skip wait
        if self._crawler_first_hit_flag:
            logger.info("Waiting for jar url to download. . .")
            self._crawler_first_hit_flag.wait()
            logger.info("jar url found, starting. . .")

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the analyzer
        """
        logger.info(f"Downloader completed in {self._timer.format_time()}")
        logger.info(
            f"Downloader has downloaded {self._downloaded_jars} jars ({self._timer.get_count_per_second(self._downloaded_jars):.01f} jars / s)")
