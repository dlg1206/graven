"""
File: scanner.py

Description: Use grype to scan jars to find CVEs

@author Derek Garcia
"""

import tempfile
import time
from abc import ABC
from concurrent.futures import Future
from threading import Event
from typing import Any

from anchore.grype import GrypeScanFailure, Grype
from db.graven_database import Stage, GravenDatabase, FinalStatus
from qmodel.message import Message
from shared.cache_manager import CacheManager, BYTES_PER_MB, RESERVE_BACKOFF_TIMEOUT
from shared.logger import logger
from shared.timer import Timer
from worker.worker import Worker

# reserve .02 MB / 20 KB of space per grype report
GRYPE_SPACE_BUFFER = 0.02 * BYTES_PER_MB


class ScannerWorker(Worker, ABC):
    """
    Worker that constantly generate vulnerability reports using grype
    """

    def __init__(self, master_terminate_flag: Event, database: GravenDatabase,
                 grype: Grype,
                 cache_size: int):
        """
        Create a new scanner worker that spawns threads to process syft sboms using grype

        :param master_terminate_flag: Master event to exit if keyboard interrupt
        :param database: The database to save grype results and store any error messages in
        :param grype: Grype interface to use for scanning
        :param cache_size: Size of syft cache to use in bytes
        """
        super().__init__(master_terminate_flag, database, "scanner")
        # config
        self._grype = grype
        self._cache_manager = CacheManager(cache_size)
        # stats
        self._sboms_scanned = 0
        self._jars_scanned = 0
        self._seen_file = False
        # set at runtime
        self._run_id = None
        self._work_dir_path = None

    def _scan_with_grype(self, message: Message) -> None:
        """
        Use grype to scan a sbom

        :param message: Message with jar path and additional details
        """
        # skip if stop order triggered
        if self._master_terminate_flag.is_set():
            logger.warn(f"[STOP ORDER RECEIVED] | Skipping grype scan | {message.jar_id}")
            self._handle_shutdown(message)
            return
        # scan
        self._database.update_jar_status(message.jar_id, Stage.SCANNER)
        try:
            logger.debug_msg(f"Queuing grype | {message.jar_id}")
            # scan sbom or jar depending on what's available
            if message.syft_file and message.syft_file.is_open:
                file_path = message.syft_file.file_path
            else:
                file_path = message.jar_file.file_path

            self._grype.scan(file_path, message.grype_file.file_path)
            # report success
            message.grype_file.open()
            logger.info(f"Generated grype report | {message.grype_file.file_name}")

            # update counts
            if message.syft_file and message.syft_file.is_open:
                self._sboms_scanned += 1
            else:
                self._jars_scanned += 1
            # skip if stop order triggered
            if self._master_terminate_flag.is_set():
                logger.warn(f"[STOP ORDER RECEIVED] | Grype report generated but not processing | {message.jar_url}")
                self._handle_shutdown(message)
            else:
                self._database.update_jar_status(
                    message.jar_id, Stage.TRN_SCN_ANL)
                self._producer_queue.put(message)

        except (GrypeScanFailure, Exception) as e:
            message.close()
            logger.error_exp(e)
            details = None
            if isinstance(e, GrypeScanFailure):
                details = {'return_code': e.return_code, 'stderr': e.stderr}
            self._database.log_error(self._run_id, Stage.SCANNER, e, jar_id=message.jar_id, details=details)
            self._database.update_jar_status(message.jar_id, FinalStatus.ERROR)
        finally:
            # mark as done
            self._consumer_queue.task_done()
            # remove jar since finished
            message.jar_file.close()

    def _handle_message(self, message: Message | str) -> Future | None:
        """
        Handle a message from the queue and return the future submitted to the executor

        :param message: The message to handle
        :return: The Future task or None if now task made
        """
        # restart timer on first file
        if not self._seen_file:
            self._seen_file = True
            self._timer.start()

            # init file
        message.init_grype_file(self._cache_manager, self._work_dir_path)
        # try to reserve space, requeue if no space
        if not self._cache_manager.reserve_space(message.grype_file.file_name, GRYPE_SPACE_BUFFER):
            logger.warn("No space left in cache, trying later. . .")
            message.grype_file.close()
            self._consumer_queue.put(message)
            time.sleep(RESERVE_BACKOFF_TIMEOUT)
            return None
        # else process
        return self._thread_pool_executor.submit(self._scan_with_grype, message)

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the scanner
        """
        logger.info(f"Scanner completed in {self._timer.format_time()}")
        logger.info(f"Scanner has scanned {self._sboms_scanned} SBOMs "
                    f"({self._timer.get_count_per_second(self._sboms_scanned):.01f} SBOMs / s)")
        logger.info(f"Scanner has scanned {self._jars_scanned} jars")

    def _pre_start(self, **kwargs: Any) -> None:
        """
        Set the working directory to save grype output to

        :param root_dir: Temp root directory working in
        """
        self._work_dir_path = tempfile.mkdtemp(
            prefix='grype_', dir=kwargs['root_dir'])
