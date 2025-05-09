import tempfile
from abc import ABC
from concurrent.futures import Future
from queue import Queue
from threading import Event
from typing import Any

from anchore.syft import Syft, SyftScanFailure
from db.graven_database import GravenDatabase, Stage, FinalStatus
from qmodel.message import Message
from shared.cache_manager import CacheManager, BYTES_PER_MB
from shared.logger import logger
from worker.worker import Worker

"""
File: generator.py

Description: Use syft to generate SBOMs

@author Derek Garcia
"""

SYFT_SPACE_BUFFER = 0.5 * BYTES_PER_MB  # reserve .5 MB / 500 KB of space per sbom


class GeneratorWorker(Worker, ABC):
    def __init__(self, master_terminate_flag: Event, database: GravenDatabase, syft: Syft,
                 generator_queue: Queue[Message | None],
                 scan_queue: Queue[Message | None]):
        """
        Create a new generator worker that spawns threads to process jars using syft

        :param master_terminate_flag: Master event to exit if keyboard interrupt
        :param database: The database to save grype results and store any error messages in
        :param syft: Syft interface to use for scanning
        :param generator_queue: Queue of jar details to generate SBOMs for
        :param scan_queue: Queue of SBOM to scan with grype
        """
        super().__init__(master_terminate_flag, database, "generator",
                         consumer_queue=generator_queue,
                         producer_queue=scan_queue)
        # config
        self._syft = syft
        self._cache_manager = CacheManager()
        # stats
        self._sboms_generated = 0
        # set at runtime
        self._run_id = None
        self._work_dir_path = None

    def _generate_sbom(self, message: Message) -> None:
        """
        Use syft to scan a jar and generate an SBOM

        :param message: Message with jar path and additional details
        """

        # skip if stop order triggered
        if self._master_terminate_flag.is_set():
            logger.debug_msg(f"[STOP ORDER RECEIVED] | Skipping syft scan | {message.jar_id}")
            self._handle_shutdown(message)
            return
        # else generate sbom
        self._database.update_jar_status(message.jar_id, Stage.GENERATOR)
        try:
            logger.debug_msg(f"{'[STOP ORDER RECEIVED] | ' if self._master_terminate_flag.is_set() else ''}"
                             f"Queuing syft | {message.jar_id}")
            self._syft.scan(message.jar_file.file_path, message.syft_file.file_path)
            # remove jar since not needed
            message.jar_file.close()
            # report success
            message.syft_file.open()
            self._sboms_generated += 1
            logger.debug_msg(f"{'[STOP ORDER RECEIVED] | ' if self._master_terminate_flag.is_set() else ''}"
                             f"Generated syft sbom | {message.syft_file.file_name}")

        except SyftScanFailure as e:
            # if syft failed, report but don't skip
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.GENERATOR, e,
                                     jar_id=message.jar_id,
                                     details={'return_code': e.return_code, 'stderr': e.stderr})
            message.syft_file.close()  # remove sbom if generated
        except Exception as e:
            message.close()
            # some unknown error - log and exit early
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.GENERATOR, e, jar_id=message.jar_id)
            self._database.update_jar_status(message.jar_id, FinalStatus.ERROR)
            return
        finally:
            # mark as done
            self._consumer_queue.task_done()

        # update pipeline
        self._database.update_jar_status(message.jar_id, Stage.TRN_GEN_SCN)
        self._producer_queue.put(message)

    def _handle_message(self, message: Message | str) -> Future | None:
        """
        Handle a message from the queue and return the future submitted to the executor

        :param message: The message to handle
        :return: The Future task or None if now task made
        """
        # init file
        message.init_syft_file(self._cache_manager, self._work_dir_path)
        # try to reserve space, requeue if no space
        if not self._cache_manager.reserve_space(message.syft_file.file_name, SYFT_SPACE_BUFFER):
            logger.warn("No space left in cache, trying later. . .")
            message.syft_file.close()
            self._consumer_queue.put(message)
            return None
        # else process
        return self._thread_pool_executor.submit(self._generate_sbom, message)

    def _pre_start(self, **kwargs: Any) -> None:
        """
        Set the working directory to save SBOMs to

        :param root_dir: Temp root directory working in
        """
        self._work_dir_path = tempfile.mkdtemp(prefix='syft_', dir=kwargs['root_dir'])

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the generator
        """
        logger.info(f"Generator completed in {self._timer.format_time()}s")
        logger.info(
            f"Generator has generated {self._sboms_generated} SBOMs "
            f"({self._timer.get_count_per_second(self._sboms_generated):.01f} SBOMs / s)")

    def get_syft_version(self) -> str:
        """
        :return: Version of syft being used by this generator
        """
        return self._syft.get_version()
