import concurrent
import os
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from threading import Event

from anchore.syft import Syft, SyftScanFailure
from db.graven_database import GravenDatabase, Stage
from qmodel.message import Message
from shared.logger import logger
from shared.utils import Timer

"""
File: generator.py

Description: Use syft to generate SBOMs

@author Derek Garcia
"""

# ScannerWorker and AnalyzerWorker get the rest of the threads
DEFAULT_MAX_GENERATOR_THREADS = int(os.cpu_count() / 2)


class GeneratorWorker:
    def __init__(self, stop_flag: Event, database: GravenDatabase,
                 syft: Syft,
                 generator_queue: Queue[Message | None],
                 analyze_queue: Queue[Message | None],
                 max_threads: int = DEFAULT_MAX_GENERATOR_THREADS):
        """
        Create a new generator worker that spawns threads to process jars using syft

        :param stop_flag: Master event to exit if keyboard interrupt
        :param database: The database to save grype results and store any error messages in
        :param syft: Syft interface to use for scanning
        :param generator_queue: Queue of jar details to generate SBOMs for
        :param analyze_queue: Queue of SBOM details to analyze
        :param max_threads: Max number of concurrent requests allowed to be made at once
        """
        self._stop_flag = stop_flag
        self._database = database
        self._syft = syft
        self._generator_queue = generator_queue
        self._scan_queue = analyze_queue
        self._max_threads = max_threads

        self._timer = Timer()
        self._sboms_generated = 0
        self._run_id = None

    def _process_message(self, message: Message, work_dir_path: str) -> None:
        """
        Use syft to scan a jar and generate an SBOM

        :param message: Message with jar path and additional details
        :param work_dir_path: Path to save the generated SBOMs to
        """
        # skip if stop order triggered
        if self._stop_flag.is_set():
            logger.debug_msg(f"[STOP ORDER RECEIVED] | Skipping syft scan of {message.syft_file.file_path}")
            message.close()
            self._generator_queue.task_done()
            return
        try:
            logger.debug_msg(f"{'[STOP ORDER RECEIVED] | ' if self._stop_flag.is_set() else ''}"
                             f"Queuing syft: {message.jar_file.file_path}")
            message.open_syft_file(work_dir_path)
            return_code = self._syft.scan(message.jar_file.file_path, message.syft_file.file_path)
            # report error and continue
            if return_code:
                logger.debug_msg(f"syft scan of {message.syft_file.file_path} had a non-zero exit code: {return_code}")
                self._database.log_error(self._run_id, Stage.GENERATOR, message.jar_url,
                                         SyftScanFailure(message.syft_file.file_name, return_code),
                                         details={'return_code': return_code})
                # If cannot generate SBOM, fail early - don't continue down this path
                message.syft_file.close()
            else:
                # Else pass down pipeline
                self._sboms_generated += 1
                logger.info(f"{'[STOP ORDER RECEIVED] | ' if self._stop_flag.is_set() else ''}"
                            f"Generated '{message.syft_file.file_name}'")
                self._scan_queue.put(message)

        except SyftScanFailure as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.GENERATOR,
                                     message.jar_url, e, details={'return_code': e.return_code, 'stderr': e.stderr})
            message.syft_file.close()  # remove sbom if generated
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.GENERATOR, message.jar_url, e,
                                     "error when generating with syft")
            message.syft_file.close()  # remove sbom if generated
        finally:
            message.jar_file.close()  # always remove jar
            self._generator_queue.task_done()

    def _generate(self, work_dir_path: str) -> None:
        """
        Main generate method. Will continuously spawn threads to scan jars until the generate queue is empty and
        retries exceeded

        :param work_dir_path: Path to save the generated SBOMs to
        """
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            # block until items to process
            # first_time_wait_for_tasks("Generator", self._generator_queue, self._downloader_done_flag)
            # todo - waiting logic
            self._timer.start()
            while not self._stop_flag.is_set():
                try:
                    message = self._generator_queue.get_nowait()

                    # break if poison pill - ie no more jobs
                    if not message:
                        break
                    # scan
                    tasks.append(exe.submit(self._process_message, message, work_dir_path))
                except Empty:
                    """
                    To prevent deadlocks, the forced timeout with throw this error 
                    for another iteration of the loop to check conditions
                    """
                    continue

        if self._stop_flag.is_set():
            logger.warn(f"Stop order received, exiting. . .")
            concurrent.futures.wait(tasks, timeout=0)  # fail fast
        else:
            logger.warn(f"No more jars to scan, waiting for scans to finish. . .")
            concurrent.futures.wait(tasks)
            logger.info(f"All jars scanned, exiting. . .")
        self._scan_queue.put(None)  # poison queue to signal stop

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the generator
        """
        logger.info(f"Generator completed in {self._timer.format_time()} using {self._max_threads} threads")
        logger.info(
            f"Generator has generated {self._sboms_generated} SBOMs ({self._timer.get_count_per_second(self._sboms_generated):.01f} jars / s)")

    def start(self, run_id: int, work_dir_path: str) -> None:
        """
        Spawn and start the generator worker thread

        :param run_id: ID of run
        :param work_dir_path: Path to save the generated SBOMs to
        """
        self._run_id = run_id
        logger.info(f"Initializing generator . .")
        # start the analyzer
        logger.info(f"Starting generator using {self._max_threads} threads")
        self._generate(work_dir_path)
        # done
        self._timer.stop()
        self.print_statistics_message()

    def get_syft_version(self) -> str:
        """
        :return: Version of syft being used by this generator
        """
        return self._syft.get_version()
