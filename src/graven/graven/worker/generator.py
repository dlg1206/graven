import concurrent
import os
from concurrent.futures import ThreadPoolExecutor
from math import ceil
from queue import Queue, Empty
from threading import Event

from anchore.syft import Syft, SyftScanFailure
from db.cve_breadcrumbs_database import BreadcrumbsDatabase, Stage
from qmodel.message import Message
from shared.logger import logger
from shared.utils import Timer, first_time_wait_for_tasks

"""
File: generator.py

Description: Use syft to generate SBOMs

@author Derek Garcia
"""

# ScannerWorker and AnalyzerWorker get the rest of the threads
DEFAULT_MAX_GENERATOR_THREADS = ceil(os.cpu_count() / 3)


class GeneratorWorker:
    def __init__(self, database: BreadcrumbsDatabase,
                 syft: Syft,
                 generator_queue: Queue[Message],
                 analyze_queue: Queue[Message],
                 downloader_done_flag: Event,
                 generator_done_flag: Event,
                 max_threads: int):
        """
        Create a new generator worker that spawns threads to process jars using syft

        :param database: The database to save grype results and store any error messages in
        :param syft: Syft interface to use for scanning
        :param generator_queue: Queue of jar details to generate SBOMs for
        :param analyze_queue: Queue of SBOM details to analyze
        :param downloader_done_flag: Flag to indicate to rest of pipeline that the downloader is finished
        :param generator_done_flag: Flag to indicate to rest of pipeline that the generator is finished
        :param max_threads: Max number of concurrent requests allowed to be made at once (default:ceil(os.cpu_count() / 3))
        """
        self._database = database
        self._syft = syft
        self._generator_queue = generator_queue
        self._scan_queue = analyze_queue
        self._downloader_done_flag = downloader_done_flag
        self._generator_done_flag = generator_done_flag
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

        try:
            message.open_syft_file(work_dir_path)
            return_code = self._syft.scan(message.jar_file.file_path, message.syft_file.file_path)
            self._scan_queue.put(message)
            self._sboms_generated += 1
            logger.info(f"Generated {message.syft_file.file_path}")
        except SyftScanFailure as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.GENERATOR, message.jar_url, e, "syft failed to scan")
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
            first_time_wait_for_tasks("Generator", self._generator_queue, self._downloader_done_flag)
            self._timer.start()
            # run while the downloader is still running or still tasks to process
            message = None
            while not (self._downloader_done_flag.is_set() and self._generator_queue.empty()):
                try:
                    message = self._generator_queue.get_nowait()
                    # scan
                    tasks.append(exe.submit(self._process_message, message, work_dir_path))
                except Empty:
                    """
                    To prevent deadlocks, the forced timeout with throw this error 
                    for another iteration of the loop to check conditions
                    """
                    continue
                except Exception as e:
                    logger.error_exp(e)
                    url = None
                    if message:
                        url = message.jar_url
                        message.close()

                    self._database.log_error(self._run_id, Stage.GENERATOR, url, e, "Failed during loop")

        logger.warn(f"No more jars to scan, waiting for scans to finish. . .")
        concurrent.futures.wait(tasks)
        self._generator_done_flag.set()  # signal no tasks

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

    @property
    def grype(self) -> Syft:
        return self._syft
