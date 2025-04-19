import concurrent
import os
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from threading import Event

from anchore.grype import GrypeScanFailure, Grype
from db.cve_breadcrumbs_database import Stage, BreadcrumbsDatabase
from qmodel.message import Message
from shared.logger import logger
from shared.utils import Timer, first_time_wait_for_tasks

"""
File: scanner.py

Description: Use grype to scan jars to find CVEs

@author Derek Garcia
"""

DEFAULT_MAX_SCANNER_THREADS = os.cpu_count() / 2  # GeneratorWorker gets other half of threads


class ScannerWorker:
    def __init__(self, database: BreadcrumbsDatabase,
                 grype: Grype,
                 scan_queue: Queue[Message],
                 analyzer_queue: Queue[Message],
                 generator_done_flag: Event,
                 scanner_done_flag: Event,
                 max_threads: int):
        """
        Create a new scanner worker that spawns threads to process syft sboms using grype

        :param database: The database to save grype results and store any error messages in
        :param grype: Grype interface to use for scanning
        :param scan_queue: Queue of scan messages to scan
        :param analyzer_queue: Queue of results to eventually write to the database
        :param generator_done_flag: Flag to indicate to rest of pipeline that the generator is finished
        :param scanner_done_flag: Flag to indicate to rest of pipeline that the scanner is finished
        :param max_threads: Max number of concurrent requests allowed to be made at once (default: cpu count / 2)
        """
        self._database = database
        self._grype = grype
        self._scan_queue = scan_queue
        self._analyze_queue = analyzer_queue
        self._generator_done_flag = generator_done_flag
        self._scanner_done_flag = scanner_done_flag
        self._max_threads = max_threads

        self._timer = Timer()
        self._sboms_scanned = 0
        self._run_id = None

    def _process_message(self, message: Message, work_dir_path: str) -> None:
        """
        Use grype to scan a sbom

        :param message: Message with jar path and additional details
        :param work_dir_path: Path to save the generated grype reports to
        """

        # scan
        try:
            message.open_grype_file(work_dir_path)
            return_code = self._grype.scan(message.syft_file.file_path, message.grype_file.file_path)
            # if return code != 1, then cves we not found
            if not return_code:
                logger.debug_msg(f"No CVEs found in {message.grype_file.file_path}")
                message.grype_file.close()
            else:
                logger.info(f"Generated {message.grype_file.file_path}")
            # add updates to queue to add later
            self._analyze_queue.put(message)
            self._sboms_scanned += 1
        except GrypeScanFailure as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.SCANNER, message.jar_url, e, "grype failed to scan")
            message.close()
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.SCANNER, message.jar_url, e, "error when scanning with grype")
            message.close()
        finally:
            self._scan_queue.task_done()

    def _scan(self, work_dir_path: str) -> None:
        """
        Main scan method. Will continuously spawn threads to scan SBOMs until
        the scan queue is empty and retries exceeded

        :param work_dir_path: Path to save the generated grype reports to
        """
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            first_time_wait_for_tasks("Scanner", self._scan_queue,
                                      self._generator_done_flag)  # block until items to process
            self._timer.start()
            # run while the generator is still running or still tasks to process
            message = None
            while not (self._generator_done_flag.is_set() and self._scan_queue.empty()):

                try:
                    message = self._scan_queue.get_nowait()
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

                    self._database.log_error(self._run_id, Stage.SCANNER, url, e, "Failed during loop")

        logger.warn(f"No more sboms to scan, waiting for scans to finish. . .")
        concurrent.futures.wait(tasks)
        self._scanner_done_flag.set()  # signal no tasks

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the scanner
        """
        logger.info(f"Scanner completed in {self._timer.format_time()} using {self._max_threads} threads")
        logger.info(
            f"Scanner has scanned {self._sboms_scanned} jars ({self._timer.get_count_per_second(self._sboms_scanned):.01f} jars / s)")

    def start(self, run_id: int, work_dir_path: str) -> None:
        """
        Spawn and start the scanner worker thread

        :param run_id: ID of run
        :param work_dir_path: Path to save the grype reports to
        """
        self._run_id = run_id
        logger.info(f"Initializing scanner . .")
        # start the scanner
        logger.info(f"Starting scanner using {self._max_threads} threads")
        self._scan(work_dir_path)
        # done
        self._timer.stop()
        self.print_statistics_message()

    @property
    def grype(self) -> Grype:
        return self._grype
