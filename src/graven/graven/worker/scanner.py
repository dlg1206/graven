import concurrent
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from queue import Queue, LifoQueue, Empty
from threading import Event

from anchore.grype import GrypeScanFailure, Grype
from db.cve_breadcrumbs_database import Stage, BreadcrumbsDatabase
from logger import logger
from shared.message import ScanMessage, ScribeMessage
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
                 scan_queue: Queue[ScanMessage],
                 scribe_queue: LifoQueue[ScribeMessage],
                 generator_done_flag: Event,
                 scanner_done_flag: Event,
                 max_threads: int):
        """
        Create a new scanner worker that spawns threads to process syft sboms using grype

        :param database: The database to save grype results and store any error messages in
        :param grype: Grype interface to use for scanning
        :param scan_queue: Queue of scan messages to scan
        :param scribe_queue: Queue of results to eventually write to the database
        :param generator_done_flag: Flag to indicate to rest of pipeline that the generator is finished
        :param scanner_done_flag: Flag to indicate to rest of pipeline that the scanner is finished
        :param max_threads: Max number of concurrent requests allowed to be made at once (default: cpu count / 2)
        """
        self._database = database
        self._grype = grype
        self._scan_queue = scan_queue
        self._scribe_queue = scribe_queue
        self._generator_done_flag = generator_done_flag
        self._scanner_done_flag = scanner_done_flag
        self._max_threads = max_threads

        self._timer = Timer()
        self._sboms_scanned = 0
        self._run_id = None

    def _grype_scan(self, scan_msg: ScanMessage) -> None:
        """
        Use grype to scan a jar

        :param scan_msg: Message with jar path and additional details
        """

        cve_ids = []
        # scan
        try:
            return_code = self._grype.scan(scan_msg.syft_sbom_path, scan_msg.get_grype_file_path())
            # return.code == 1, which means cves were found
            if return_code:
                # save results
                with open(scan_msg.get_grype_file_path(), "r") as file:
                    grype_data = json.load(file)
                scan_msg.cleanup()
                # get all cves
                cve_ids = list({vuln["vulnerability"]["id"] for vuln in grype_data["matches"] if
                                vuln["vulnerability"]["id"].startswith("CVE")})
                logger.info(
                    f"Scan found {len(cve_ids)} CVE{'' if len(cve_ids) == 1 else 's'} in {scan_msg.syft_sbom_path}")
            # add updates to queue to add later
            self._scribe_queue.put(
                ScribeMessage(scan_msg.url, scan_msg.publish_date, cve_ids, datetime.now(timezone.utc)))
            self._sboms_scanned += 1
        except GrypeScanFailure as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.SCANNER, scan_msg.url, e, "grype failed to scan")
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.SCANNER, scan_msg.url, e,
                                     "error when scanning with grype")
        finally:
            scan_msg.cleanup()
            self._scan_queue.task_done()

    def _analyze(self) -> None:
        """
        Main analyze method. Will continuously spawn threads to scan jars until
        the analysis queue is empty and retries exceeded
        """
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            first_time_wait_for_tasks("Scanner", self._scan_queue,
                                      self._generator_done_flag)  # block until items to process
            self._timer.start()
            # run while the generator is still running or still tasks to process
            while not (self._generator_done_flag.is_set() and self._scan_queue.empty()):
                scan_task = None
                try:
                    scan_task = self._scan_queue.get_nowait()
                    self._heartbeat.beat(self._scan_queue.qsize())
                    # scan
                    tasks.append(exe.submit(self._grype_scan, scan_task))
                except Empty:
                    """
                    To prevent deadlocks, the forced timeout with throw this error 
                    for another iteration of the loop to check conditions
                    """
                    continue
                except Exception as e:
                    logger.error_exp(e)
                    url = None
                    if scan_task:
                        url = scan_task.url
                        scan_task.cleanup()

                    self._database.log_error(self._run_id, Stage.SCANNER, url, e, "Failed during loop")

        logger.info(f"No more sboms to scan, waiting for scans to finish. . .")
        concurrent.futures.wait(tasks)
        self._scanner_done_flag.set()  # signal no tasks

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the scanner
        """
        logger.info(f"Scanner completed in {self._timer.format_time()} using {self._max_threads} threads")
        logger.info(
            f"Scanner has scanned {self._sboms_scanned} jars ({self._timer.get_count_per_second(self._sboms_scanned):.01f} jars / s)")

    def start(self, run_id: int) -> None:
        """
        Spawn and start the scanner worker thread

        :param run_id: ID of run
        """
        self._run_id = run_id
        logger.info(f"Initializing scanner . .")
        # start the scanner
        logger.info(f"Starting scanner using {self._max_threads} threads")
        self._analyze()
        # done
        self._timer.stop()
        self.print_statistics_message()

    @property
    def grype(self) -> Grype:
        return self._grype
