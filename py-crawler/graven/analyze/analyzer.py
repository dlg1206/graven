"""
File: analyzer.py

Description: Use grype to scan jars to find CVEs

@author Derek Garcia
"""

import concurrent
import json
import os
import queue
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from queue import Queue
from threading import Event, Thread

from db.cve_breadcrumbs_database import Stage, BreadcrumbsDatabase
from grype.grype import GrypeScanFailure, Grype
from log.logger import logger
from shared.analysis_task import AnalysisTask
from shared.heartbeat import Heartbeat
from shared.utils import Timer, first_time_wait_for_tasks

DEFAULT_MAX_ANALYZER_THREADS = os.cpu_count()
ANALYZE_QUEUE_TIMEOUT = 0


class AnalyzerWorker:
    def __init__(self, database: BreadcrumbsDatabase,
                 grype: Grype,
                 analyze_queue: Queue[AnalysisTask],
                 downloader_done_event: Event,
                 max_threads: int):
        """
        Create a new analyzer worker that spawns threads to process jars using grype

        :param database: The database to save grype results and store any error messages in
        :param grype: Grype interface to use for scanning
        :param analyze_queue: Queue of tasks to analyze
        :param downloader_done_event: Flag to indicate to rest of pipeline that the downloader is finished
        :param max_threads: Max number of concurrent requests allowed to be made at once (default: cpu count)
        """
        self._database = database
        self._grype = grype
        self._analyze_queue = analyze_queue
        self._downloader_done_event = downloader_done_event
        self._max_threads = max_threads

        self._heartbeat = Heartbeat("Analysis")
        self._timer = Timer()
        self._jars_scanned = 0
        self._run_id = None

    def _grype_scan(self, analysis_task: AnalysisTask) -> None:
        """
        Use grype to scan a jar

        :param analysis_task: Task with jar path and additional details
        """

        cve_ids = []
        # scan
        try:
            return_code = self._grype.scan(analysis_task.get_file_path(), analysis_task.get_grype_file_path())
            # return.code == 1, which means cves were found
            if return_code:
                # save results
                with open(analysis_task.get_grype_file_path(), "r") as file:
                    grype_data = json.load(file)
                analysis_task.cleanup()
                # get all cves
                cve_ids = list({vuln["vulnerability"]["id"] for vuln in grype_data["matches"] if
                                vuln["vulnerability"]["id"].startswith("CVE")})
                logger.info(
                    f"Scan found {len(cve_ids)} CVE{'' if len(cve_ids) == 1 else 's'} in {analysis_task.get_filename()}")

            self._database.upsert_jar_and_grype_results(self._run_id, analysis_task.get_url(),
                                                        analysis_task.get_publish_date(),
                                                        cve_ids, datetime.now(timezone.utc))
            self._jars_scanned += 1
        except GrypeScanFailure as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.ANALYZER, analysis_task.get_url(), e, "grype failed to scan")
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.ANALYZER, analysis_task.get_url(), e,
                                     "error when scanning with grype")
        finally:
            analysis_task.cleanup()
            self._analyze_queue.task_done()

    def _analyze(self) -> None:
        """
        Main analyze method. Will continuously spawn threads to scan jars until
        the analysis queue is empty and retries exceeded
        """
        logger.info(f"Initializing analyzer . .")
        # start the analyzer
        logger.info(f"Starting analyzer using {self._max_threads} threads")
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            first_time_wait_for_tasks("Analyzer", self._analyze_queue,
                                      self._downloader_done_event)  # block until items to process
            self._timer.start()
            # run while the downloader is still running or still tasks to process
            while not (self._downloader_done_event.is_set() and self._analyze_queue.empty()):
                analysis_task = None
                try:
                    analysis_task = self._analyze_queue.get_nowait()
                    self._heartbeat.beat(self._analyze_queue.qsize())
                    # scan
                    tasks.append(exe.submit(self._grype_scan, analysis_task))
                except queue.Empty:
                    """
                    To prevent deadlocks, the forced timeout with throw this error 
                    for another iteration of the loop to check conditions
                    """
                    continue
                except Exception as e:
                    logger.error_exp(e)
                    url = None
                    if analysis_task:
                        url = analysis_task.get_url()
                        analysis_task.cleanup()

                    self._database.log_error(self._run_id, Stage.ANALYZER, url, e, "Failed during loop")

        logger.warn(f"No more jars to scan, waiting for scans to finish. . .")
        concurrent.futures.wait(tasks)
        logger.warn(f"All scans finished, exiting. . .")
        # done
        self._timer.stop()
        self.print_statistics_message()

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the analyzer
        """
        logger.info(f"Analyzer completed in {self._timer.format_time()} using {self._max_threads} threads")
        logger.info(
            f"Analyzer has scanned {self._jars_scanned} jars ({self._timer.get_count_per_second(self._jars_scanned):.01f} jars / s)")

    def start(self, run_id: int) -> Thread:
        """
        Spawn and start the analyzer worker thread

        :param run_id: ID of run
        :return: Analyzer thread
        """
        self._run_id = run_id
        thread = Thread(target=self._analyze)
        thread.start()
        return thread
