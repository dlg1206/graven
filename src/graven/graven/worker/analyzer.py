import concurrent
import json
import os
import queue
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from queue import Queue
from threading import Event
from typing import List

from common.logger import logger

from anchore.grype import GrypeScanFailure, Grype
from shared.analysis_task import AnalysisTask
from shared.cve_breadcrumbs_database import Stage, BreadcrumbsDatabase
from shared.heartbeat import Heartbeat
from shared.utils import Timer, first_time_wait_for_tasks

"""
File: analyzer.py

Description: Use grype to scan jars to find CVEs

@author Derek Garcia
"""

DEFAULT_MAX_ANALYZER_THREADS = os.cpu_count()


@dataclass
class AnalysisResult:
    url: str
    publish_date: datetime
    cve_ids: List[str]
    last_scanned: datetime


class AnalyzerWorker:
    def __init__(self, database: BreadcrumbsDatabase,
                 grype: Grype,
                 analyze_queue: Queue[AnalysisTask],
                 scribe_queue: queue.LifoQueue,
                 downloader_done_flag: Event,
                 analyzer_done_flag: Event,
                 max_threads: int):
        """
        Create a new analyzer worker that spawns threads to process jars using grype

        :param database: The database to save grype results and store any error messages in
        :param grype: Grype interface to use for scanning
        :param analyze_queue: Queue of tasks to analyze
        :param scribe_queue: Queue of results to eventually write to the database
        :param downloader_done_flag: Flag to indicate to rest of pipeline that the downloader is finished
        :param analyzer_done_flag: Flag to indicate to rest of pipeline that the analyzer is finished
        :param max_threads: Max number of concurrent requests allowed to be made at once (default: cpu count)
        """
        self._database = database
        self._grype = grype
        self._analyze_queue = analyze_queue
        self._scribe_queue = scribe_queue
        self._downloader_done_flag = downloader_done_flag
        self._analyzer_done_flag = analyzer_done_flag
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
                    f"Scan found {len(cve_ids)} CVE{'' if len(cve_ids) == 1 else 's'} in {analysis_task.filename}")
            # add updates to queue to add later
            self._scribe_queue.put(
                AnalysisResult(analysis_task.url, analysis_task.publish_date, cve_ids, datetime.now(timezone.utc)))
            self._jars_scanned += 1
        except GrypeScanFailure as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.ANALYZER, analysis_task.url, e, "grype failed to scan")
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.ANALYZER, analysis_task.url, e,
                                     "error when scanning with grype")
        finally:
            analysis_task.cleanup()
            self._analyze_queue.task_done()

    def _analyze(self) -> None:
        """
        Main analyze method. Will continuously spawn threads to scan jars until
        the analysis queue is empty and retries exceeded
        """
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            first_time_wait_for_tasks("Analyzer", self._analyze_queue,
                                      self._downloader_done_flag)  # block until items to process
            self._timer.start()
            # run while the downloader is still running or still tasks to process
            while not (self._downloader_done_flag.is_set() and self._analyze_queue.empty()):
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
                        url = analysis_task.url
                        analysis_task.cleanup()

                    self._database.log_error(self._run_id, Stage.ANALYZER, url, e, "Failed during loop")

        logger.info(f"No more jars to scan, waiting for scans to finish. . .")
        concurrent.futures.wait(tasks)
        self._analyzer_done_flag.set()  # signal no tasks

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the analyzer
        """
        logger.info(f"Analyzer completed in {self._timer.format_time()} using {self._max_threads} threads")
        logger.info(
            f"Analyzer has scanned {self._jars_scanned} jars ({self._timer.get_count_per_second(self._jars_scanned):.01f} jars / s)")

    def start(self, run_id: int) -> None:
        """
        Spawn and start the analyzer worker thread

        :param run_id: ID of run
        """
        self._run_id = run_id
        logger.info(f"Initializing analyzer . .")
        # start the analyzer
        logger.info(f"Starting analyzer using {self._max_threads} threads")
        self._analyze()
        # done
        self._timer.stop()
        self.print_statistics_message()

    @property
    def grype(self) -> Grype:
        return self._grype
