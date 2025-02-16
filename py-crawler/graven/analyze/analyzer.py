"""
File: analyzer.py

Description: Use grype to scan jars to find CVEs

@author Derek Garcia
"""

import concurrent
import json
import os
import platform
import queue
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from queue import Queue
from threading import Event, Thread

from db.cve_breadcrumbs_database import Stage, BreadcrumbsDatabase
from log.logger import logger
from shared.analysis_task import AnalysisTask
from shared.heartbeat import Heartbeat
from shared.utils import Timer, first_time_wait_for_tasks

DEFAULT_MAX_ANALYZER_THREADS = os.cpu_count()
GRYPE_BIN = "grype.exe" if platform.system() == "Windows" else "grype"
ANALYZE_QUEUE_TIMEOUT = 0


class GrypeScanFailure(RuntimeError):
    def __init__(self, file_name: str, stderr: str):
        """
        Create new scan failure

        :param file_name: Name of file scanned
        :param stderr: grype stderr output
        """
        super().__init__(f"grype scan failed for {file_name}")
        self.file_name = file_name
        self.stderr = stderr


class AnalyzerWorker:
    def __init__(self, database: BreadcrumbsDatabase,
                 grype_path: str,
                 analyze_queue: Queue[AnalysisTask],
                 downloader_done_event: Event,
                 max_threads: int):
        """
        Create a new analyzer worker that spawns threads to process jars using grype

        :param database: The database to save grype results and store any error messages in
        :param grype_path: The path to the grype executable
        :param analyze_queue: Queue of tasks to analyze
        :param downloader_done_event: Flag to indicate to rest of pipeline that the downloader is finished
        :param max_threads: Max number of concurrent requests allowed to be made at once (default: cpu count)
        """
        self._database = database
        self._grype_path = grype_path
        self._analyze_queue = analyze_queue
        self._downloader_done_event = downloader_done_event
        self._max_threads = max_threads

        self._heartbeat = Heartbeat("Analysis")
        self._timer = Timer()
        self._jars_scanned = 0

        self._verify_grype_installation()

    def _grype_scan(self, analysis_task: AnalysisTask) -> None:
        """
        Use grype to scan a jar

        :param analysis_task: Task with jar path and additional details
        """
        start_time = time.time()
        cve_ids = []
        # scan
        try:
            result = subprocess.run([GRYPE_BIN, "--by-cve",
                                     "-f", "negligible",
                                     f"-o json={analysis_task.get_grype_file_path()}",
                                     analysis_task.get_file_path()],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            # non-zero, non-one error
            if result.returncode and result.returncode != 1:
                raise GrypeScanFailure(analysis_task.get_filename(), result.stderr.decode())
            logger.debug_msg(f"Scanned {analysis_task.get_file_path()} in {time.time() - start_time:.2f}s")

            # return.code == 1, which means cves were found
            if result.returncode:
                # save results
                with open(analysis_task.get_grype_file_path(), "r") as file:
                    grype_data = json.load(file)
                analysis_task.cleanup()
                # get all cves
                cve_ids = list({vuln["vulnerability"]["id"] for vuln in grype_data["matches"] if
                                vuln["vulnerability"]["id"].startswith("CVE")})
                logger.info(
                    f"Scan found {len(cve_ids)} CVE{'' if len(cve_ids) == 1 else 's'} in {analysis_task.get_filename()}")

            self._database.upsert_jar_and_grype_results(analysis_task.get_url(), analysis_task.get_publish_date(),
                                                        cve_ids, datetime.now(timezone.utc))
            self._jars_scanned += 1
        except GrypeScanFailure as e:
            logger.error_exp(e)
            self._database.log_error(Stage.ANALYZER, e.stderr, e.file_name)
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(Stage.ANALYZER, str(e), analysis_task.get_filename())
        finally:
            analysis_task.cleanup()
            self._analyze_queue.task_done()

    def _analyze(self) -> None:
        """
        Main analyze method. Will continuously spawn threads to scan jars until
        the analysis queue is empty and retries exceeded
        """
        logger.info(f"Initializing analyzer . .")
        self._update_grype_db()
        # start the analyzer
        logger.info(f"Starting analyzer using {self._max_threads} threads")
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            first_time_wait_for_tasks("Analyzer", self._analyze_queue)  # block until items to process
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
                    self._database.log_error(
                        Stage.ANALYZER,
                        f"{type(e).__name__} | {e.__str__()} | {analysis_task.get_filename()}")
                    if analysis_task:
                        analysis_task.cleanup()

        logger.warn(f"No more jars to scan, waiting for scans to finish. . .")
        concurrent.futures.wait(tasks)
        logger.warn(f"All scans finished, exiting. . .")
        # done
        self._timer.stop()
        self.print_statistics_message()

    def _update_grype_db(self) -> None:
        # update local grype db if needed
        logger.info(f"Checking grype database status. . .")
        db_status = subprocess.run([f"{self._grype_path}", "db", "check"],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL).returncode
        if db_status:
            start_time = time.time()
            logger.warn("grype database needs to be updated!")
            logger.warn("THIS MAY TAKE A FEW MINUTES, ESPECIALLY IF THIS IS THE FIRST RUN")
            logger.warn("Subsequent runs will be faster (only if using cached volume if using docker)")
            subprocess.run([f"{self._grype_path}", "db", "update"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            logger.info(f"Updated grype vulnerability database in {time.time() - start_time:.2f} seconds")

        logger.info(f"grype database is up to date")

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the analyzer
        """
        logger.info(f"Analyzer completed in {self._timer.format_time()} using {self._max_threads} threads")
        logger.info(
            f"Analyzer has scanned {self._jars_scanned} jars ({self._timer.get_count_per_second(self._jars_scanned):.01f} jars / s)")

    def start(self) -> Thread:
        """
        Spawn and start the analyzer worker thread

        :return: Analyzer thread
        """
        thread = Thread(target=self._analyze)
        thread.start()
        return thread
