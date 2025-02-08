"""
File: analyzer.py

Description: Use grype to scan jars to find CVEs

@author Derek Garcia
"""
import asyncio
import datetime
import json
import os
import platform
import subprocess
import time
from asyncio import Event
from concurrent.futures import ThreadPoolExecutor

from db.cve_breadcrumbs_database import Stage, BreadcrumbsDatabase
from log.logger import logger
from shared.analysis_task import AnalysisTask
from shared.defaults import format_time
from shared.heartbeat import Heartbeat

DEFAULT_MAX_THREADS = os.cpu_count()
GRYPE_BIN = "grype.exe" if platform.system() == "Windows" else "grype"
GRYPE_OUTPUT_JSON = "tmp.json"


class AnalyzerWorker:
    def __init__(self, database: BreadcrumbsDatabase, analyze_queue: asyncio.Queue[AnalysisTask],
                 downloader_done_event: Event,
                 max_threads: int = DEFAULT_MAX_THREADS):
        """
        Create a new analyzer worker that spawns threads to process jars using grype

        :param database: The database to save grype results and store any error messages in
        :param analyze_queue: Queue of tasks to analyze
        :param downloader_done_event: Flag to indicate to rest of pipeline that the downloader is finished
        :param max_threads: Max number of concurrent requests allowed to be made at once (default: cpu count)
        """
        self._database = database
        self._analyze_queue = analyze_queue
        self._downloader_done_event = downloader_done_event
        self._max_threads = max_threads
        self._heartbeat = Heartbeat("Analysis")

    def _save_results(self, url: str, published_date: datetime, grype_output_path: str) -> None:

        with open(grype_output_path, "r") as file:
            grype_data = json.load(file)
        # get all cves
        cve_ids = {vuln["vulnerability"]["id"] for vuln in grype_data["matches"] if
                   vuln["vulnerability"]["id"].startswith("CVE")}

        self._database.add_jar_and_grype_results(url, published_date, list(cve_ids))

    def _grype_scan(self, analysis_task: AnalysisTask) -> None:
        """
        Use grype to scan a jar

        :param analysis_task: Task with jar path and additional details
        """
        with analysis_task as at:
            start_time = time.time()
            grype_output_path = f"{at.get_working_directory()}{os.sep}{GRYPE_OUTPUT_JSON}"
            subprocess.run([GRYPE_BIN, "--by-cve",
                            f"-o json={grype_output_path}",
                            at.get_file_path()],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.debug_msg(f"Scanned {at.get_file_path()} in {time.time() - start_time:.2f}s")
            self._save_results(at.get_url(), at.get_publish_date(), grype_output_path)

    async def _analyze(self) -> None:
        """
        Main analyze method. Will continuously spawn threads to scan jars until
        the analysis queue is empty and retries exceeded
        """

        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            # run while the downloader is still running or still tasks to process
            while not (self._downloader_done_event.is_set() and self._analyze_queue.empty()):
                analysis_task = None
                try:
                    analysis_task = await asyncio.wait_for(self._analyze_queue.get(), timeout=1)
                    # spawn thread
                    exe.submit(self._grype_scan, analysis_task)
                    # log status
                    self._analyze_queue.task_done()
                    self._heartbeat.beat(self._analyze_queue.qsize())
                except asyncio.TimeoutError:
                    """
                    To prevent deadlocks, the forced timeout with throw this error 
                    for another iteration of the loop to check conditions
                    """
                    continue
                except Exception as e:
                    logger.error_exp(e)
                    self._database.log_error(Stage.ANALYZER, f"{type(e).__name__} | {e.__str__()}", url)
                    if analysis_task:
                        analysis_task.close()

        logger.warn(f"No more jars to scan, exiting. . .")

    async def start(self) -> None:
        """
        Launch the analyzer
        """
        start_time = time.time()
        # update local grype db to save time
        logger.info(f"Initializing grype vulnerability database")
        subprocess.run([GRYPE_BIN, "db", "update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info(f"Updated grype vulnerability database in {time.time() - start_time:.2f} seconds")
        # start the analyzer
        logger.info(f"Starting analyzer")
        await self._analyze()
        logger.info(f"Completed analysis in {format_time(time.time() - start_time)}")
