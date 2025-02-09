"""
File: analyzer.py

Description: Use grype to scan jars to find CVEs

@author Derek Garcia
"""
import asyncio
import concurrent
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

    def _save_results(self, analysis_task: AnalysisTask) -> None:

        with open(analysis_task.get_grype_file_path(), "r") as file:
            grype_data = json.load(file)
        # get all cves
        cve_ids = {vuln["vulnerability"]["id"] for vuln in grype_data["matches"] if
                   vuln["vulnerability"]["id"].startswith("CVE")}

        self._database.add_jar_and_grype_results(analysis_task.get_url(), analysis_task.get_publish_date(),
                                                 list(cve_ids))
        analysis_task.cleanup()

    def _grype_scan(self, analysis_task: AnalysisTask) -> None:
        """
        Use grype to scan a jar

        :param analysis_task: Task with jar path and additional details
        """
        start_time = time.time()
        subprocess.run([GRYPE_BIN, "--by-cve",
                        f"-o json={analysis_task.get_grype_file_path()}",
                        analysis_task.get_file_path()],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.debug_msg(f"Scanned {analysis_task.get_file_path()} in {time.time() - start_time:.2f}s")
        self._save_results(analysis_task)

    async def _analyze(self) -> None:
        """
        Main analyze method. Will continuously spawn threads to scan jars until
        the analysis queue is empty and retries exceeded
        """
        futures = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            # run while the downloader is still running or still tasks to process
            while not (self._downloader_done_event.is_set() and self._analyze_queue.empty()):
                analysis_task = None
                try:
                    analysis_task = await asyncio.wait_for(self._analyze_queue.get(), timeout=30)
                    self._heartbeat.beat(self._analyze_queue.qsize())
                    # spawn thread
                    futures.append(exe.submit(self._grype_scan, analysis_task))
                    # log status
                    self._analyze_queue.task_done()
                except asyncio.TimeoutError:
                    """
                    To prevent deadlocks, the forced timeout with throw this error 
                    for another iteration of the loop to check conditions
                    """
                    logger.warn("Failed to get jar path from queue, retrying. . .")
                    continue
                except Exception as e:
                    logger.error_exp(e)
                    self._database.log_error(
                        Stage.ANALYZER,
                        f"{type(e).__name__} | {e.__str__()} | {analysis_task.get_file_path()}")
                    if analysis_task:
                        analysis_task.cleanup()

        logger.warn(f"No more jars to scan, waiting for scans to finish. . .")
        concurrent.futures.wait(futures)
        logger.warn(f"All scans finished, exiting. . .")

    async def start(self) -> None:
        """
        Launch the analyzer
        """
        start_time = time.time()
        # update local grype db if needed
        logger.info(f"Checking grype database status. . .")
        db_status = subprocess.run([f"{GRYPE_BIN}", "db", "check"],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL).returncode
        if db_status:
            logger.warn("grype database needs to be updated!")
            logger.warn("THIS MAY TAKE A FEW MINUTES, ESPECIALLY IF THIS IS THE FIRST RUN")
            logger.warn("Subsequent runs will be faster (only if using cached volume if using docker)")
            subprocess.run([f"{GRYPE_BIN}", "db", "update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"Updated grype vulnerability database in {time.time() - start_time:.2f} seconds")

        logger.info(f"grype database is up to date")
        # start the analyzer
        start_time = time.time()
        logger.info(f"Starting analyzer")
        await self._analyze()
        logger.info(f"Completed analysis in {format_time(time.time() - start_time)}")


def check_for_grype() -> None:
    """
    Check that grype is installed

    :raises FileNotFoundError: if grype is not present
    """
    try:
        result = subprocess.run(
            f"{GRYPE_BIN} --version",
            shell=True,
            capture_output=True,  # Capture stdout & stderr
            text=True,  # Return output as string
            check=True  # Raise error if command fails
        )
    except subprocess.CalledProcessError:
        raise FileNotFoundError("Could not find grype binary; is it on the path or in pwd?")
    logger.info(f"Using {result.stdout.strip()}")
