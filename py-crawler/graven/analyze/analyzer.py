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

DEFAULT_MAX_ANALYZER_THREADS = os.cpu_count()
GRYPE_BIN = "grype.exe" if platform.system() == "Windows" else "grype"


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
    def __init__(self, database: BreadcrumbsDatabase, grype_path: str, analyze_queue: asyncio.Queue[AnalysisTask],
                 downloader_done_event: Event, max_threads: int):
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

        self._verify_grype_installation()

    def _grype_scan(self, analysis_task: AnalysisTask) -> None:
        """
        Use grype to scan a jar

        :param analysis_task: Task with jar path and additional details
        """
        start_time = time.time()
        # scan
        try:
            result = subprocess.run([self._grype_path, "--by-cve",
                                     "-f", "negligible",
                                     f"-o json={analysis_task.get_grype_file_path()}",
                                     analysis_task.get_file_path()],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

            if result.returncode:
                raise GrypeScanFailure(analysis_task.get_filename(), result.stderr.decode())
            logger.debug_msg(f"Scanned {analysis_task.get_file_path()} in {time.time() - start_time:.2f}s")

            # save results
            with open(analysis_task.get_grype_file_path(), "r") as file:
                grype_data = json.load(file)
            analysis_task.cleanup()
            # get all cves
            cve_ids = {vuln["vulnerability"]["id"] for vuln in grype_data["matches"] if
                       vuln["vulnerability"]["id"].startswith("CVE")}

            self._database.add_jar_and_grype_results(analysis_task.get_url(), analysis_task.get_publish_date(),
                                                     list(cve_ids))
        except GrypeScanFailure as e:
            logger.error_exp(e)
            self._database.log_error(Stage.ANALYZER, e.stderr, e.file_name)
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(Stage.ANALYZER, str(e), analysis_task.get_filename())
        finally:
            analysis_task.cleanup()

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
                    self._heartbeat.beat(self._analyze_queue.qsize())
                    analysis_task = await asyncio.wait_for(self._analyze_queue.get(), timeout=5)

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
                        f"{type(e).__name__} | {e.__str__()} | {analysis_task.get_filename()}")
                    if analysis_task:
                        analysis_task.cleanup()

        logger.warn(f"No more jars to scan, waiting for scans to finish. . .")
        concurrent.futures.wait(futures)
        # await asyncio.gather(*futures)
        logger.warn(f"All scans finished, exiting. . .")

    def _verify_grype_installation(self) -> None:
        """
        Check that grype is installed

        :raises FileNotFoundError: if grype is not present
        """
        try:
            result = subprocess.run(
                f"{self._grype_path} --version",
                shell=True,
                capture_output=True,  # Capture stdout & stderr
                text=True,  # Return output as string
                check=True  # Raise error if command fails
            )
        except subprocess.CalledProcessError:
            raise FileNotFoundError("Could not find grype binary; is it on the path or in pwd?")
        logger.info(f"Using {result.stdout.strip()}")

    def print_statistics_message(self) -> None:
        logger.info(f"Analyzer completed in {self._timer.format_time()} using {self._max_threads} threads")
        logger.info(
            f"Analyzer has scanned {self._jars_scanned} jars ({self._timer.get_count_per_second(self._jars_scanned):.01f} jars / s)")

    async def start(self) -> None:
        """
        Launch the analyzer
        """
        start_time = time.time()
        # update local grype db if needed
        logger.info(f"Checking grype database status. . .")
        db_status = subprocess.run([f"{self._grype_path}", "db", "check"],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL).returncode
        if db_status:
            logger.warn("grype database needs to be updated!")
            logger.warn("THIS MAY TAKE A FEW MINUTES, ESPECIALLY IF THIS IS THE FIRST RUN")
            logger.warn("Subsequent runs will be faster (only if using cached volume if using docker)")
            subprocess.run([f"{self._grype_path}", "db", "update"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            logger.info(f"Updated grype vulnerability database in {time.time() - start_time:.2f} seconds")

        logger.info(f"grype database is up to date")
        # start the analyzer
        start_time = time.time()
        logger.info(f"Starting analyzer using {self._max_threads} threads")
        await self._analyze()
        self._timer.stop()
        self.print_statistics_message()
