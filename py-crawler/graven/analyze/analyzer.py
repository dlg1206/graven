"""
File: analyzer.py

Description: Use grype to scan jars to find CVEs

@author Derek Garcia
"""
import asyncio
import os
import platform
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from log.logger import logger
from shared.analysis_task import AnalysisTask
from shared.defaults import DEFAULT_MAX_RETRIES
from shared.heartbeat import Heartbeat

DEFAULT_MAX_THREADS = os.cpu_count()
GRYPE_BIN = "grype.exe" if platform.system() == "Windows" else "grype"
GRYPE_OUTPUT_JSON = "tmp.json"


class AnalyzerWorker:
    def __init__(self, analyze_queue: asyncio.Queue[AnalysisTask], max_retries: int = DEFAULT_MAX_RETRIES,
                 max_threads: int = DEFAULT_MAX_THREADS):
        """
        Create a new analyzer worker that spawns threads to process jars using grype

        :param analyze_queue: Queue of tasks to analyze
        :param max_retries: Max number of retries to get an url from the crawl queue before exiting (default: 3)
        :param max_threads: Max number of concurrent requests allowed to be made at once (default: cpu count)
        """
        self._analyze_queue = analyze_queue
        self._max_retries = max_retries
        self._max_threads = max_threads
        self._heartbeat = Heartbeat("Analysis")

    def _save_grype_results(self, analysis_task: AnalysisTask) -> None:
        # todo save results to database
        pass

    def _grype_scan(self, analysis_task: AnalysisTask) -> None:
        """
        Use grype to scan a jar

        :param analysis_task: Task with jar path and additional details
        """
        with analysis_task as at:
            subprocess.run([GRYPE_BIN, "--by-cve",
                            f"-o json={at.get_working_directory()}{os.sep}{GRYPE_OUTPUT_JSON}",
                            at.get_file_path()],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._save_grype_results(at)
            logger.debug_msg(f"Scanned {at.get_file_path()}")

    async def _analyze(self) -> None:
        """
        Main analyze method. Will continuously spawn threads to scan jars until
        the analyze queue is empty and retries exceeded
        """

        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            first_download = True
            cur_retries = 0
            # repeat until exceed returies
            while cur_retries < self._max_retries:
                analysis_task = None
                try:
                    # if first download, wait until jar to download
                    if first_download:
                        logger.info("Analyzer idle until analyze queue is populated")
                        analysis_task = await self._analyze_queue.get()
                        first_download = False
                        logger.info("Analysis task added; Analyzer starting")
                    else:
                        # If the queue is empty, will error
                        analysis_task = self._analyze_queue.get_nowait()
                    # spawn thread
                    exe.submit(self._grype_scan, analysis_task)
                    # log status
                    cur_retries = 0
                    self._analyze_queue.task_done()
                    self._heartbeat.beat(self._analyze_queue.qsize())
                except asyncio.QueueEmpty:
                    # sleep and try again
                    # todo - replace retry with signal
                    cur_retries += 1
                    logger.warn(
                        f"No tasks left in the analysis queue, retrying ({cur_retries}/{self._max_retries}). . .")
                    await asyncio.sleep(1)  # todo - might need to increase?

                except Exception as e:
                    # todo error handling and reporting
                    if analysis_task:
                        analysis_task.close()

        logger.warn(f"Exceeded retries, exiting. . .")

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
        logger.info(f"Completed analysis in {time.time() - start_time:.2f} seconds")  # todo -replace with hh:mm:ss
