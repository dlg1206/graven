import concurrent
import os
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from threading import Event

from anchore.syft import Syft, SyftScanFailure
from logger import logger
from shared.cve_breadcrumbs_database import BreadcrumbsDatabase, Stage
from shared.heartbeat import Heartbeat
from shared.message import ScanMessage, GeneratorMessage
from shared.utils import Timer, first_time_wait_for_tasks

"""
File: generator.py

Description: Use syft to generate SBOMs

@author Derek Garcia
"""

DEFAULT_MAX_GENERATOR_THREADS = os.cpu_count() / 2  # AnalyzerWorker gets other half of threads


class GeneratorWorker:
    def __init__(self, database: BreadcrumbsDatabase,
                 syft: Syft,
                 generator_queue: Queue[GeneratorMessage],
                 analyze_queue: Queue[ScanMessage],
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
        :param max_threads: Max number of concurrent requests allowed to be made at once (default: cpu count)
        """
        self._database = database
        self._syft = syft
        self._generator_queue = generator_queue
        self._analyze_queue = analyze_queue
        self._downloader_done_flag = downloader_done_flag
        self._generator_done_flag = generator_done_flag
        self._max_threads = max_threads

        self._heartbeat = Heartbeat("Generator")
        self._timer = Timer()
        self._sboms_generated = 0
        self._run_id = None

    def _syft_scan(self, generator_msg: GeneratorMessage) -> None:
        """
        Use syft to scan a jar and generate an SBOM

        :param generator_msg: Message with jar path and additional details
        """

        try:
            return_code = self._syft.scan(generator_msg.get_file_path(), generator_msg.get_syft_file_path())
            self._analyze_queue.put(
                ScanMessage(generator_msg.url, generator_msg.publish_date, generator_msg.get_syft_file_path(),
                            generator_msg.working_dir_path))
            # TODO - save SBOM and additional details
            self._sboms_generated += 1
        except SyftScanFailure as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.GENERATOR, generator_msg.url, e, "syft failed to scan")
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.GENERATOR, generator_msg.url, e,
                                     "error when generating with syft")
        finally:
            generator_msg.cleanup()
            self._generator_queue.task_done()

    def _generate(self) -> None:
        """
        Main generate method. Will continuously spawn threads to scan jars until the generate queue is empty and
        retries exceeded
        """
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            # block until items to process
            first_time_wait_for_tasks("Generator", self._generator_queue, self._downloader_done_flag)
            self._timer.start()
            # run while the downloader is still running or still tasks to process
            while not (self._downloader_done_flag.is_set() and self._generator_queue.empty()):
                generator_msg = None
                try:
                    generator_msg = self._generator_queue.get_nowait()
                    self._heartbeat.beat(self._generator_queue.qsize())
                    # scan
                    tasks.append(exe.submit(self._syft_scan, generator_msg))
                except Empty:
                    """
                    To prevent deadlocks, the forced timeout with throw this error 
                    for another iteration of the loop to check conditions
                    """
                    continue
                except Exception as e:
                    logger.error_exp(e)
                    url = None
                    if generator_msg:
                        url = generator_msg.url
                        generator_msg.cleanup()

                    self._database.log_error(self._run_id, Stage.GENERATOR, url, e, "Failed during loop")

        logger.info(f"No more jars to scan, waiting for scans to finish. . .")
        concurrent.futures.wait(tasks)
        self._generator_done_flag.set()  # signal no tasks

    def print_statistics_message(self) -> None:
        """
        Prints statistics about the generator
        """
        logger.info(f"Generator completed in {self._timer.format_time()} using {self._max_threads} threads")
        logger.info(
            f"Generator has generated {self._sboms_generated} SBOMs ({self._timer.get_count_per_second(self._sboms_generated):.01f} jars / s)")

    def start(self, run_id: int) -> None:
        """
        Spawn and start the generator worker thread

        :param run_id: ID of run
        """
        self._run_id = run_id
        logger.info(f"Initializing generator . .")
        # start the analyzer
        logger.info(f"Starting generator using {self._max_threads} threads")
        self._generate()
        # done
        self._timer.stop()
        self.print_statistics_message()

    @property
    def grype(self) -> Syft:
        return self._syft
