import concurrent
import os
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from tempfile import TemporaryDirectory
from threading import Event
from typing import List, Callable, Any

from anchore.grype import Grype
from anchore.syft import Syft
from db.graven_database import GravenDatabase
from qmodel.message import Message
from shared.logger import logger
from shared.timer import Timer
from worker.analzyer import AnalyzerWorker
from worker.crawler import CrawlerWorker
from worker.downloader import DownloaderWorker
from worker.generator import GeneratorWorker
from worker.scanner import ScannerWorker
from worker.vuln_fetcher import VulnFetcherWorker

"""
File: worker_factory.py

Description: Factory for generating, coupling, and running graven workers

@author Derek Garcia
"""

DEFAULT_MAX_CONCURRENT_MAVEN_REQUESTS = 100
DEFAULT_MAX_CPU_THREADS = os.cpu_count()


class WorkerFactory:
    def __init__(self,
                 io_thread_count: int = DEFAULT_MAX_CONCURRENT_MAVEN_REQUESTS,
                 cpu_thread_count: int = DEFAULT_MAX_CPU_THREADS):
        """
        Create new worker factory

        :param io_thread_count: Number threads to create in io threadpool
        :param cpu_thread_count: Number threads to create in cpu threadpool
        """
        # attempt to log in into the database
        self._database = GravenDatabase()
        self._interrupt_stop_flag = Event()
        self._io_thread_count = io_thread_count
        self._cpu_thread_count = cpu_thread_count

        # shared crawler objects
        self._crawler_first_hit_flag = Event()
        self._crawler_done_flag = Event()

        # shared generator objects
        self._generator_queue: Queue[Message | None] = Queue()

        # shared scanner objects
        self._scan_queue: Queue[Message | None] = Queue()

        # shared analyzer objects
        self._analyzer_queue: Queue[Message | None] = Queue()
        self._analyzer_first_hit_flag = Event()
        self._analyzer_done_flag = Event()

    def create_crawler_worker(self, update_domain: bool, update_jar: bool) -> CrawlerWorker:
        """
        Create a new crawler worker

        :param update_domain: Update a domain if already seen
        :param update_jar: Update a jar if already seen
        :return: CrawlerWorker
        """
        return CrawlerWorker(self._interrupt_stop_flag, self._database,
                             self._crawler_first_hit_flag, self._crawler_done_flag, update_domain, update_jar)

    def create_downloader_worker(self, cache_size: int) -> DownloaderWorker:
        """
        Create a new downloader worker

        :param cache_size: Size of jar cache to use in bytes
        :return: DownloaderWorker
        """
        return DownloaderWorker(self._interrupt_stop_flag, self._database, self._generator_queue,
                                self._crawler_first_hit_flag, self._crawler_done_flag, cache_size)

    def create_generator_worker(self, cache_size: int, syft_path: str = None) -> GeneratorWorker:
        """
        Create a new downloader worker

        :param cache_size: Size of syft cache to use in bytes
        :param syft_path: Path to syft bin (Default: assume on path or in pwd)
        :return: GeneratorWorker
        """
        # init syft
        if syft_path:
            syft = Syft(syft_path)
        else:
            syft = Syft()
        return GeneratorWorker(self._interrupt_stop_flag, self._database, syft, cache_size, self._generator_queue,
                               self._scan_queue)

    def create_scanner_worker(self, cache_size: int, grype_path: str = None,
                              grype_db_source: str = None) -> ScannerWorker:
        """
        Create a new scanner worker

        :param cache_size: Size of grype cache to use in bytes
        :param grype_path: Path to grype bin (Default: assume on path or in pwd)
        :param grype_db_source: Optional source url of specific grype database to use. If defined, database will not be updated
        :return: ScannerWorker
        """
        # init grype
        if grype_path:
            grype = Grype(bin_path=grype_path, db_source_url=grype_db_source)
        else:
            grype = Grype(grype_db_source)
        return ScannerWorker(self._interrupt_stop_flag, self._database, grype, cache_size,
                             self._scan_queue, self._analyzer_queue)

    def create_analyzer_worker(self) -> AnalyzerWorker:
        """
        Create a new analyzer worker

        :return: AnalyzerWorker
        """
        return AnalyzerWorker(self._interrupt_stop_flag, self._database, self._analyzer_queue,
                              self._analyzer_first_hit_flag, self._analyzer_done_flag)

    def run_workers(self, crawler: CrawlerWorker, downloader: DownloaderWorker, generator: GeneratorWorker,
                    scanner: ScannerWorker, analyzer: AnalyzerWorker, seed_urls: List[str]) -> int:
        """
        Run all workers until completed

        :param crawler: Crawler Worker
        :param downloader: Downloader Worker
        :param generator: Generator Worker
        :param scanner: Scanner Worker
        :param analyzer: Analyzer Worker
        :param seed_urls: List of URLs to for crawler to search
        :return: Exit code
        """
        logger.info("Launching Graven worker threads...")
        # for getting cve details
        vuln_worker = VulnFetcherWorker(self._interrupt_stop_flag, self._database, self._analyzer_first_hit_flag,
                                        self._analyzer_done_flag)
        exit_code = 0  # assume ok
        run_id = self._database.log_run_start(generator.get_syft_version(),
                                              scanner.get_grype_version(),
                                              scanner.get_grype_db_source())

        timer = Timer(True)
        # create threadpools to be sheared by workers
        io_exe = ThreadPoolExecutor(max_workers=self._io_thread_count)
        cpu_exe = ThreadPoolExecutor(max_workers=self._cpu_thread_count)
        # spawn tasks
        with TemporaryDirectory(prefix='graven_') as tmp_dir:
            logger.debug_msg(f"Working Directory: {tmp_dir}")
            with ThreadPoolExecutor(max_workers=6) as executor:
                futures = [
                    executor.submit(lambda: _graceful_start(analyzer.start, run_id)),
                    executor.submit(
                        lambda: _graceful_start(crawler.start, run_id, io_exe,
                                                root_url=seed_urls.pop(0),
                                                seed_urls=seed_urls)),
                    executor.submit(lambda: _graceful_start(downloader.start, run_id, io_exe, root_dir=tmp_dir)),
                    executor.submit(lambda: _graceful_start(generator.start, run_id, cpu_exe, root_dir=tmp_dir)),
                    executor.submit(lambda: _graceful_start(scanner.start, run_id, cpu_exe, root_dir=tmp_dir)),
                    executor.submit(lambda: _graceful_start(vuln_worker.start, run_id))
                ]
                try:
                    # poll futures to break on interrupt
                    while not self._interrupt_stop_flag.is_set():
                        _, not_done = concurrent.futures.wait(futures, timeout=1)
                        if not not_done:
                            break
                # interrupt
                except KeyboardInterrupt:
                    # report early exit with padding
                    logger.warn(
                        f"\n\n{'\033[1;31mKeyboardInterrupt received! Shutting down workers. . .\n\033[0m' * 5}")
                    self._interrupt_stop_flag.set()
                    logger.warn("Shutting down workers")
                    exit_code = 2
                # unknown error
                except Exception as e:
                    logger.fatal(e)

            # fail fast if interrupt
            if self._interrupt_stop_flag.is_set():
                try:
                    for f in futures:
                        f.result(timeout=0)
                except Exception:
                    pass

        # shutdown thread pools
        io_exe.shutdown()
        cpu_exe.shutdown()
        # print task durations
        self._database.log_run_end(run_id, exit_code)
        timer.stop()
        if exit_code:
            logger.warn(f"Completed with non-zero exit code: {exit_code}")
        logger.info(f"Total Execution Time: {timer.format_time()}")
        crawler.print_statistics_message()
        downloader.print_statistics_message()
        generator.print_statistics_message()
        scanner.print_statistics_message()
        return exit_code


def _graceful_start(start_function: Callable, *args: Any, **kwargs: Any) -> None:
    """
    Wrapper function for handling errors on exiting

    :param start_function: Start function of the worker
    :param args: Args for the worker's start function
    :param kwargs: Args for the worker's start function
    """
    try:
        start_function(*args, **kwargs)
    except Exception as e:
        logger.error_exp(e)
