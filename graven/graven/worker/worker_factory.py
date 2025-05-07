import concurrent
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


class WorkerFactory:
    def __init__(self):
        """
        Create new worker factory
        """
        # attempt to log in into the database
        self._database = GravenDatabase()
        self._interrupt_stop_flag = Event()
        self._io_thread_count = 0  # to be updated as set

        # shared crawler objects
        self._crawler_first_hit_flag = Event()
        self._crawler_done_flag = Event()

        # shared generator objects
        self._generator_queue: Queue[Message | None] = Queue()

        # shared scanner objects
        self._scan_queue: Queue[Message | None] = Queue()

        # shared analyzer objects
        self._analyze_queue: Queue[Message | None] = Queue()

        # shared nvd objects
        self._cve_queue: Queue[str | None] = Queue()

    def create_crawler_worker(self, max_concurrent_requests: int, update_domain: bool,
                              update_jar: bool) -> CrawlerWorker:
        """
        Create a new crawler worker

        :param update_domain: Update a domain if already seen
        :param update_jar: Update a jar if already seen
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once
        :return: CrawlerWorker
        """
        self._io_thread_count += max_concurrent_requests  # reserve threads
        return CrawlerWorker(self._interrupt_stop_flag, self._database,
                             self._crawler_first_hit_flag, self._crawler_done_flag, update_domain, update_jar,
                             max_concurrent_requests)

    def create_downloader_worker(self, max_concurrent_requests: int, download_limit: int) -> DownloaderWorker:
        """
        Create a new downloader worker

        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once
        :param download_limit: Max number of jars to be downloaded at one time
        :return: DownloaderWorker
        """
        return DownloaderWorker(self._interrupt_stop_flag, self._database, self._generator_queue,
                                self._crawler_first_hit_flag, self._crawler_done_flag, max_concurrent_requests,
                                download_limit)

    def create_generator_worker(self, max_threads: int, syft_path: str = None) -> GeneratorWorker:
        """
        Create a new downloader worker

        :param max_threads: Max number of concurrent requests allowed to be made at once
        :param syft_path: Path to syft bin (Default: assume on path or in pwd)
        :return: GeneratorWorker
        """
        # init syft
        if syft_path:
            syft = Syft(syft_path)
        else:
            syft = Syft()
        return GeneratorWorker(self._interrupt_stop_flag, self._database, syft, self._generator_queue, self._scan_queue,
                               max_threads)

    def create_scanner_worker(self, max_threads: int, grype_path: str = None,
                              grype_db_source: str = None) -> ScannerWorker:
        """
        Create a new scanner worker

        :param max_threads: Max number of concurrent scans to be made at once
        :param grype_path: Path to grype bin (Default: assume on path or in pwd)
        :param grype_db_source: Optional source url of specific grype database to use. If defined, database will not be updated
        :return: ScannerWorker
        """
        # init grype
        if grype_path:
            grype = Grype(bin_path=grype_path, db_source_url=grype_db_source)
        else:
            grype = Grype(grype_db_source)
        return ScannerWorker(self._interrupt_stop_flag, self._database, grype, self._scan_queue, self._analyze_queue,
                             max_threads)

    def create_analyzer_worker(self, max_threads: int) -> AnalyzerWorker:
        """
        Create a new analyzer worker

        :param max_threads: Max number of threads to parse anchore results
        :return: AnalyzerWorker
        """
        return AnalyzerWorker(self._interrupt_stop_flag, self._database, self._analyze_queue, self._cve_queue,
                              max_threads)

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
        vuln_worker = VulnFetcherWorker(self._interrupt_stop_flag, self._database,
                                        self._cve_queue)  # for getting cve details
        exit_code = 0  # assume ok
        run_id = self._database.log_run_start(generator.get_syft_version(),
                                              scanner.get_grype_version(),
                                              scanner.get_grype_db_source())

        timer = Timer(True)
        # create threadpools to be sheared by workers
        io_exe = ThreadPoolExecutor(max_workers=self._io_thread_count)
        # spawn tasks
        with TemporaryDirectory(prefix='graven_') as tmp_dir:
            logger.debug_msg(f"Working Directory: {tmp_dir}")
            with ThreadPoolExecutor(max_workers=6) as executor:
                futures = [
                    executor.submit(lambda: _graceful_start(analyzer.start, run_id)),
                    executor.submit(
                        lambda: _graceful_start(crawler.start, run_id, io_exe, root_url=seed_urls.pop(0),
                                                seed_urls=seed_urls)),
                    executor.submit(lambda: _graceful_start(downloader.start, run_id, tmp_dir)),
                    executor.submit(lambda: _graceful_start(generator.start, run_id, tmp_dir)),
                    executor.submit(lambda: _graceful_start(scanner.start, run_id, tmp_dir)),
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
