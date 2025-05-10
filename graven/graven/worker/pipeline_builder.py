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
from shared.logger import logger
from shared.timer import Timer
from worker.analzyer import AnalyzerWorker
from worker.crawler import CrawlerWorker
from worker.downloader import DownloaderWorker
from worker.generator import GeneratorWorker
from worker.scanner import ScannerWorker
from worker.vuln_fetcher import VulnFetcherWorker

"""
File: pipeline_builder.py

Description: Builder for generating, coupling, and running graven workers

@author Derek Garcia
"""

DEFAULT_MAX_CONCURRENT_MAVEN_REQUESTS = 100
DEFAULT_MAX_CPU_THREADS = os.cpu_count()


class PipelineBuilder:
    def __init__(self):
        """
        Create new pipeline builder
        """
        # attempt to log in into the database
        self._database = GravenDatabase()
        self._interrupt_stop_flag = Event()
        self._io_thread_count = 0
        self._cpu_thread_count = 0

        # metadata
        self._syft_version = None
        self._grype_version = None
        self._grype_db_source = None

        # workers
        self._crawler: CrawlerWorker | None = None
        self._downloader: DownloaderWorker | None = None
        self._generator: GeneratorWorker | None = None
        self._scanner: ScannerWorker | None = None
        self._analyzer: AnalyzerWorker | None = None
        self._vuln_fetcher: VulnFetcherWorker | None = None

    def _couple_crawl_and_download(self) -> None:
        """
        Append crawl and download into pipeline
        """
        first_hit = Event()
        is_done = Event()
        # update crawler
        self._crawler.set_first_hit_flag(first_hit)
        self._crawler.set_done_flag(is_done)
        # update download
        self._downloader.set_crawler_first_hit_flag(first_hit)
        self._downloader.set_crawler_done_flag(is_done)

    def _couple_analyze_and_vuln(self) -> None:
        """
        Append analyze and vuln fetcher into pipeline
        """
        first_hit = Event()
        is_done = Event()
        # update analyzer
        self._analyzer.set_first_hit_flag(first_hit)
        self._analyzer.set_done_flag(is_done)
        # update vuln fetcher
        self._vuln_fetcher.set_analyzer_first_hit_flag(first_hit)
        self._vuln_fetcher.set_analyzer_done_flag(is_done)

    def _couple_generator(self) -> None:
        """
        Insert generator into the pipeline
        """
        generator_queue = Queue()
        scan_queue = Queue()
        # download to gen
        self._downloader.set_producer_queue(generator_queue)
        self._generator.set_consumer_queue(generator_queue)
        # self._generator.set_consumer_queue(Queue())
        # gen to scan
        self._generator.set_producer_queue(scan_queue)
        self._scanner.set_consumer_queue(scan_queue)

    def set_io_thread_limit(self, limit: int) -> None:
        """
        Set IO thread count limit
        
        :param limit: thread limit
        """
        self._io_thread_count = limit

    def set_cpu_thread_limit(self, limit: int) -> None:
        """
        Set CPU thread count limit

        :param limit: thread limit
        """
        self._cpu_thread_count = limit

    def set_crawler_worker(self, seed_urls: List[str], update_domain: bool, update_jar: bool) -> 'PipelineBuilder':
        """
        Add a crawler worker to the pipeline

        :param seed_urls: List of URLs to for crawler to search
        :param update_domain: Update a domain if already seen
        :param update_jar: Update a jar if already seen
        :return: builder
        """
        self._crawler = CrawlerWorker(self._interrupt_stop_flag, self._database, seed_urls, update_domain, update_jar)
        return self

    def set_process_workers(self, download_cache_size: int, grype_cache_size: int,
                            grype_path: str, grype_db_source: str, jar_limit: int = None) -> 'PipelineBuilder':
        """
        Create all the workers required for the process operation
        By default, syft SBOMs are not generated

        :param download_cache_size: Size of jar cache to use in bytes
        :param grype_cache_size: Size of grype cache to use in bytes
        :param grype_path: Path to grype bin
        :param grype_db_source: Optional source url of specific grype database to use. If defined, database will not be updated
        :param jar_limit: Optional limit of jars to download at once
        :return: builder
        """
        # init grype
        if grype_path:
            grype = Grype(bin_path=grype_path, db_source_url=grype_db_source)
        else:
            grype = Grype(grype_db_source)
        self._grype_version = grype.get_version()
        self._grype_db_source = grype_db_source
        # set workers
        self._downloader = DownloaderWorker(self._interrupt_stop_flag, self._database, download_cache_size, jar_limit)
        self._scanner = ScannerWorker(self._interrupt_stop_flag, self._database, grype, grype_cache_size)
        self._analyzer = AnalyzerWorker(self._interrupt_stop_flag, self._database)

        # create message queues
        scan_queue = Queue()
        analyzer_queue = Queue()
        self._downloader.set_producer_queue(scan_queue)
        self._scanner.set_consumer_queue(scan_queue)
        self._scanner.set_producer_queue(analyzer_queue)
        self._analyzer.set_consumer_queue(analyzer_queue)
        return self

    def set_generator_worker(self, cache_size: int, syft_path: str) -> 'PipelineBuilder':
        """
        Create a new generator worker

        :param cache_size: Size of syft cache to use in bytes
        :param syft_path: Path to syft bin
        :return: builder
        """
        # init syft
        if syft_path:
            syft = Syft(syft_path)
        else:
            syft = Syft()
        self._grype_version = syft.get_version()
        self._generator = GeneratorWorker(self._interrupt_stop_flag, self._database, syft, cache_size)
        return self

    def set_vuln_worker(self) -> 'PipelineBuilder':
        """
        Create a new vun fetcher worker

        :return: builder
        """
        self._vuln_fetcher = VulnFetcherWorker(self._interrupt_stop_flag, self._database)
        return self

    def run_workers(self) -> int:
        """
        Run all workers until completed

        :return: Exit code
        """
        # todo - check if have all components to run
        logger.info("Launching Graven worker threads. . .")
        exit_code = 0  # assume ok

        # using run or crawl and process - couple
        if self._crawler and self._downloader:
            self._couple_crawl_and_download()
        # using run or process and update-vuln - couple
        if self._analyzer and self._vuln_fetcher:
            self._couple_analyze_and_vuln()
        # using run or if generating sboms - couple
        if self._generator:
            self._couple_generator()

        # todo - crawl, process, and vuln each get own run ids but same batch number
        run_id = self._database.log_run_start(self._syft_version, self._grype_version, self._grype_db_source)

        # create threadpools to be sheared by workers
        if self._crawler or self._downloader:
            io_exe = ThreadPoolExecutor(max_workers=self._io_thread_count)
        else:
            io_exe = None
        if self._scanner or self._generator:
            cpu_exe = ThreadPoolExecutor(max_workers=self._cpu_thread_count)
        else:
            cpu_exe = None

        # spawn tasks
        with TemporaryDirectory(prefix='graven_') as tmp_dir:
            logger.debug_msg(f"Working Directory: {tmp_dir}")
            # create list of workers to run
            tasks = []
            if self._crawler:
                tasks.append(lambda: _graceful_start(self._crawler.start, run_id, io_exe))
            if self._downloader:
                tasks.append(lambda: _graceful_start(self._downloader.start, run_id, io_exe, root_dir=tmp_dir))
            if self._generator:
                tasks.append(lambda: _graceful_start(self._generator.start, run_id, cpu_exe, root_dir=tmp_dir))
            if self._scanner:
                tasks.append(lambda: _graceful_start(self._scanner.start, run_id, cpu_exe, root_dir=tmp_dir))
            if self._analyzer:
                tasks.append(lambda: _graceful_start(self._analyzer.start, run_id))
            if self._vuln_fetcher:
                tasks.append(lambda: _graceful_start(self._vuln_fetcher.start, run_id))

            timer = Timer(True)
            with ThreadPoolExecutor(max_workers=len(tasks)) as exe:
                futures = [exe.submit(t) for t in tasks]
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
        if io_exe:
            io_exe.shutdown()
        if cpu_exe:
            cpu_exe.shutdown()
        # print task durations
        self._database.log_run_end(run_id, exit_code)
        timer.stop()
        if exit_code:
            logger.warn(f"Completed with non-zero exit code: {exit_code}")
        logger.info(f"Total Execution Time: {timer.format_time()}")
        if self._crawler:
            self._crawler.print_statistics_message()
        if self._downloader:
            self._downloader.print_statistics_message()
        if self._generator:
            self._generator.print_statistics_message()
        if self._scanner:
            self._scanner.print_statistics_message()
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
