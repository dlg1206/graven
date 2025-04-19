import concurrent
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from queue import Queue
from tempfile import TemporaryDirectory
from threading import Event
from typing import List

from anchore.grype import Grype
from anchore.syft import Syft
from db.cve_breadcrumbs_database import BreadcrumbsDatabase
from qmodel.message import Message
from shared.logger import logger
from shared.utils import Timer
from worker.analzyer import AnalyzerWorker
from worker.crawler import CrawlerWorker
from worker.downloader import DownloaderWorker
from worker.generator import GeneratorWorker
from worker.scanner import ScannerWorker

"""
File: worker_factory.py

Description: Factory for coupling and generating graven workers

@author Derek Garcia
"""


class WorkerFactory:
    def __init__(self):
        """
        Create new worker factory
        """
        # attempt to log in into the database
        self._database = BreadcrumbsDatabase()

        # shared scribe objects
        self._analyze_queue: Queue[Message] = Queue()

        # shared crawler objects
        self._crawler_done_flag = Event()

        # shared downloader objects
        self._download_queue: Queue[Message] = Queue()
        self._downloader_done_flag = Event()

        # shared generator objects
        self._generator_queue: Queue[Message] = Queue()
        self._generator_done_flag = Event()

        # shared scanner objects
        self._scan_queue: Queue[Message] = Queue()
        self._scan_done_flag = Event()

    def create_crawler_worker(self, max_concurrent_requests: int, update: bool) -> CrawlerWorker:
        """
        Create a new crawler worker

        :param update: Add jar url to download queue even if already in the database
        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once
        :return: CrawlerWorker
        """

        return CrawlerWorker(self._database, self._download_queue,
                             self._crawler_done_flag, update, max_concurrent_requests)

    def create_downloader_worker(self, max_concurrent_requests: int, download_limit: int) -> DownloaderWorker:
        """
        Create a new downloader worker

        :param max_concurrent_requests: Max number of concurrent requests allowed to be made at once
        :param download_limit: Max number of jars to be downloaded at one time
        :return: DownloaderWorker
        """
        return DownloaderWorker(self._database, self._download_queue, self._generator_queue,
                                self._crawler_done_flag, self._downloader_done_flag,
                                max_concurrent_requests, download_limit)

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
        return GeneratorWorker(self._database, syft, self._generator_queue, self._scan_queue,
                               self._downloader_done_flag, self._generator_done_flag, max_threads)

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
        return ScannerWorker(self._database, grype, self._scan_queue, self._analyze_queue,
                             self._generator_done_flag, self._scan_done_flag, max_threads)

    def create_analyzer_worker(self, max_threads: int) -> AnalyzerWorker:
        """
        Create a new analyzer worker

        :param max_threads: Max number of threads to parse anchore results
        :return: AnalyzerWorker
        """
        return AnalyzerWorker(self._database, self._analyze_queue, self._scan_done_flag, max_threads)

    def run_workers(self, crawler: CrawlerWorker, downloader: DownloaderWorker, generator: GeneratorWorker,
                    scanner: ScannerWorker, analyzer: AnalyzerWorker, root_url: str = None,
                    seed_urls: List[str] = None) -> None:
        """
        Run all workers until completed

        :param crawler: Crawler Worker
        :param downloader: Downloader Worker
        :param generator: Generator Worker
        :param scanner: Scanner Worker
        :param analyzer: Analyzer Worker
        :param root_url: Root URL to start at
        :param seed_urls: List of URLs to continue crawling
        """
        logger.info("Launching Graven worker threads...")
        # spawn tasks
        timer = Timer()
        with TemporaryDirectory(prefix='graven_') as tmp_dir:
            timer.start()
            run_id = self._database.log_run_start(generator.get_syft_version(), scanner.get_grype_version(), scanner.get_grype_db_source())
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(analyzer.start, run_id),
                    executor.submit(crawler.start, run_id, root_url if root_url else seed_urls.pop(), seed_urls),
                    executor.submit(downloader.start, run_id, tmp_dir),
                    executor.submit(generator.start, run_id, tmp_dir),
                    executor.submit(scanner.start, run_id, tmp_dir)
                ]
                concurrent.futures.wait(futures)

        # print task durations
        self._database.log_run_end(run_id, datetime.now(timezone.utc))
        timer.stop()
        logger.info(f"Total Execution Time: {timer.format_time()}")
        crawler.print_statistics_message()
        downloader.print_statistics_message()
        generator.print_statistics_message()
        scanner.print_statistics_message()
