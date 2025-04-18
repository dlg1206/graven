from queue import Queue
from threading import Event

from anchore.grype import Grype
from shared.cve_breadcrumbs_database import BreadcrumbsDatabase
from worker.analyzer import AnalyzerWorker
from worker.crawler import CrawlerWorker
from worker.downloader import DownloaderWorker

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

        # shared crawler objects
        self._crawler_done_flag = Event()

        # shared downloader objects
        self._download_queue = Queue()
        self._downloader_done_flag = Event()

        # shared analyzer objects
        self._analyze_queue = Queue()

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
        return DownloaderWorker(self._database, self._download_queue, self._analyze_queue,
                                self._crawler_done_flag, self._downloader_done_flag,
                                max_concurrent_requests, download_limit)

    def create_analyzer_worker(self, grype: Grype, max_threads: int) -> AnalyzerWorker:
        """
        Create a new analyzer worker

        :param grype: Grype interface to use for scanning
        :param downloader: DownloaderWorker being used
        :param max_threads: Max number of concurrent requests allowed to be made at once
        """
        return AnalyzerWorker(self._database, grype, self._analyze_queue, self._downloader_done_flag, max_threads)
