"""
File: __main__.py
Description: Main entrypoint for crawling operations

@author Derek Garcia
"""
import asyncio
import threading
import time
from argparse import ArgumentParser, Namespace
from typing import Tuple, Coroutine

from analyze.analyzer import AnalyzerWorker, DEFAULT_MAX_THREADS, check_for_grype
from crawl.crawler import CrawlerWorker, DEFAULT_MAX_RETRIES
from db.cve_breadcrumbs_database import BreadcrumbsDatabase
from download.downloader import DownloaderWorker, DEFAULT_MAX_JAR_LIMIT
from log.logger import Level, logger
from shared.defaults import DEFAULT_MAX_CONCURRENT_REQUESTS, format_time


async def _timed_task(worker_name: str, coroutine: Coroutine) -> Tuple[str, float]:
    """
    Wrapper for coroutine to time execution

    :param worker_name: Name of worker
    :param coroutine: Coroutine to await
    :return: Name of worker, duration string in hh:mm:ss
    """
    start_time = time.perf_counter()
    await coroutine
    return worker_name, time.perf_counter() - start_time


def _create_workers(max_retries: int, max_concurrent_requests: int, max_threads: int) \
        -> Tuple[CrawlerWorker, DownloaderWorker, AnalyzerWorker]:
    """
    Create the crawler, downloader, and analyzer workers used to create crawl for and processes jars

    :param max_retries: Max retries for crawler before terminating
    :param max_concurrent_requests: Max allowed concurrent requests for crawler and downloader independently
    :param max_threads: Max threads allowed to be used for scanning jars with grype
    :return: CrawlerWorker, DownloaderWorker, AnalyzerWorker
    """
    # check for grype
    try:
        check_for_grype()
    except FileNotFoundError as e:
        logger.fatal(e)
    # attempt to log in into the database
    database = BreadcrumbsDatabase()
    # create shared queues
    download_queue = asyncio.Queue()
    analyze_queue = asyncio.Queue()
    # create signal flags
    crawler_done_flag = asyncio.Event()
    downloader_done_flag = asyncio.Event()
    # create workers
    c = CrawlerWorker(database, download_queue, crawler_done_flag, max_retries, max_concurrent_requests)
    d = DownloaderWorker(database, download_queue, analyze_queue, crawler_done_flag, downloader_done_flag,
                         max_concurrent_requests)
    a = AnalyzerWorker(database, analyze_queue, downloader_done_flag, max_threads)
    return c, d, a


async def _execute(args: Namespace) -> None:
    """
    run graven

    :param args: args to get command details from
    """
    start_time = time.perf_counter()
    crawler, downloader, analyzer = _create_workers(args.retries, args.concurrent_requests, args.threads)
    download_limit = threading.Semaphore(args.jar_limit)

    # spawn tasks
    tasks = [_timed_task("Crawler", crawler.start(args.root_url)),
             _timed_task("Downloader", downloader.start(download_limit)),
             _timed_task("Analyzer", analyzer.start())]

    # print task durations
    for worker_name, duration in await asyncio.gather(*tasks):
        logger.info(f"{worker_name} completed in {format_time(duration)}")
    end_time = time.perf_counter()
    logger.info(f"Total Execution Time: {format_time(end_time - start_time)}")


def _create_parser() -> ArgumentParser:
    """
    Create the Arg parser

    :return: Arg parser
    """
    parser = ArgumentParser(
        description='Recursive and optimized crawler for scraping the Maven Central Repository',
        prog='graven'
    )
    # logging flags
    parser.add_argument('-l', '--log-level',
                        metavar='<log level>',
                        choices=[Level.INFO.name, Level.DEBUG.name, Level.ERROR.name],
                        help=f'Set log level (Default: INFO) ({[Level.INFO.name, Level.DEBUG.name, Level.ERROR.name]})',
                        default=Level.INFO.name)
    parser.add_argument('-s', '--silent',
                        action='store_true',
                        help='Run in silent mode',
                        default=False)
    # start url
    parser.add_argument('root_url', help="Root URL to start crawler at")

    # optional flags
    parser.add_argument('-r', '--retries',
                        help="Max number of times to attempt to pop from the crawl queue before quitting",
                        default=DEFAULT_MAX_RETRIES
                        )
    parser.add_argument('-c', '--concurrent_requests',
                        help="Max number of concurrent requests each worker can make at once",
                        default=DEFAULT_MAX_CONCURRENT_REQUESTS)

    parser.add_argument('-j', '--jar_limit',
                        help="Max number of jars allowed to be downloaded at once",
                        default=DEFAULT_MAX_JAR_LIMIT)

    parser.add_argument('-t', '--threads',
                        help="Max number of threads allowed to be used to scan jars. Increase with caution",
                        default=DEFAULT_MAX_THREADS)

    return parser


def main() -> None:
    """
    Parse initial arguments and execute commands
    """
    args = _create_parser().parse_args()
    # set logging level
    if args.silent:
        # silent override all
        logger.set_log_level(Level.SILENT)
    elif args.log_level is not None:
        # else update if option
        logger.set_log_level(args.log_level)

    # create command
    asyncio.run(_execute(args))


if __name__ == '__main__':
    main()
