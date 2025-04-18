import concurrent
import csv
from argparse import ArgumentParser, Namespace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from tempfile import TemporaryDirectory

from common.logger import Level, logger

from anchore.grype import Grype, GRYPE_BIN
from shared.cve_breadcrumbs_database import BreadcrumbsDatabase
from shared.utils import DEFAULT_MAX_CONCURRENT_REQUESTS, Timer
from worker.analyzer import DEFAULT_MAX_ANALYZER_THREADS
from worker.downloader import DEFAULT_MAX_JAR_LIMIT
from worker.worker_factory import WorkerFactory

"""
File: __main__.py
Description: Main entrypoint for crawling operations

@author Derek Garcia
"""


def _execute(args: Namespace) -> None:
    """
    run graven

    :param args: args to get command details from
    """
    # attempt to log in into the database
    database = BreadcrumbsDatabase()
    worker_factory = WorkerFactory()

    # parse seed urls if any
    seed_urls = None
    if args.seed_urls_csv:
        with open(args.seed_urls_csv) as file:
            csv_reader = csv.reader(file)
            seed_urls = [row[0] for row in csv_reader]

    if args.grype_path:
        grype = Grype(bin_path=args.grype_path, db_source_url=args.grype_db_source)
    else:
        grype = Grype(args.grype_db_source)

    # make workers
    crawler = worker_factory.create_crawler_worker(args.update, args.max_concurrent_crawl_requests)
    downloader = worker_factory.create_downloader_worker(args.max_concurrent_download_requests, args.download_limit)
    analyzer = worker_factory.create_analyzer_worker(grype, args.max_threads)

    # spawn tasks
    timer = Timer()
    with TemporaryDirectory() as tmp_dir:
        timer.start()
        run_id = database.log_run_start(grype.get_version(), grype.db_source)
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(crawler.start, run_id, args.root_url if args.root_url else seed_urls.pop(), seed_urls),
                executor.submit(downloader.start, run_id, tmp_dir),
                executor.submit(analyzer.start, run_id)
            ]
            concurrent.futures.wait(futures)

    # print task durations
    database.log_run_end(run_id, datetime.now(timezone.utc))
    timer.stop()
    logger.info(f"Total Execution Time: {timer.format_time()}")
    crawler.print_statistics_message()
    downloader.print_statistics_message()
    analyzer.print_statistics_message()


def _create_parser() -> ArgumentParser:
    """
    Create the Arg parser

    :return: Arg parser
    """
    parser = ArgumentParser(
        description="Recursive and optimized crawler for scraping the Maven Central Repository",
        prog="graven"
    )
    # logging flags
    parser.add_argument("-l", "--log-level",
                        metavar="<log level>",
                        choices=[Level.INFO.name, Level.DEBUG.name, Level.ERROR.name],
                        help=f"Set log level (Default: INFO) ({[Level.INFO.name, Level.DEBUG.name, Level.ERROR.name]})",
                        default=Level.INFO.name)
    parser.add_argument("-s", "--silent",
                        action="store_true",
                        help="Run in silent mode",
                        default=False)
    # start url
    parser.add_argument("--root-url",
                        metavar="<starting url>",
                        help="Root URL to start crawler at")
    parser.add_argument("--seed-urls-csv",
                        metavar="<path to csv>",
                        help="CSV file of root urls to restart the crawler at once the current root url is exhausted")
    parser.add_argument("-u", "--update",
                        action="store_true",
                        help="Download jar and scan even if already in the database")

    crawler_group = parser.add_argument_group("Crawler Options")
    crawler_group.add_argument("--max-concurrent-crawl-requests",
                               metavar="<number of requests>",
                               type=int,
                               help=f"Max number of requests crawler can make at once (Default: {DEFAULT_MAX_CONCURRENT_REQUESTS})",
                               default=DEFAULT_MAX_CONCURRENT_REQUESTS)

    downloader_group = parser.add_argument_group("Downloader Options")
    downloader_group.add_argument("--max-concurrent-download-requests",
                                  metavar="<number of requests>",
                                  type=int,
                                  help=f"Max number of downloads downloader can make at once (Default: {DEFAULT_MAX_CONCURRENT_REQUESTS})",
                                  default=DEFAULT_MAX_CONCURRENT_REQUESTS)

    downloader_group.add_argument("--download-limit",
                                  metavar="<number of jars>",
                                  type=int,
                                  help=f"Max number of jars allowed to be to downloaded local at once (Default: {DEFAULT_MAX_JAR_LIMIT})",
                                  default=DEFAULT_MAX_JAR_LIMIT)

    analyzer_group = parser.add_argument_group("Analyzer Options")
    analyzer_group.add_argument("--max-threads",
                                metavar="<number of the threads>",
                                type=int,
                                help=f"Max number of threads allowed to be used to scan jars. Increase with caution (Default: {DEFAULT_MAX_ANALYZER_THREADS})",
                                default=DEFAULT_MAX_ANALYZER_THREADS)

    analyzer_group.add_argument("--grype-path",
                                metavar="<absolute path to grype binary>",
                                type=str,
                                help=f"Path to Grype binary to use. By default, assumes grype is already on the PATH",
                                default=GRYPE_BIN)

    analyzer_group.add_argument("--grype-db-source",
                                metavar="<url of grype database to use>",
                                type=str,
                                help=f"URL of specific grype database to use. To see the full list, run 'grype db list'")

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
    # at least 1 needs to be added
    if not (args.root_url or args.seed_urls_csv):
        logger.fatal("Please provide at least root_url or seed_url_csv")

    try:
        _execute(args)
    except Exception as e:
        logger.fatal(e)


if __name__ == "__main__":
    main()
