"""
File: __main__.py
Description: Main entrypoint for crawling operations

@author Derek Garcia
"""
import csv
from argparse import ArgumentParser, Namespace
from datetime import datetime, timezone
from queue import Queue
from tempfile import TemporaryDirectory

from common.logger import Level, logger

from cve_breadcrumbs_database import BreadcrumbsDatabase
from grype import Grype, GRYPE_BIN
from shared.utils import DEFAULT_MAX_CONCURRENT_REQUESTS, Timer
from worker.analyzer import AnalyzerWorker, DEFAULT_MAX_ANALYZER_THREADS
from worker.crawler import CrawlerWorker
from worker.downloader import DownloaderWorker, DEFAULT_MAX_JAR_LIMIT


def _execute(args: Namespace) -> None:
    """
    run graven

    :param args: args to get command details from
    """
    # attempt to log in into the database
    database = BreadcrumbsDatabase()

    # parse seed urls if any
    seed_urls = None
    if args.seed_urls_csv:
        try:
            with open(args.seed_urls_csv) as file:
                csv_reader = csv.reader(file)
                seed_urls = [row[0] for row in csv_reader]
        except Exception as e:
            logger.fatal(e)

    # make workers
    download_queue = Queue()
    analyze_queue = Queue()

    grype = Grype(bin_path=args.grype_path, db_source_url=args.grype_db_source) if args.grype_path else Grype(
        db_source_url=args.grype_db_source)
    crawler = CrawlerWorker(database,
                            args.update,
                            download_queue,
                            args.crawler_requests)
    downloader = DownloaderWorker(database,
                                  download_queue,
                                  analyze_queue,
                                  crawler.get_crawler_done_flag(),
                                  args.downloader_requests,
                                  args.jar_limit)
    analyzer = AnalyzerWorker(database,
                              grype,
                              analyze_queue,
                              downloader.get_downloader_done_flag(),
                              args.analyzer_threads)

    # spawn tasks
    timer = Timer()
    with TemporaryDirectory() as tmp_dir:
        timer.start()
        run_id = database.log_run_start(grype.get_version(), grype.get_db_source())
        threads = [
            crawler.start(run_id, args.root_url if args.root_url else seed_urls.pop(), seed_urls),
            downloader.start(run_id, tmp_dir),
            analyzer.start(run_id)
        ]
        for t in threads:
            t.join()

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
    crawler_group.add_argument("--crawler-requests",
                               metavar="<number of requests>",
                               type=int,
                               help=f"Max number of requests crawler can make at once (Default: {DEFAULT_MAX_CONCURRENT_REQUESTS})",
                               default=DEFAULT_MAX_CONCURRENT_REQUESTS)

    downloader_group = parser.add_argument_group("Downloader Options")
    downloader_group.add_argument("--downloader-requests",
                                  metavar="<number of requests>",
                                  type=int,
                                  help=f"Max number of downloads downloader can make at once (Default: {DEFAULT_MAX_CONCURRENT_REQUESTS})",
                                  default=DEFAULT_MAX_CONCURRENT_REQUESTS)

    downloader_group.add_argument("--jar-limit",
                                  metavar="<number of jars>",
                                  type=int,
                                  help=f"Max number of jars allowed to be to downloaded local at once (Default: {DEFAULT_MAX_JAR_LIMIT})",
                                  default=DEFAULT_MAX_JAR_LIMIT)

    analyzer_group = parser.add_argument_group("Analyzer Options")
    analyzer_group.add_argument("--analyzer-threads",
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
    # create command
    _execute(args)


if __name__ == "__main__":
    main()
