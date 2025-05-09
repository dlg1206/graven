import csv
from argparse import ArgumentParser, Namespace

from dotenv import load_dotenv

from anchore.grype import GRYPE_BIN
from anchore.syft import SYFT_BIN
from shared.cache_manager import bytes_to_mb, DEFAULT_MAX_CAPACITY
from shared.logger import Level, logger
from worker.worker_factory import WorkerFactory, DEFAULT_MAX_CONCURRENT_MAVEN_REQUESTS, DEFAULT_MAX_CPU_THREADS

"""
File: __main__.py
Description: Main entrypoint for graven operations

@author Derek Garcia
"""


def _execute(args: Namespace) -> None:
    """
    run graven

    :param args: args to get command details from
    """
    # attempt to log in into the database
    worker_factory = WorkerFactory()

    # parse seed urls if any
    if args.seed_urls_csv:
        with open(args.seed_urls_csv) as file:
            csv_reader = csv.reader(file)
            seed_urls = [row[0] for row in csv_reader]
    else:
        seed_urls = [args.root_url]

    # make workers
    crawler = worker_factory.create_crawler_worker(args.update or args.update_domain,
                                                   args.update or args.update_jar)
    downloader = worker_factory.create_downloader_worker(args.download_cache_size)
    generator = worker_factory.create_generator_worker(args.syft_path)
    scanner = worker_factory.create_scanner_worker(args.grype_path, args.grype_db_source)
    analyzer = worker_factory.create_analyzer_worker()

    # start job
    exit_code = worker_factory.run_workers(crawler, downloader, generator, scanner, analyzer, seed_urls)
    exit(exit_code)


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
    input_group = parser.add_argument_group(title="Input Options", description="Only one flag is permitted")
    input_flags = input_group.add_mutually_exclusive_group(required=True)
    input_flags.add_argument("--root-url",
                             metavar="<starting url>",
                             type=str,
                             help="Root URL to start crawler at")
    input_flags.add_argument("--seed-urls-csv",
                             metavar="<path to csv>",
                             type=str,
                             help="CSV file of root urls to restart the crawler "
                                  "at once the current root url is exhausted")

    crawler_group = parser.add_argument_group("Crawler Options")
    crawler_group.add_argument("--update-domain",
                               action="store_true",
                               help="Update domains that have already been crawled. "
                                    "Useful for ensuring no jars were missed in a domain"
                               )

    crawler_group.add_argument("--update-jar",
                               action="store_true",
                               help="Update jars that have already been crawled"
                               )

    crawler_group.add_argument("-u", "--update",
                               action="store_true",
                               help="Update domains AND jars that have already been crawled. "
                                    "Supersedes --update-* flags"
                               )

    downloader_group = parser.add_argument_group("Downloader Options")
    downloader_group.add_argument("--download-cache-size",
                                  metavar="<cache size in MB>",
                                  type=int,
                                  help=f"Limit of the number of jars to be saved at one time. "
                                       f"(Default: {bytes_to_mb(DEFAULT_MAX_CAPACITY)} MB)",
                                  default=DEFAULT_MAX_CAPACITY)

    generator_group = parser.add_argument_group("Generator Options")
    generator_group.add_argument("--syft-path",
                                 metavar="<absolute path to syft binary>",
                                 type=str,
                                 help=f"Path to syft binary to use. By default, assumes syft is already on the PATH",
                                 default=SYFT_BIN)

    scanner_group = parser.add_argument_group("Scanner Options")
    scanner_group.add_argument("--grype-path",
                               metavar="<absolute path to grype binary>",
                               type=str,
                               help=f"Path to Grype binary to use. By default, assumes grype is already on the PATH",
                               default=GRYPE_BIN)

    scanner_group.add_argument("--grype-db-source",
                               metavar="<url of grype database to use>",
                               type=str,
                               help=f"URL of specific grype database to use. To see the full list, run 'grype db list'")

    misc_group = parser.add_argument_group("Miscellaneous Options")
    misc_group.add_argument("--max-concurrent-maven-requests",
                            metavar="<number of requests>",
                            type=int,
                            help=f"Max number of requests can make at once to Maven Central. "
                                 f"(Default: {DEFAULT_MAX_CONCURRENT_MAVEN_REQUESTS})",
                            default=DEFAULT_MAX_CONCURRENT_MAVEN_REQUESTS)
    misc_group.add_argument("--max-cpu-threads",
                            metavar="<number of the threads>",
                            type=int,
                            help=f"Max number of threads allowed to be used to generate anchore results. "
                                 f"Increase with caution (Default: {DEFAULT_MAX_CPU_THREADS})",
                            default=DEFAULT_MAX_CPU_THREADS)

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
    load_dotenv()
    main()
