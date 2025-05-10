import csv
from argparse import ArgumentParser, Namespace
from typing import List

from anchore.grype import GRYPE_BIN
from anchore.syft import SYFT_BIN
from shared.cache_manager import bytes_to_mb, DEFAULT_MAX_CAPACITY
from shared.logger import Level
from worker.pipeline_builder import DEFAULT_MAX_CONCURRENT_MAVEN_REQUESTS, DEFAULT_MAX_CPU_THREADS

"""
File: cli_parser.py

Description: Parser for CLI arguments

@author Derek Garcia
"""


def _add_input_options(parser: ArgumentParser) -> None:
    """
    Add input options to the given parser
    """
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


def _add_crawl_options(parser: ArgumentParser) -> None:
    """
    Add crawler options to the given parser
    """
    crawler_group = parser.add_argument_group("Crawler Options")
    crawler_group.add_argument("--update-domain",
                               action="store_true",
                               help="Update domains that have already been crawled. "
                                    "Useful for ensuring no jars were missed in a domain")

    crawler_group.add_argument("--update-jar",
                               action="store_true",
                               help="Update jars that have already been crawled")

    crawler_group.add_argument("-u", "--update",
                               action="store_true",
                               help="Update domains AND jars that have already been crawled. "
                                    "Supersedes --update-* flags")


def _add_process_options(parser: ArgumentParser) -> None:
    """
    Add process options to the given parser
    """
    downloader_group = parser.add_argument_group("Downloader Options")
    downloader_group.add_argument("--download-cache-size",
                                  metavar="<cache size in MB>",
                                  type=float,
                                  help=f"Limit of the number of jars to be saved at one time. "
                                       f"(Default: {bytes_to_mb(DEFAULT_MAX_CAPACITY)} MB)")

    downloader_group.add_argument("--jar-limit",
                                  metavar="<max jar count>",
                                  type=int,
                                  help="Limit the number of jars downloaded at once")

    generator_group = parser.add_argument_group("Generator Options")
    generator_group.add_argument("--syft-path",
                                 metavar="<absolute path to syft binary>",
                                 type=str,
                                 help=f"Path to syft binary to use. By default, assumes syft is already on the PATH",
                                 default=SYFT_BIN)
    generator_group.add_argument("--syft-cache-size",
                                 metavar="<cache size in MB>",
                                 type=float,
                                 help=f"Limit of the number of grype files to be saved at one time. "
                                      f"(Default: {bytes_to_mb(DEFAULT_MAX_CAPACITY)} MB)")
    generator_group.add_argument("--disable-syft",
                                 action="store_true",
                                 help="Disable SBOM generation and scan jars directly")

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

    scanner_group.add_argument("--grype-cache-size",
                               metavar="<cache size in MB>",
                               type=float,
                               help=f"Limit of the number of grype files to be saved at one time. "
                                    f"(Default: {bytes_to_mb(DEFAULT_MAX_CAPACITY)} MB)")


def _add_misc_options(parser: ArgumentParser,
                      add_request_limit: bool = True,
                      add_cpu_limit: bool = True,
                      add_disable_vuln: bool = True,
                      add_enable_vuln: bool = False) -> None:
    """
    Add misc options to the given parser

    :param add_request_limit: Add the request limit arg (Default: True)
    :param add_cpu_limit: Add max cpu thread limit arg (Default: True)
    :param add_disable_vuln: Add disable vuln update arg (Default: True)
    :param add_enable_vuln: Add enable vuln update arg (Default: False)
    """
    misc_group = parser.add_argument_group("Miscellaneous Options")

    if add_request_limit:
        misc_group.add_argument("--max-concurrent-maven-requests",
                                metavar="<number of requests>",
                                type=int,
                                help=f"Max number of requests can make at once to Maven Central. "
                                     f"(Default: {DEFAULT_MAX_CONCURRENT_MAVEN_REQUESTS})",
                                default=DEFAULT_MAX_CONCURRENT_MAVEN_REQUESTS)

    if add_cpu_limit:
        misc_group.add_argument("--max-cpu-threads",
                                metavar="<number of the threads>",
                                type=int,
                                help=f"Max number of threads allowed to be used to generate anchore results. "
                                     f"Increase with caution (Default: {DEFAULT_MAX_CPU_THREADS})",
                                default=DEFAULT_MAX_CPU_THREADS)

    if add_disable_vuln:
        misc_group.add_argument("--disable-update-vuln",
                                action='store_true',
                                help="Disable real-time queries for CVE and CWE details")
    if add_enable_vuln:
        misc_group.add_argument("--enable-update-vuln",
                                action='store_true',
                                help="Enable real-time queries for CVE and CWE details")


def create_parser() -> ArgumentParser:
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

    subparsers = parser.add_subparsers(dest="command", required=True)

    # run
    run_help = "Run the entire graven pipeline"
    run_parser = subparsers.add_parser("run", help=run_help, description=run_help)
    _add_input_options(run_parser)
    _add_crawl_options(run_parser)
    _add_process_options(run_parser)
    _add_misc_options(run_parser)

    # crawl
    crawl_help = "Crawl Maven Central for jars"
    crawl_parser = subparsers.add_parser("crawl", help=crawl_help, description=crawl_help)
    _add_input_options(crawl_parser)
    _add_crawl_options(crawl_parser)
    _add_misc_options(crawl_parser, add_cpu_limit=False, add_disable_vuln=False)

    # process
    process_help = "Process jars stored in the database"
    process_parser = subparsers.add_parser("process", help=process_help, description=process_help)
    _add_process_options(process_parser)
    _add_misc_options(process_parser, add_disable_vuln=False, add_enable_vuln=True)

    # vuln
    vuln_help = "Update CVE and CWE data"
    subparsers.add_parser("update-vuln", help=vuln_help,
                          description=f"{vuln_help}. Will use 'NVD_API_KEY' env variable if available")

    # export
    export_help = "Export SBOMs in the database to file"
    export_parser = subparsers.add_parser("export", help=export_help, description=export_help)
    export_parser.add_argument("-d", "--directory",
                               type=str,
                               help="Directory to save dump to",
                               required=True)

    export_parser.add_argument("-c", "--compression-method",
                               type=str,
                               choices=['zip', 'tar.gz'],
                               help="Compression mode to export data to",
                               required=True)

    return parser


def parse_input_args_for_seed_urls(args: Namespace) -> List[str]:
    """
    Parse input args for seed urls

    :param args: Args to parse
    :return: List of urls to parse
    """
    if args.seed_urls_csv:
        with open(args.seed_urls_csv) as file:
            csv_reader = csv.reader(file)
            return [row[0] for row in csv_reader]

    # only root
    return [args.root_url]
