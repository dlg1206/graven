from argparse import Namespace

from dotenv import load_dotenv

from shared.cache_manager import DEFAULT_MAX_CAPACITY, mb_to_bytes
from shared.cli_parser import create_parser, parse_input_args_for_seed_urls
from shared.logger import Level, logger
from worker.pipeline_builder import PipelineBuilder

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
    # init pipeline
    pipline_builder = PipelineBuilder()
    if hasattr(args, 'max_concurrent_maven_requests'):
        pipline_builder.set_io_thread_limit(args.max_concurrent_maven_requests)
    if hasattr(args, 'max_cpu_threads'):
        pipline_builder.set_cpu_thread_limit(args.max_cpu_threads)

    # determine command
    is_run = args.command == 'run'
    is_crawl = args.command == 'crawl'
    is_process = args.command == 'process'
    is_update_vuln = args.command == 'update-vuln'

    # Init crawl
    if is_run or is_crawl:
        seed_urls = parse_input_args_for_seed_urls(args)
        update_domain = args.update or args.update_domain
        update_jar = args.update or args.update_jar
        pipline_builder.set_crawler_worker(seed_urls, update_domain, update_jar)

    # Init process
    if is_run or is_process:
        download_cache = mb_to_bytes(args.download_cache_size) if args.download_cache_size else DEFAULT_MAX_CAPACITY
        grype_cache = mb_to_bytes(args.grype_cache_size) if args.grype_cache_size else DEFAULT_MAX_CAPACITY
        jar_limit = getattr(args, 'jar_limit', None)

        pipline_builder.set_process_workers(
            download_cache,
            grype_cache,
            args.grype_path,
            args.grype_db_source,
            jar_limit
        )

        # Add syft worker if not disabled
        if not getattr(args, 'disable_syft', False):
            syft_cache = mb_to_bytes(args.syft_cache_size) if args.syft_cache_size else DEFAULT_MAX_CAPACITY
            pipline_builder.set_generator_worker(syft_cache, args.syft_path)

    # Init vuln fetch worker
    vuln_enabled = (is_run and not getattr(args, 'disable_update_vuln', False)) or getattr(args, 'enable_update_vuln',
                                                                                           False) or is_update_vuln

    if vuln_enabled:
        pipline_builder.set_vuln_worker()

    # start job
    exit_code = pipline_builder.run_workers()
    exit(exit_code)


def main() -> None:
    """
    Parse initial arguments and execute commands
    """
    args = create_parser().parse_args()
    # set logging level
    if args.silent:
        # silent override all
        logger.set_log_level(Level.SILENT.value)
    elif args.log_level is not None:
        # else update if option
        logger.set_log_level(args.log_level)

    try:
        _execute(args)
    except Exception as e:
        logger.fatal(e)


if __name__ == "__main__":
    load_dotenv()
    main()
