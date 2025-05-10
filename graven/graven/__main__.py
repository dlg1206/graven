from argparse import Namespace

from dotenv import load_dotenv

from shared.cache_manager import DEFAULT_MAX_CAPACITY, mb_to_bytes
from shared.logger import Level, logger
from shared.parser import create_parser, parse_input_args_for_seed_urls
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

    # init crawl
    if args.command == 'run' or args.command == 'crawl':
        seed_urls = parse_input_args_for_seed_urls(args)
        pipline_builder.set_crawler_worker(seed_urls, args.update or args.update_domain, args.update or args.update_jar)
    # init process
    if args.command == 'run' or args.command == 'process':
        download_cache = mb_to_bytes(args.download_cache_size) if args.download_cache_size else DEFAULT_MAX_CAPACITY
        jar_limit = args.jar_limit if hasattr(args, 'jar_limit') else None
        grype_cache = mb_to_bytes(args.grype_cache_size) if args.grype_cache_size else DEFAULT_MAX_CAPACITY
        pipline_builder.set_process_workers(download_cache, grype_cache, args.grype_path, args.grype_db_source,
                                            jar_limit)

        # todo - add cli option to skip this
        syft_cache = mb_to_bytes(args.syft_cache_size) if args.syft_cache_size else DEFAULT_MAX_CAPACITY
        pipline_builder.set_generator_worker(syft_cache, args.syft_path)
    # init vuln fetch
    if args.command == 'run' or args.command == 'update-vuln':
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
