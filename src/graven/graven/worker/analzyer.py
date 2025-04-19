import concurrent
import json
import os
from concurrent.futures import ThreadPoolExecutor
from math import floor
from queue import Queue, Empty
from threading import Event

import zstandard as zstd

from db.cve_breadcrumbs_database import BreadcrumbsDatabase, Stage
from qmodel.file import GrypeFile, SyftFile
from qmodel.message import Message
from shared.logger import logger
from shared.utils import first_time_wait_for_tasks

"""
File: analyzer.py

Description: Worker dedicated to parsing anchore output and writing data to the database

@author Derek Garcia
"""

WRITE_TIMEOUT = 1
# GeneratorWorker and ScannerWorker get the rest of the threads
DEFAULT_MAX_ANALYZER_THREADS = floor(os.cpu_count() / 3)


class AnalyzerWorker:
    def __init__(self, database: BreadcrumbsDatabase,
                 analyze_queue: Queue[Message],
                 cve_queue: Queue[str],
                 scanner_done_flag: Event,
                 analyzer_done_flag: Event,
                 max_threads: int):
        """
        Create a new analyzer worker that constantly parses anchore output and saves data to the database

        :param database: Database to save results to
        :param analyze_queue: Queue of items to save to the database
        :param scanner_done_flag: Flag to indicate the scanner has finished running
        :param max_threads: Max number of messages that can be processed at once (default: floor(os.cpu_count() / 3))
        """
        self._database = database
        self._analyze_queue = analyze_queue
        self._cve_queue = cve_queue
        self._scanner_done_flag = scanner_done_flag
        self._analyzer_done_flag = analyzer_done_flag
        self._max_threads = max_threads

        self._run_id = None

    def _compress_and_save_sbom(self, jar_id: str, syft_file: SyftFile) -> None:
        """
        Compress SBOM with zstandard and save to the binary to the database

        :param jar_id: Jar ID SBOM belongs to
        :param syft_file: Syft file metadata with path to sbom file
        """
        # create a new compressor each time, sharing leads to buffer overflow
        cctx = zstd.ZstdCompressor()
        with open(syft_file.file_path, 'rb') as f:
            compressed_data = cctx.compress(f.read())

        self._database.upsert_sbom_blob(self._run_id, jar_id, compressed_data)
        logger.info(f"Compressed and saved '{syft_file.file_path}'")

    def _save_dependency_artifacts(self, jar_id: str, syft_file: SyftFile) -> None:
        """
        Parse syft SBOM and save direct dependency artifact information

        :param jar_id: Jar ID SBOM belongs to
        :param syft_file: Syft file metadata with path to sbom file
        """
        with open(syft_file.file_path, 'r') as f:
            syft_data = json.load(f)

        # no additional artifacts
        if len(syft_data['artifacts']) == 1:
            logger.debug_msg(f"'{syft_file.file_path}' does not contain any additional artifacts, skipping. . .")
            return

        # todo - assume first item is always root
        artifacts = syft_data['artifacts']
        root_id = artifacts[0]['id']
        direct_dependency_ids = {r['parent'] for r in syft_data['artifactRelationships']
                                 if r['child'] == root_id and r['type'] == "dependency-of"}

        # no direct dependencies
        if not direct_dependency_ids:
            logger.debug_msg(f"'{syft_file.file_path}' does not contain any direct dependencies, skipping. . .")
            return

        # save any additional arifact information
        for artifact in artifacts[1:]:
            # only care about direct deps for now
            if artifact['id'] not in direct_dependency_ids:
                continue
            # ensure artifact is a jar
            if artifact['type'] != "java-archive":
                continue
            purl = artifact['purl']
            # skip update if seen
            if self._database.has_seen_purl(purl):
                logger.debug_msg(f"Seen '{purl}', skipping. . .")
            else:
                self._database.upsert_artifact(self._run_id, purl, name=artifact['name'], version=artifact['version'])
                logger.info(f"Found new artifact: '{purl}'")
            # save association
            self._database.associate_sbom_and_artifact(self._run_id, jar_id, purl,
                                                       'pomProperties' in artifact['metadata'])

    def _save_grype_results(self, jar_id: str, grype_file: GrypeFile) -> None:
        """
        Parse and save grype results into the database
        jar must exist in the database

        :param jar_id: Primary jar id
        :param grype_file: Metadata object with path to grype file
        """
        with open(grype_file.file_path, 'r') as f:
            grype_data = json.load(f)

        for hit in grype_data['matches']:
            vuln = hit['vulnerability']
            vid = vuln['id']
            # skip non-cves
            if not vid.startswith('CVE'):
                logger.debug_msg(f"Skipping non-CVE '{vid}'")
                continue
            # skip update if seen
            if self._database.has_seen_cve(vid):
                logger.debug_msg(f"Seen '{vid}', skipping. . .")
            else:
                self._database.upsert_cve(self._run_id, vid, severity=vuln['severity'])
                logger.info(f"Found new CVE: '{vid}'")
                # send to nvd api to get details
                self._cve_queue.put(vid)

            # save to db
            self._database.associate_jar_and_cve(self._run_id, jar_id, vid)
        # save timestamp
        self._database.upsert_jar_last_scan(self._run_id, jar_id, grype_data['descriptor']['timestamp'])

    def _process_message(self, message: Message) -> None:
        """
        Parse syft and grype (if available) files and save it to the database

        :param message: Message with all data to parse and save
        """
        try:
            # save jar
            self._database.upsert_jar(self._run_id, message.jar_url, message.publish_date)
            # process and save sbom
            if message.syft_file.is_open:
                self._compress_and_save_sbom(message.jar_id, message.syft_file)
                self._save_dependency_artifacts(message.jar_id, message.syft_file)
                message.syft_file.close()
            # process grype report
            if message.grype_file.is_open:
                self._save_grype_results(message.jar_id, message.grype_file)
                message.grype_file.close()
            logger.info(f"Saved {message.jar_id}")
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.ANALYZER, message.jar_url, e, "error when parsing results")
            message.close()
        finally:
            # remove any remaining files
            if message:
                message.close()
            self._analyze_queue.task_done()

    def _analyze(self) -> None:
        """
        Start the analyzer worker
        """
        message = None
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            first_time_wait_for_tasks("Analyzer", self._analyze_queue,
                                      self._scanner_done_flag)  # block until items to process
            # while the scanner is still running or still tasks to process
            while not (self._scanner_done_flag.is_set() and self._analyze_queue.empty()):

                try:
                    message = self._analyze_queue.get(timeout=WRITE_TIMEOUT)
                    # scan
                    tasks.append(exe.submit(self._process_message, message))
                except Empty:
                    """
                    To prevent deadlocks, the forced timeout with throw this error
                    for another iteration of the loop to check conditions
                    """
                    continue
                except Exception as e:
                    logger.error_exp(e)
                    url = None
                    if message:
                        url = message.jar_url
                        message.close()

                    self._database.log_error(self._run_id, Stage.ANALYZER, url, e, "Failed during loop")
        logger.warn(f"No more files left to process, waiting for analysis to finish. . .")
        concurrent.futures.wait(tasks)
        self._analyzer_done_flag.set()  # signal no tasks

    def start(self, run_id: int) -> None:
        """
            Spawn and start the analyzer worker thread

            :param run_id: ID of run
            """
        self._run_id = run_id
        logger.info(f"Initializing analyzer . .")
        # start the analyzer
        logger.info(f"Starting analyzer")
        self._analyze()
        # done
        logger.info("All data saved, exiting. . .")
