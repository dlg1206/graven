import concurrent
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from math import floor
from queue import Queue, Empty
from threading import Event

import zstandard as zstd

from db.graven_database import GravenDatabase, Stage, FinalStatus
from qmodel.file import GrypeFile, SyftFile
from qmodel.message import Message
from shared.logger import logger

"""
File: analyzer.py

Description: Worker dedicated to parsing anchore output and writing data to the database

@author Derek Garcia
"""

WRITE_TIMEOUT = 1
# GeneratorWorker and ScannerWorker get the rest of the threads
# careful increasing at risk over buffer overflow during compression
DEFAULT_MAX_ANALYZER_THREADS = int(floor(os.cpu_count() / 3))


class AnalyzerWorker:
    def __init__(self, stop_flag: Event, database: GravenDatabase,
                 analyze_queue: Queue[Message | None],
                 cve_queue: Queue[str | None],
                 max_threads: int = DEFAULT_MAX_ANALYZER_THREADS):
        """
        Create a new analyzer worker that constantly parses anchore output and saves data to the database

        :param stop_flag: Master event to exit if keyboard interrupt
        :param database: Database to save results to
        :param analyze_queue: Queue of items to save to the database
        :param max_threads: Max number of messages that can be processed at once (default: floor(os.cpu_count() / 3))
        """
        self._stop_flag = stop_flag
        self._database = database
        self._analyze_queue = analyze_queue
        self._cve_queue = cve_queue
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
        logger.debug_msg(f"Compressed and saved '{syft_file.file_name}'")

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
        last_scanned = datetime.fromisoformat(grype_data['descriptor']['timestamp'].replace("Z", "")[:26])
        self._database.upsert_jar_last_grype_scan(self._run_id, jar_id, last_scanned)

    def _process_message(self, message: Message) -> None:
        """
        Parse syft and grype (if available) files and save it to the database

        :param message: Message with all data to parse and save
        """
        # skip if stop order triggered
        if self._stop_flag.is_set():
            logger.debug_msg(f"[STOP ORDER RECEIVED] | Skipping analysis | {message.syft_file.file_name}")
            logger.debug_msg(f"[STOP ORDER RECEIVED] | Skipping analysis | {message.grype_file.file_name}")
            self._analyze_queue.task_done()
            return
        try:
            # process and save sbom
            if message.syft_file.is_open:
                self._compress_and_save_sbom(message.jar_id, message.syft_file)
                logger.info(f"Compressed syft SBOM | {message.jar_id}")
                message.syft_file.close()
            else:
                logger.debug_msg(f"syft file is closed, skipping. . . | {message.syft_file.file_name}")
            # process grype report
            if message.grype_file.is_open:
                self._save_grype_results(message.jar_id, message.grype_file)
                message.grype_file.close()
                logger.info(f"Processed grype scan | {message.jar_id}")
            else:
                logger.debug_msg(f"grype file is closed, skipping. . . | {message.grype_file.file_name}")
            # mark as done
            self._database.update_jar_status(message.jar_id, FinalStatus.DONE)
            logger.info(f"Saved {message.jar_id}")
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(self._run_id, Stage.ANALYZER, e, jar_id=message.jar_id)
            self._database.update_jar_status(message.jar_id, FinalStatus.ERROR)
        finally:
            # remove any remaining files
            if message:
                message.close()
            self._analyze_queue.task_done()

    def _analyze(self) -> None:
        """
        Start the analyzer worker
        """
        tasks = []
        with ThreadPoolExecutor(max_workers=self._max_threads) as exe:
            # first_time_wait_for_tasks("Analyzer", self._analyze_queue, self._scanner_done_flag)  # block until items to process
            # todo - waiting logic
            while not self._stop_flag.is_set():
                try:
                    message = self._analyze_queue.get(timeout=WRITE_TIMEOUT)
                    # break if poison pill - ie no more jobs
                    if not message:
                        break
                    # scan
                    self._database.update_jar_status(message.jar_id, Stage.ANALYZER)
                    tasks.append(exe.submit(self._process_message, message))
                except Empty:
                    """
                    To prevent deadlocks, the forced timeout with throw this error 
                    for another iteration of the loop to check conditions
                    """
                    continue

        # log exit type
        if self._stop_flag.is_set():
            logger.warn(f"Stop order received, exiting. . .")
            concurrent.futures.wait(tasks, timeout=0)  # fail fast
        else:
            logger.warn(f"No more files left to process, waiting for analysis to finish. . .")
            concurrent.futures.wait(tasks)
            logger.info(f"All files processed, exiting. . .")
        self._cve_queue.put(None)  # poison queue to signal stop

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
