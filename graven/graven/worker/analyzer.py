"""
File: analyzer.py

Description: Worker dedicated to parsing anchore output and writing data to the database

@author Derek Garcia
"""

import json
from abc import ABC
from concurrent.futures import Future
from datetime import datetime, timezone
from threading import Event

import zstandard as zstd

from db.graven_database import GravenDatabase, Stage, FinalStatus
from qmodel.file import GrypeFile, SyftFile
from qmodel.message import Message
from shared.logger import logger
from shared.timer import Timer
from worker.worker import Worker

MAX_ANALYZER_THREADS = 50


class AnalyzerWorker(Worker, ABC):
    """
    Worker dedicated to parsing anchore output and writing data to the database
    """

    def __init__(self, master_terminate_flag: Event, database: GravenDatabase):
        """
        Create a new analyzer worker that constantly parses anchore output and saves data to the database

        :param master_terminate_flag: Master event to exit if keyboard interrupt
        :param database: Database to save results to
        """
        super().__init__(master_terminate_flag, database, "analyzer")
        self._analyzer_first_hit_flag = None
        self._analyzer_done_flag = None
        self._seen_file = False
        # set at runtime
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
        logger.debug_msg(f"Compressed and saved SBOM | {jar_id}")

    def _save_grype_results(self, jar_id: str, grype_file: GrypeFile) -> None:
        """
        Parse and save grype results into the database
        jar must exist in the database

        :param jar_id: Primary jar id
        :param grype_file: Metadata object with path to grype file
        """
        with open(grype_file.file_path, 'r') as f:
            grype_data = json.load(f)

        for hit in grype_data.get('matches', []):
            vuln = hit['vulnerability']
            vid = vuln.get('id', '')
            # skip non-cves
            if not vid.startswith('CVE'):
                logger.debug_msg(f"Skipping non-CVE '{vid}'")
                continue
            # skip update if seen
            if self._database.has_seen_cve(vid):
                logger.debug_msg(f"Seen '{vid}', skipping. . .")
            else:
                # set if first hit
                if self._analyzer_first_hit_flag and not self._analyzer_done_flag.is_set():
                    self._analyzer_first_hit_flag.set()
                self._database.upsert_cve(
                    self._run_id, vid, severity=vuln['severity'])
                logger.info(f"Found new CVE: '{vid}'")

            # save to db
            self._database.associate_jar_and_cve(self._run_id, jar_id, vid)
        # save timestamp (grype uses RFC 3339 timestamp?)
        last_scanned = datetime.fromisoformat(
            grype_data['descriptor']['timestamp']).astimezone(
            timezone.utc)
        self._database.upsert_jar_last_grype_scan(
            self._run_id, jar_id, last_scanned)
        logger.debug_msg(f"Processed and saved grype report | {jar_id}")

    def _analyze_files(self, message: Message) -> None:
        """
        Parse syft and grype (if available) files and save it to the database

        :param message: Message with all data to parse and save
        """
        self._database.log_event(message.jar_id, event_label="analyzer_dequeue")
        # skip if stop order triggered
        if self._master_terminate_flag.is_set():
            if message.syft_file:
                logger.debug_msg(f"[STOP ORDER RECEIVED] | Skipping analysis | {message.syft_file.file_name}")
            if message.grype_file:
                logger.debug_msg(f"[STOP ORDER RECEIVED] | Skipping analysis | {message.grype_file.file_name}")
            self._handle_shutdown(message)
            return
        # process files
        self._database.update_jar_status(message.jar_id, Stage.ANALYZER)
        try:
            timer = Timer(True)
            # process and save sbom
            if message.syft_file:
                if message.syft_file.is_open:
                    self._compress_and_save_sbom(
                        message.jar_id, message.syft_file)
                    message.syft_file.close()
                else:
                    logger.debug_msg(f"syft file is closed, skipping. . . | {message.syft_file.file_name}")
            else:
                logger.debug_msg("syft file dne, skipping. . .")
            # process grype report
            if message.grype_file.is_open:
                self._save_grype_results(message.jar_id, message.grype_file)
                message.grype_file.close()
            else:
                logger.debug_msg(f"grype file is closed, skipping. . . | {message.grype_file.file_name}")
            # mark as done
            self._database.update_jar_status(message.jar_id, FinalStatus.DONE)
            self._database.log_event(message.jar_id, event_label="analyzer_end")
            logger.info(f"Processed in {timer.format_time()}s | {message.jar_id}")
        except Exception as e:
            logger.error_exp(e)
            self._database.log_error(
                self._run_id, Stage.ANALYZER, e, jar_id=message.jar_id)
            self._database.update_jar_status(message.jar_id, FinalStatus.ERROR)
        finally:
            # remove any remaining files
            message.close()
            self._consumer_queue.task_done()

    def _handle_message(self, message: Message | str) -> Future | None:
        """
        Handle a message from the queue and return the future submitted to the executor

        :param message: The message to handle
        :return: The Future task or None if now task made
        """
        # restart timer on first file
        if not self._seen_file:
            self._seen_file = True
            self._timer.start()
        self._database.log_event(message.jar_id, event_label="analyzer_enqueue")
        return self._thread_pool_executor.submit(self._analyze_files, message)

    def _post_start(self) -> None:
        """
        Set the done flag if using
        """
        # indicate the analyzer is finished
        if self._analyzer_done_flag:
            self._analyzer_done_flag.set()
        # ensure the hit flag it set if used regardless of any hits to not
        # deadlock rest of the pipeline
        if self._analyzer_first_hit_flag:
            self._analyzer_first_hit_flag.set()

    def print_statistics_message(self) -> None:
        """
        Print worker specific statistic messages
        """
        return

    def set_first_hit_flag(self, flag: Event) -> None:
        """
        Set the first hit flag

        :param: Flag to indicate that the analyzer added a CVE if using analyzer
        """
        self._analyzer_first_hit_flag = flag

    def set_done_flag(self, flag: Event) -> None:
        """
        Set the done flag

        :param: Flag to indicate that the analyzer is finished if using analyzer
        """
        self._analyzer_done_flag = flag
