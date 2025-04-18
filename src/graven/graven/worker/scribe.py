import queue
from queue import LifoQueue
from threading import Event

from logger import logger
from shared.cve_breadcrumbs_database import BreadcrumbsDatabase
from shared.message import ScribeMessage

"""
File: scribe.py

Description: Worker dedicated to writing data to the database

@author Derek Garcia
"""

WRITE_TIMEOUT = 1


class ScribeWorker:
    def __init__(self, database: BreadcrumbsDatabase, scribe_queue: LifoQueue[ScribeMessage],
                 analyzer_done_flag: Event):
        """
        Create a new scribe worker that constantly saves data to the database

        :param database: Database to save results to
        :param scribe_queue: Queue of items to save to the database
        :param analyzer_done_flag: Flag to indicate the analyzer has finished running
        """
        # attempt to log in into the database
        self._database = database
        self._scribe_queue = scribe_queue
        self._analyzer_done_flag = analyzer_done_flag
        self._run_id = None

    def _write(self) -> None:
        """
        Start the scribe worker
        """
        while not (self._analyzer_done_flag.is_set() and self._scribe_queue.empty()):
            try:
                scribe_msg = self._scribe_queue.get(timeout=WRITE_TIMEOUT)
                self._database.upsert_jar_and_grype_results(self._run_id, scribe_msg.url,
                                                            scribe_msg.publish_date, scribe_msg.cve_ids,
                                                            scribe_msg.last_scanned)
                self._scribe_queue.task_done()
            except queue.Empty:
                """
                To prevent deadlocks, the forced timeout with throw this error
                for another iteration of the loop to check conditions
                """
                continue

    def start(self, run_id: int) -> None:
        """
        Spawn and start the analyzer worker thread

        :param run_id: ID of run
        """
        self._run_id = run_id
        logger.info(f"Initializing scribe . .")
        # start the scribe
        logger.info(f"Starting scribe")
        self._write()
        # done
        logger.info(f"All data saved, exiting. . .")
