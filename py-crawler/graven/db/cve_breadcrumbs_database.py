"""
File: cve_breadcrumbs_database.py

Description: MySQL database interface for CVE-Breadcrumbs database

@author Derek Garcia
"""
import json
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any

from mysql.connector import ProgrammingError, DatabaseError

from db.database import MySQLDatabase
from db.tables import Data, Association
from log.logger import logger

DEFAULT_POOL_SIZE = 32

MAVEN_CENTRAL_ROOT = "https://repo1.maven.org/maven2/"


class Stage(Enum):
    """
    Stage enums - max is 5 chars
    """
    CRAWLER = "CRAWL"
    DOWNLOADER = "DWNLD"
    ANALYZER = "ALYZR"


class BreadcrumbsDatabase(MySQLDatabase):
    def __init__(self, pool_size: int = DEFAULT_POOL_SIZE):
        """
        Create a new interface connection to the database

        :param pool_size: Size of the database pool (max is 32)
        """
        try:
            super().__init__(pool_size)
        except (ProgrammingError, DatabaseError) as e:
            logger.fatal(e)
        logger.info("Connected to the database")

    def has_seen_domain_url(self, url: str) -> bool:
        """
        Check if the database has seen these domains before

        :param url: URL to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Data.DOMAIN, where_equals=[('url', url)])) != 0

    def has_seen_jar_url(self, url: str) -> bool:
        """
        Check if the database has seen these jars before

        :param url: URL to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Data.JAR, where_equals=[('uri', url.removeprefix(MAVEN_CENTRAL_ROOT))])) != 0

    def save_domain_url_as_seen(self, run_id: int, url: str, last_crawled: datetime) -> None:
        """
        Save that this domain has been crawled

        :param run_id: ID of the jar and scan was done in
        :param url: URL of root domain fully crawled
        :param last_crawled: Timestamp of when last crawled domain (Default: now)
        """
        self._upsert(Data.DOMAIN, ('url', url), [('run_id', run_id), ('last_crawled', last_crawled)])

    def upsert_jar_and_grype_results(self, run_id: int, jar_url: str,
                                     published_date: datetime,
                                     cves: List[str],
                                     last_scanned: datetime) -> None:
        """
        Add a jar to the database and any associated CVEs

        :param run_id: ID of the jar and scan was done in
        :param jar_url: URL of jar
        :param published_date: Date when the jar was published
        :param cves: List of CVEs associated with the jar
        :param last_scanned: Date last scanned with grype (Default: now)
        """
        components = jar_url.replace(MAVEN_CENTRAL_ROOT, "").split("/")
        jar_id = components[-1]
        # add jar
        inserts = [
            ('run_id', run_id),
            ('uri', jar_url.replace(MAVEN_CENTRAL_ROOT, "")),
            ('group_id', ".".join(components[:-3])),
            ('artifact_id', components[-3]),
            ('version', components[-2]),
            ('publish_date', published_date),
            ('last_scanned', last_scanned)
        ]
        self._upsert(Data.JAR, ('jar_id', jar_id), inserts)
        # add cves
        for cve_id in cves:
            self._insert(Data.CVE, [('cve_id', cve_id), ('run_id', run_id)], on_success_msg=f"Add new cve '{cve_id}'")
            self._insert(Association.JAR__CVE, [('jar_id', jar_id), ('cve_id', cve_id), ('run_id', run_id)])

    def log_run_start(self, grype_version: str, grype_db_source: str) -> int:
        """
        Log a start of a run

        :param grype_version: Version of grype used
        :param grype_db_source: URL source of grype used
        :return: run id
        """
        run_id = self._insert(Data.RUN_LOG, [('grype_version', grype_version), ('grype_db_source', grype_db_source)])
        return run_id

    def log_run_end(self, run_id: int, run_end_time: datetime) -> None:
        """
        log the end of a run

        :param run_id: ID of run to end
        :param run_end_time: Time run ended
        """
        self._update(Data.RUN_LOG, [('end', run_end_time)], [('run_id', run_id)])

    def log_error(self, run_id: int, stage: Stage, url: str, error: Exception, comment: str = None,
                  details: Dict[Any, Any] = None) -> None:
        """
        Log an error in the database

        :param run_id: ID of the jar and scan was done in
        :param stage: Stage of pipeline the error occurred at
        :param url: URL of resource
        :param error: Error that occurred
        :param comment: Optional comment about error
        :param details: Option JSON data to include to help debug error
        """
        inserts = [('run_id', run_id), ('stage', stage.value), ('url', url),
                   ('error_type', type(error).__name__), ('error_message', str(error))]
        if comment:
            inserts.append(('comment', comment))
        if details:
            inserts.append(('details', json.dumps(details)))
        self._insert(Data.ERROR_LOG, inserts)
