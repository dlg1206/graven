"""
File: cve_breadcrumbs_database.py

Description: MySQL database interface for CVE-Breadcrumbs database

@author Derek Garcia
"""
import datetime
from enum import Enum
from typing import List

from mysql.connector import ProgrammingError, DatabaseError

from db.database import MySQLDatabase
from db.tables import Data, Association
from log.logger import logger

DEFAULT_POOL_SIZE = 10

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

    def add_jar_and_grype_results(self, jar_url: str, published_date: datetime,
                                  cves: List[str], last_scanned: datetime = datetime.datetime.now()) -> None:
        """
        Add a jar to the database and any associated CVEs

        :param jar_url: URL of jar
        :param published_date: Date when the jar was published
        :param cves: List of CVEs associated with the jar
        :param last_scanned: Date last scanned with grype (default: now)
        """
        components = jar_url.replace(MAVEN_CENTRAL_ROOT, "").split("/")
        jar_id = components[-1]
        # add jar
        super()._insert(Data.JAR, [
            ('jar_id', jar_id),
            ('uri', jar_url),
            ('group_id', ".".join(components[:-3])),
            ('artifact_id', components[-3]),
            ('version', components[-2]),
            ('publish_date', published_date),
            ('last_scanned', last_scanned)
        ], on_success_msg=f"added {jar_id} to database")
        # add cves
        for cve_id in cves:
            super()._insert(Data.CVE, [('cve_id', cve_id)], on_success_msg=f"Add new cve '{cve_id}'")
            super()._insert(Association.JAR__CVE, [('jar_id', jar_id), ('cve_id', cve_id)])

    def log_error(self, stage: Stage, message: str, uri: str = None) -> None:
        """
        Log an error in the database

        :param stage: Stage of pipeline the error occurred at
        :param message: Error message
        :param uri: URI of resource
        """
        inserts = [('stage', stage.value), ('message', message)]
        if uri:
            inserts.append(('uri', uri))
        super()._insert(Data.ERROR_LOG, inserts)
