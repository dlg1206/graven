"""
File: cve_breadcrumbs_database.py

Description: MySQL database interface for CVE-Breadcrumbs database

@author Derek Garcia
"""
from enum import Enum

from db.database import MySQLDatabase
from db.tables import Data

DEFAULT_POOL_SIZE = 10


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
        Create a new interface to the database

        :param pool_size: Size of the database pool (max is 32)
        """
        super().__init__(pool_size)

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
