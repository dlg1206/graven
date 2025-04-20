import json
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any

from mysql.connector import ProgrammingError, DatabaseError

from db.database import MySQLDatabase, Table, JoinTable
from shared.logger import logger

"""
File: cve_breadcrumbs_database.py

Description: MySQL database interface for CVE-Breadcrumbs database

@author Derek Garcia
"""

DEFAULT_POOL_SIZE = 32

MAVEN_CENTRAL_ROOT = "https://repo1.maven.org/maven2/"


class Stage(Enum):
    """
    Stage enums - max is 5 chars
    """
    CRAWLER = "CRAWL"
    DOWNLOADER = "DWNLD"
    GENERATOR = "GENER"
    SCANNER = "SCANR"
    ANALYZER = "ALYZR"
    NVD = "NVDAP"


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
        return len(self._select(Table.DOMAIN, where_equals=[('url', url)])) != 0

    def has_seen_jar_url(self, url: str) -> bool:
        """
        Check if the database has seen these jars before

        :param url: URL to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Table.JAR, where_equals=[('uri', url.removeprefix(MAVEN_CENTRAL_ROOT))])) != 0

    def has_seen_cve(self, cve_id: str) -> bool:
        """
        Check if the database has seen these cves before

        :param cve_id: CVE id to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Table.CVE, where_equals=[('cve_id', cve_id)])) != 0

    def has_seen_cwe(self, cwe_id: str) -> bool:
        """
        Check if the database has seen these cwes before

        :param cwe_id: CWE id to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Table.CWE, where_equals=[('cwe_id', cwe_id)])) != 0

    def has_seen_purl(self, purl: str) -> bool:
        """
        Check if the database has seen these purls before

        :param purl: purl to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Table.ARTIFACT, where_equals=[('purl', purl)])) != 0

    def save_domain_url_as_seen(self, run_id: int, url: str, last_crawled: datetime) -> None:
        """
        Save that this domain has been crawled

        :param run_id: ID of the jar and scan was done in
        :param url: URL of root domain fully crawled
        :param last_crawled: Timestamp of when last crawled domain (Default: now)
        """
        self._upsert(Table.DOMAIN, [('url', url)], [('run_id', run_id), ('last_crawled', last_crawled)])

    def upsert_artifact(self, run_id: int, purl: str, **kwargs: str | int) -> None:
        """
        Upsert a syft artifact to the database

        :param run_id: Run id this was found in
        :param purl: purl of artifact to update
        :param kwargs: table key value pairs to update the database with
        """
        self._upsert(Table.ARTIFACT, [('purl', purl)], [('run_id', run_id)] + list(kwargs.items()))

    def upsert_cve(self, run_id: int, cve_id: str, **kwargs: str | int | float | datetime) -> None:
        """
        Upsert cve to the database

        :param run_id: Run id this was found in
        :param cve_id: CVE id to update
        :param kwargs: table key value pairs to update the database with
        """
        self._upsert(Table.CVE, [('cve_id', cve_id)], [('run_id', run_id)] + list(kwargs.items()))

    def upsert_cwe(self, run_id: int, cwe_id: str, **kwargs: str) -> None:
        """
        Upsert cwe to the database

        :param run_id: Run id this was found in
        :param cwe_id: CWE id to update
        :param kwargs: table key value pairs to update the database with
        """
        self._upsert(Table.CWE, [('cwe_id', cwe_id)], [('run_id', run_id)] + list(kwargs.items()))

    def upsert_jar(self, run_id: int, jar_url: str, published_date: datetime) -> None:
        """
        Add a jar to the database and any associated CVEs

        :param run_id: ID of the jar and scan was done in
        :param jar_url: URL of jar
        :param published_date: Date when the jar was published
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
            ('publish_date', published_date)
        ]
        self._upsert(Table.JAR, [('jar_id', jar_id)], inserts)

    def upsert_jar_last_scan(self, run_id: int, jar_id: str, last_scanned: datetime) -> None:
        """
        Update when the last time the jar's SBOM was scanned with grype

        :param run_id: Run id this was done
        :param jar_id: id of the jar being scanned
        :param last_scanned: timestamp string of the last scan
        """
        self._upsert(Table.JAR, [('jar_id', jar_id)], [('run_id', run_id), ('last_scanned', last_scanned)])

    def upsert_sbom_blob(self, run_id: int, jar_id: str, sbom_blob: bytes) -> None:
        """
        Upsert a zstandard compressed syft json sbom to the database

        :param run_id: Run id this was done
        :param jar_id: id of the jar sbom belongs to
        :param sbom_blob: compressed binary
        """
        self._upsert(Table.SBOM, [('jar_id', jar_id)], [('run_id', run_id), ('sbom', sbom_blob)])

    def associate_cve_and_cwe(self, cve_id: str, cwe_id: str) -> None:
        """
        Save a cve and cwe that impacts it
        CVE must exist in db prior, but CWE is updated if dne

        :param cve_id: id of cve
        :param cwe_id: id of cwe
        """
        self._insert(Table.CWE, [('cwe_id', cwe_id)])
        self._insert(JoinTable.CVE__CWE, [('cve_id', cve_id), ('cwe_id', cwe_id)])

    def associate_jar_and_cve(self, run_id: int, jar_id: str, cve_id: str) -> None:
        """
        Save a jar and cve that impacts it
        Jar and CVE must exist in db prior

        :param run_id: ID of the jar and scan was done in
        :param jar_id: id of jar
        :param cve_id: id of cve
        """
        self._upsert(JoinTable.JAR__CVE, [('jar_id', jar_id), ('cve_id', cve_id)], [('run_id', run_id)])

    def associate_sbom_and_artifact(self, run_id: int, jar_id: str, purl: str, has_pom: bool) -> None:
        """
        Save an sbom and artifact that it contains
        Jar / SBOM and purl must exist in db prior

        :param run_id: ID of the jar and scan was done in
        :param jar_id: id of jar the sbom is of
        :param purl: purl of the artifact
        :param has_pom: whether or not the artifact contains a pom file
        """
        self._upsert(JoinTable.SBOM__ARTIFACT, [('jar_id', jar_id), ('purl', purl)],
                     [('run_id', run_id), ('has_pom', 1 if has_pom else 0)])

    def log_run_start(self, syft_version: str, grype_version: str, grype_db_source: str) -> int:
        """
        Log a start of a run

        :param syft_version: Version of syft used
        :param grype_version: Version of grype used
        :param grype_db_source: URL source of grype used
        :return: run id
        """
        run_id = self._insert(Table.RUN_LOG, [
            ('syft_version', syft_version),
            ('grype_version', grype_version),
            ('grype_db_source', grype_db_source)])
        return run_id

    def log_run_end(self, run_id: int, exit_code: int) -> None:
        """
        log the end of a run

        :param run_id: ID of run to end
        :param exit_code: run exit code
        """
        self._update(Table.RUN_LOG, [('end', datetime.now(timezone.utc)), ('exit_code', exit_code)],
                     [('run_id', run_id)])

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
        self._insert(Table.ERROR_LOG, inserts)
