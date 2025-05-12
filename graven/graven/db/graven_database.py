import io
import json
import os
import tarfile
import zipfile
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Literal

import zstandard as zstd
from sqlalchemy import text

from db.database import MySQLDatabase, TableEnum, DEFAULT_POOL_SIZE
from qmodel.message import Message
from shared.logger import logger

"""
File: graven_database.py

Description: MySQL database interface for CVE-Breadcrumbs database

@author Derek Garcia
"""

MAVEN_CENTRAL_ROOT = "https://repo1.maven.org/maven2/"


class Table(TableEnum):
    """
    Tables that hold data
    """
    CVE = "cve"
    CWE = "cwe"
    JAR = "jar"
    SBOM = "sbom"
    ARTIFACT = "artifact"
    DOMAIN = "domain"
    ERROR_LOG = "error_log"
    RUN_LOG = "run_log"


class JoinTable(TableEnum):
    """
    Tables that associate data
    """
    CVE__CWE = "cve__cwe"
    JAR__CVE = "jar__cve"
    SBOM__ARTIFACT = "sbom__artifact"


class CrawlStatus(Enum):
    DOES_NOT_EXIST = "DOES_NOT_EXIST"
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"


class FinalStatus(Enum):
    DONE = "DONE"
    ERROR = "ERROR"


class Stage(Enum):
    """
    Stage enums
    """
    CRAWLER = "CRAWL"
    TRN_DB_DWN = "TRN_DATABASE_DOWNLOAD"
    DOWNLOADER = "DOWNLOAD"
    TRN_DWN_ANCHORE = "TRN_DOWNLOAD_ANCHORE"
    GENERATOR = "GENERATOR"
    TRN_GEN_SCN = "TRN_GENERATOR_SCANNER"
    SCANNER = "SCANNER"
    TRN_SCN_ANL = "TRN_SCANNER_ANALYZER"
    ANALYZER = "ANALYZER"
    VULN = "VULN"


class GravenDatabase(MySQLDatabase):
    def __init__(self, pool_size: int = DEFAULT_POOL_SIZE):
        """
        Create a new interface connection to the database

        :param pool_size: Size of the database pool (max is 32)
        """
        # try:
        super().__init__(pool_size)
        # except Exception as e:
        #     logger.fatal(e)
        logger.info("Connected to the database")

    def has_seen_jar_url(self, url: str) -> bool:
        """
        Check if the database has seen these jars before

        :param url: URL to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Table.JAR,
                                where_equals={'uri': url.removeprefix(MAVEN_CENTRAL_ROOT)},
                                fetch_all=False)) != 0

    def has_seen_cve(self, cve_id: str) -> bool:
        """
        Check if the database has seen these cves before
        todo - check for errors
        :param cve_id: CVE id to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Table.CVE, where_equals={'cve_id': cve_id}, fetch_all=False)) != 0

    def has_seen_cwe(self, cwe_id: str) -> bool:
        """
        Check if the database has seen these cwes before

        todo - check for errors
        :param cwe_id: CWE id to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Table.CWE, where_equals={'cwe_id': cwe_id}, fetch_all=False)) != 0

    def get_cve_for_update(self) -> str | None:
        """
        Get a CVE to update
        todo - check for errors

        :return: CVE ID to query, None if none available
        """
        row = self._select(Table.CVE, columns=['cve_id'], where_equals={'status_code': None}, fetch_all=False)
        if not len(row):
            return None
        cve_id = row[0][0]
        self._upsert(Table.CVE, {'cve_id': cve_id}, {'status_code': 2})  # mark as in progress
        return cve_id

    def has_seen_purl(self, purl: str) -> bool:
        """
        Check if the database has seen these purls before

        :param purl: purl to check
        :return: True if seen, false otherwise
        """
        return len(self._select(Table.ARTIFACT, where_equals={'purl': purl}, fetch_all=False)) != 0

    def shelf_message(self, jar_id: str) -> None:
        """
        Deque message for later analysis

        :param jar_id: id of the jar being shelled
        """
        self._update(Table.JAR, {'status': None}, where_equals={'jar_id': jar_id})

    def get_message_for_update(self) -> Message | None:
        """
        Get a jar that has not been process and lock for update

        # todo - option to get completed or failed jars
        """

        with self._engine.begin() as conn:
            # get jar to process
            result = conn.execute(text("SELECT uri, jar_id FROM jar WHERE status IS NULL LIMIT 1;")).fetchone()
            # return none if no jobs
            if not result:
                return None
            # else mark in progress
            conn.execute(
                text("UPDATE jar SET status = :status WHERE jar_id = :jar_id"),
                {"status": Stage.TRN_DB_DWN.value, "jar_id": result.jar_id}
            )
        return Message(f"{MAVEN_CENTRAL_ROOT}{result[0]}", result[1])

    def get_domain_status(self, domain_url: str) -> CrawlStatus:
        """
        Check if the database has seen these domains before

        :param domain_url: URL to check
        :return: Crawler status
        """
        domains = self._select(Table.DOMAIN, ['crawl_start', 'crawl_end'], where_equals={'url': domain_url})
        # domain has never been explored
        if len(domains) == 0:
            return CrawlStatus.DOES_NOT_EXIST
        domain = domains[0]
        # if started and ended - then done
        if domain[0] and domain[1]:
            return CrawlStatus.COMPLETED
        # elif started and not ended - then in progress
        elif domain[0] and not domain[1]:
            return CrawlStatus.IN_PROGRESS
        # not started and not ended - must be not started
        else:
            return CrawlStatus.NOT_STARTED

    def init_domain(self, run_id: int, domain_url: str) -> None:
        """
        Record that this domain has been initialized, but not started

        :param run_id: ID of the jar and scan was done in
        :param domain_url: URL of root domain starting to crawl
        """
        self._upsert(Table.DOMAIN, {'url': domain_url}, {'run_id': run_id})

    def start_domain(self, domain_url: str, crawl_start: datetime) -> None:
        """
        Record that this domain has started the crawl

        :param domain_url: URL of root domain starting to crawl
        :param crawl_start: Timestamp of when crawl started
        """
        # reset end time
        self._upsert(Table.DOMAIN, {'url': domain_url}, {'crawl_start': crawl_start, 'crawl_end': None})

    def complete_domain(self, run_id: int, domain_url: str, crawl_end: datetime) -> None:
        """
        Save that this domain has been crawled

        :param run_id: ID of run crawl was started in
        :param domain_url: URL of root domain fully crawled
        :param crawl_end: Timestamp of when crawl ended
        """
        self._upsert(Table.DOMAIN, {'url': domain_url, 'run_id': run_id}, {'crawl_end': crawl_end})

    def update_jar_status(self, jar_id: str, status: Stage | FinalStatus | None) -> None:
        updates = {'status': status.value if status else None}
        # add process status if done
        if status == FinalStatus.DONE:
            updates['last_processed'] = datetime.now(timezone.utc)
        # update db
        self._upsert(Table.JAR, {'jar_id': jar_id}, updates)

    def upsert_artifact(self, run_id: int, purl: str, **kwargs: str | int) -> None:
        """
        Upsert a syft artifact to the database

        :param run_id: Run id this was found in
        :param purl: purl of artifact to update
        :param kwargs: table key value pairs to update the database with
        """
        self._upsert(Table.ARTIFACT, {'purl': purl}, {'run_id': run_id, **kwargs})

    def upsert_cve(self, run_id: int, cve_id: str, **kwargs: str | int | float | datetime) -> None:
        """
        Upsert cve to the database

        :param run_id: Run id this was found in
        :param cve_id: CVE id to update
        :param kwargs: table key value pairs to update the database with
        """
        self._upsert(Table.CVE, {'cve_id': cve_id}, {'run_id': run_id, **kwargs})

    def upsert_cwe(self, run_id: int, cwe_id: str, **kwargs: Any) -> None:
        """
        Upsert cwe to the database

        :param run_id: Run id this was found in
        :param cwe_id: CWE id to update
        :param kwargs: table key value pairs to update the database with
        """
        self._upsert(Table.CWE, {'cwe_id': cwe_id}, {'run_id': run_id, **kwargs})

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
        inserts = {
            'run_id': run_id,
            'uri': jar_url.replace(MAVEN_CENTRAL_ROOT, ""),
            'group_id': ".".join(components[:-3]),
            'artifact_id': components[-3],
            'version': components[-2],
            'publish_date': published_date
        }
        self._upsert(Table.JAR, {'jar_id': jar_id}, inserts)

    def upsert_jar_last_grype_scan(self, run_id: int, jar_id: str, last_grype_scan: datetime) -> None:
        """
        Update when the last time the jar's SBOM was scanned with grype

        :param run_id: Run id this was done
        :param jar_id: id of the jar being scanned
        :param last_grype_scan: timestamp string of the last scan
        """
        self._upsert(Table.JAR, {'jar_id': jar_id}, {'run_id': run_id, 'last_grype_scan': last_grype_scan})

    def upsert_sbom_blob(self, run_id: int, jar_id: str, sbom_blob: bytes) -> None:
        """
        Upsert a zstandard compressed syft json sbom to the database

        :param run_id: Run id this was done
        :param jar_id: id of the jar sbom belongs to
        :param sbom_blob: compressed binary
        """
        self._upsert(Table.SBOM, {'jar_id': jar_id}, {'run_id': run_id, 'sbom': sbom_blob})

    def associate_cve_and_cwe(self, run_id: int, cve_id: str, cwe_id: str) -> None:
        """
        Save a cve and cwe that impacts it
        CVE must exist in db prior, but CWE is updated if dne

        :param run_id: Run id this was done
        :param cve_id: id of cve
        :param cwe_id: id of cwe
        """
        self._insert(Table.CWE, {'cwe_id': cwe_id})
        self._insert(JoinTable.CVE__CWE, {'run_id': run_id, 'cve_id': cve_id, 'cwe_id': cwe_id})

    def associate_jar_and_cve(self, run_id: int, jar_id: str, cve_id: str) -> None:
        """
        Save a jar and cve that impacts it
        Jar and CVE must exist in db prior

        :param run_id: ID of the jar and scan was done in
        :param jar_id: id of jar
        :param cve_id: id of cve
        """
        self._upsert(JoinTable.JAR__CVE, {'jar_id': jar_id, 'cve_id': cve_id}, {'run_id': run_id})

    def associate_sbom_and_artifact(self, run_id: int, jar_id: str, purl: str, has_pom: bool) -> None:
        """
        Save an sbom and artifact that it contains
        Jar / SBOM and purl must exist in db prior

        :param run_id: ID of the jar and scan was done in
        :param jar_id: id of jar the sbom is of
        :param purl: purl of the artifact
        :param has_pom: whether or not the artifact contains a pom file
        """
        self._upsert(JoinTable.SBOM__ARTIFACT,
                     {'jar_id': jar_id, 'purl': purl},
                     {'run_id': run_id, 'has_pom': 1 if has_pom else 0})

    def log_run_start(self, syft_version: str, grype_version: str, grype_db_source: str) -> int:
        """
        Log a start of a run

        :param syft_version: Version of syft used
        :param grype_version: Version of grype used
        :param grype_db_source: URL source of grype used
        :return: run id
        """
        run_id = self._insert(Table.RUN_LOG, {
            'syft_version': syft_version,
            'grype_version': grype_version,
            'grype_db_source': grype_db_source})
        return run_id

    def log_run_end(self, run_id: int, exit_code: int) -> None:
        """
        log the end of a run

        :param run_id: ID of run to end
        :param exit_code: run exit code
        """
        self._update(Table.RUN_LOG,
                     {'end': datetime.now(timezone.utc), 'exit_code': exit_code},
                     {'run_id': run_id})

    def log_error(self, run_id: int, stage: Stage, error: Exception, jar_id: str = None,
                  details: Dict[Any, Any] = None) -> None:
        """
        Log an error in the database

        :param run_id: ID of the jar and scan was done in
        :param stage: Stage of pipeline the error occurred at
        :param error: Error that occurred
        :param jar_id: Jar ID if available
        :param details: Optional JSON data to include to help debug error
        """
        inserts = {
            'timestamp': datetime.now(timezone.utc),
            'run_id': run_id,
            'stage': stage.value,
            'error_type': type(error).__name__,
            'error_message': str(error)
        }
        if jar_id:
            inserts.update({'jar_id': jar_id})
        if details:
            inserts.update({'details': json.dumps(details)})
        self._insert(Table.ERROR_LOG, inserts)

    def export_sboms(self, export_directory: str, compression_method: Literal['zip', 'tar.gz']) -> None:
        """
        Export SBOMs stored in database to file

        :param export_directory: Path to directory to save SBOMs to
        :param compression_method: Method to bundle SBOMs for export (zip or tar.gz)
        """
        os.makedirs(export_directory, exist_ok=True)
        dctx = zstd.ZstdDecompressor()
        sboms = self._select(Table.SBOM, ['jar_id', 'sbom'])
        out_file_path = f"{export_directory}{os.sep}graven_sbom_dump.{compression_method}"
        # determine write type based on extension
        if compression_method == 'zip':
            open_method = zipfile.ZipFile(out_file_path, 'w', compression=zipfile.ZIP_DEFLATED)
        else:
            open_method = tarfile.open(out_file_path, 'w:gz')
        # decompress and write to file
        with open_method as export:
            for jar_id, sbom_bytes in logger.get_data_queue(sboms, "Exporting SBOMs", "SBOM"):
                try:
                    # decompress
                    decompressed = dctx.decompress(sbom_bytes)
                    sbom_json = json.loads(decompressed)

                    # format JSON and prepare in-memory file
                    json_bytes = json.dumps(sbom_json, indent=2).encode('utf-8')  # todo - add conversion support?
                    json_io = io.BytesIO(json_bytes)

                    if compression_method == 'zip':
                        export.writestr(f"{jar_id}.json", json_bytes)
                    else:
                        # create tar entry
                        tarinfo = tarfile.TarInfo(name=f"{jar_id}.json")
                        tarinfo.size = len(json_bytes)
                        export.addfile(tarinfo, fileobj=json_io)
                    logger.debug_msg(f"Exported {jar_id}")
                except Exception as e:
                    logger.error_exp(e, f"Failed to export SBOM for {jar_id}")
