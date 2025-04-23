import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from queue import Queue, Empty
from threading import Event
from typing import List

import requests

from db.cve_breadcrumbs_database import BreadcrumbsDatabase, Stage
from shared.logger import logger
from shared.utils import first_time_wait_for_tasks

"""
file: nvd.py
Description: Pull CVE data from NVD
Documentation: https://nvd.nist.gov/developers/vulnerabilities

Adapted from https://github.com/dlg1206/threat-actor-database/blob/main/src/threat_actor_db/vuln_api/nvd.py

@author Derek Garcia
"""
# prevent rate limiting
PUBLIC_RATE_LIMIT_SLEEP_SECONDS = 6
API_RATE_LIMIT_SLEEP_SECONDS = 0.6
NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class NVDResult:
    cvss: float
    publish_date: str
    description: str
    source: str
    last_queried: datetime
    cwes: List[str]

    def __post_init__(self):
        self.description = self.description.strip()


class CVENotFoundError(IOError):
    def __init__(self, cve_id: str, nvd_url: str):
        """
        CVE is not found in NVD

        :param cve_id: Missing CVE
        :param nvd_url: URL attempt to access for CVE
        """
        self.cve_id = cve_id
        self.nvd_url = nvd_url
        super().__init__(f"CVE '{cve_id}' does not exist: {nvd_url}")


class NVDWorker:
    def __init__(self, database: BreadcrumbsDatabase, cve_queue: Queue[str], analyzer_done_flag: Event):
        """
        Create a new NVD Worker

        'NVD_API_KEY' env variable is used if available
        :param database: Database to save results to
        :param cve_queue: Queue of cves to process
        :param analyzer_done_flag: Flag to indicate the analyzer has finished running

        """
        self._database = database
        self._cve_queue = cve_queue
        self._analyzer_done_flag = analyzer_done_flag
        # determine sleep if key is available
        self._api_key_available = True if os.getenv('NVD_API_KEY') else False
        self._sleep = API_RATE_LIMIT_SLEEP_SECONDS if self._api_key_available else PUBLIC_RATE_LIMIT_SLEEP_SECONDS
        if self._api_key_available:
            logger.debug_msg("Using NVD API Key")
        else:
            logger.warn("Not using NVD API Key, this will affect query time")

        self._run_id = None

    def _fetch_cve(self, cve_id: str) -> NVDResult:
        """
        Get CVE data from NVD

        :param cve_id: CVE to get cwes for
        :raises HTTPError: If the request fails
        :raises CVENotFoundError: If request success, but returns no CVE matches
        :return: NVD Result of cve data
        """

        nvd_url = f"{NVD_CVE_ENDPOINT}?cveId={cve_id}"
        # ensure sleep before next attempt
        logger.debug_msg(f"{cve_id} | Sleeping for {self._sleep} seconds")
        time.sleep(self._sleep)
        # use key if available
        if self._api_key_available:
            r = requests.get(nvd_url, headers={"apiKey": os.environ["NVD_API_KEY"]})
        else:
            r = requests.get(nvd_url)
        r.raise_for_status()  # check if ok
        logger.info(f"Queried {nvd_url}")
        # ensure CVE exists
        if not r.json()['vulnerabilities']:
            raise CVENotFoundError(cve_id, nvd_url)
        cve = r.json()['vulnerabilities'][0]['cve']
        # get cvss 3.1 if available
        cvss_score = None
        cvss_31_metrics = cve.get('metrics', {}).get('cvssMetricV31')
        if cvss_31_metrics:
            cvss_score = float(cvss_31_metrics[0]['cvssData']['baseScore'])
        # get additional CVE details
        description = [dsc['value'] for dsc in cve['descriptions'] if dsc['lang'] == 'en'][0]
        cwe_ids = [cwe['description'][0]['value'] for cwe in cve['weaknesses'] if
                   cwe['description'][0]['value'].startswith('CWE')]

        # return results
        return NVDResult(cvss_score, cve['published'], description, nvd_url, datetime.now(timezone.utc), cwe_ids)

    def _query_nvd(self) -> None:
        """
        Retrieve CVE data from NVD as new CVEs are discovered
        """
        # block until items to process
        first_time_wait_for_tasks("NVD", self._cve_queue, self._analyzer_done_flag)

        # run while the analyzer is still running or still tasks to process
        result = None
        while True:
            try:
                cve_id = self._cve_queue.get(timeout=1)
                print(list(self._cve_queue.queue))
                # if new id, fetch and save results
                result = self._fetch_cve(cve_id)
                self._database.upsert_cve(self._run_id, cve_id, cvss=result.cvss, publish_date=result.publish_date,
                                          description=result.description, source=result.source,
                                          last_queried=result.last_queried)
                # add cwes
                for cwe_id in result.cwes:
                    self._database.associate_cve_and_cwe(cve_id, cwe_id)
                self._cve_queue.task_done()  # mark task as done
            except Empty:
                """
                To prevent deadlocks, the forced timeout with throw this error 
                for another iteration of the loop to check conditions
                """
                # break if nothing new and nothing left
                if self._analyzer_done_flag.is_set() and self._cve_queue.empty():
                    break
            except Exception as e:
                logger.error_exp(e)
                url = None
                if result:
                    url = result.source

                self._database.log_error(self._run_id, Stage.NVD, url, e, "Failed during loop")
                self._cve_queue.task_done()  # ensure task is marked even if failed to prevent deadlock

        logger.warn(f"No more CVEs to query for. . .")

    def start(self, run_id: int) -> None:
        """
        Spawn and start the NVD worker thread

        :param run_id: ID of run
        """
        self._run_id = run_id
        logger.info(f"Initializing NVD API . .")
        # start the scanner
        logger.info(f"Starting NVD API")
        self._query_nvd()
        # done
