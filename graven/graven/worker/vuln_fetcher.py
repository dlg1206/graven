import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from queue import Queue, Empty
from threading import Event
from typing import List

import requests
from bs4 import BeautifulSoup

from db.graven_database import GravenDatabase
from shared.logger import logger

"""
file: vuln_fetcher.py
Description: Pull CVE and CWE data from NVD and MITRE
Documentation: https://nvd.nist.gov/developers/vulnerabilities

Adapted from https://github.com/dlg1206/threat-actor-database/blob/v1.0.0/src/threat_actor_db/vuln_api/nvd.py
and https://github.com/dlg1206/threat-actor-database/blob/v1.0.0/src/threat_actor_db/mitre/search.py

@author Derek Garcia
"""
# prevent rate limiting
PUBLIC_RATE_LIMIT_SLEEP_SECONDS = 6
API_RATE_LIMIT_SLEEP_SECONDS = 0.6
NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MITRE_CWE_ROOT = "https://cwe.mitre.org/data/definitions"


@dataclass
class MITREResult:
    name: str
    description: str
    source: str


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


class VulnFetcherWorker:
    def __init__(self, stop_flag: Event, database: GravenDatabase, cve_queue: Queue[str | None]):
        """
        Create a new NVD and Mitre Worker

        'NVD_API_KEY' env variable is used if available

        :param stop_flag: Master event to exit if keyboard interrupt
        :param database: Database to save results to
        :param cve_queue: Queue of cves to process
        """
        self._stop_flag = stop_flag
        self._database = database
        self._cve_queue = cve_queue
        # determine sleep if key is available
        self._api_key_available = True if os.getenv('NVD_API_KEY') else False
        self._sleep = API_RATE_LIMIT_SLEEP_SECONDS if self._api_key_available else PUBLIC_RATE_LIMIT_SLEEP_SECONDS
        if self._api_key_available:
            logger.debug_msg("Using NVD API Key")
        else:
            logger.warn("Not using NVD API Key, this will affect query time")

        self._run_id = None

    def _fetch_cwe(self, cwe_id: str) -> MITREResult:
        """
        Parse CWE name, description, and website link from MITRE’s CWE site

        :param cwe_id: A string like "CWE-79", "CWE-89", etc.
        :return: A MITREResult object containing the CWE ID, name, description, and link
        """
        mitre_url = f"{MITRE_CWE_ROOT}/{cwe_id.split('-')[1]}.html"
        r = requests.get(mitre_url)
        r.raise_for_status()
        logger.debug_msg(f"Queried {mitre_url}")
        soup = BeautifulSoup(r.text, "html.parser")

        # 1) Find the CWE name (often in an <h2> tag)
        h2_tag = soup.find("h2")
        if h2_tag:
            cwe_name = h2_tag.get_text(strip=True).removeprefix(f"{cwe_id.upper()}: ")
        else:
            cwe_name = None

        # 2) Find the CWE description (look for a <div> with id="Description" or "Abstract")
        desc_div = soup.find("div", id="Description")
        if not desc_div:
            desc_div = soup.find("div", id="Abstract")

        if desc_div:
            cwe_description = desc_div.get_text(strip=True).removeprefix("Description")
        else:
            cwe_description = None

        return MITREResult(cwe_name, cwe_description, mitre_url)

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
        # first_time_wait_for_tasks("NVD", self._cve_queue, self._analyzer_done_flag)
        # todo - waiting logic

        while not self._stop_flag.is_set():
            try:
                cve_id = self._cve_queue.get(timeout=1)
                # break if poison pill - ie no more jobs
                if not cve_id:
                    break
                # if new id, fetch and save results
                nvd_result = self._fetch_cve(cve_id)
                self._database.upsert_cve(self._run_id, cve_id, cvss=nvd_result.cvss,
                                          publish_date=nvd_result.publish_date,
                                          description=nvd_result.description, source=nvd_result.source,
                                          last_queried=nvd_result.last_queried)
                logger.info(f"Added details for '{cve_id}'")
                # add cwes
                for cwe_id in nvd_result.cwes:
                    # add cwe details if new
                    if not self._database.has_seen_cwe(cwe_id):
                        mitre_result = self._fetch_cwe(cwe_id)
                        self._database.upsert_cwe(self._run_id, cwe_id, name=mitre_result.name,
                                                  description=mitre_result.description, source=mitre_result.source)
                        logger.info(f"Added details for '{cwe_id}'")
                    # associate cve to cwe
                    self._database.associate_cve_and_cwe(self._run_id, cve_id, cwe_id)

                self._cve_queue.task_done()  # mark task as done
            except Empty:
                """
                To prevent deadlocks, the forced timeout with throw this error 
                for another iteration of the loop to check conditions
                """
                continue

        # log exit type
        if self._stop_flag.is_set():
            logger.warn(f"Stop order received, exiting. . .")
        else:
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
