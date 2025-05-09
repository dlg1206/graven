import os
import time
from abc import ABC
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event
from typing import List, Literal, Any

import requests
from bs4 import BeautifulSoup
from requests import RequestException

from db.graven_database import GravenDatabase, Stage
from shared.logger import logger
from worker.worker import Worker

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
# endpoints
NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_CWE_ROOT = "https://cwe.mitre.org/data/definitions"

RETRY_SLEEP = 10


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


class VulnFetcherWorker(Worker, ABC):
    def __init__(self, master_terminate_flag: Event, database: GravenDatabase):
        """
        Create a new NVD and Mitre Worker

        'NVD_API_KEY' env variable is used if available

        :param master_terminate_flag: Master event to exit if keyboard interrupt
        :param database: Database to save results to
        """
        super().__init__(master_terminate_flag, database, "vuln_fetcher")
        self._analyzer_done_flag = None
        self._analyzer_first_hit_flag = None
        # determine sleep if key is available
        self._api_key_available = True if os.getenv('NVD_API_KEY') else False
        self._sleep = API_RATE_LIMIT_SLEEP_SECONDS if self._api_key_available else PUBLIC_RATE_LIMIT_SLEEP_SECONDS
        if self._api_key_available:
            logger.debug_msg("Using NVD API Key")
        else:
            logger.warn("Not using NVD API Key, this will affect query time")
        # set at runtime
        self._run_id = None

    def _fetch_cve(self, cve_id: str) -> NVDResult:
        """
        Get CVE data from NVD

        :param cve_id: CVE to get cwes for
        :raises RequestException: If the request fails
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

    def _handle_message(self, message: str) -> None:
        """
        Handle a message from the queue and return the future submitted to the executor

        :param message: The message to handle
        :return: The Future task or None if now task made
        """
        cve_id = message
        try:
            nvd_result = self._fetch_cve(cve_id)
            self._database.upsert_cve(self._run_id, cve_id,
                                      cvss=nvd_result.cvss,
                                      publish_date=nvd_result.publish_date,
                                      description=nvd_result.description,
                                      source=nvd_result.source,
                                      last_queried=nvd_result.last_queried,
                                      status_code=0)
            logger.info(f"Added details for '{cve_id}'")
            # add cwes
            for cwe_id in nvd_result.cwes:
                # add cwe details if new
                if not self._database.has_seen_cwe(cwe_id):
                    try:
                        mitre_result = _fetch_cwe(cwe_id)
                        self._database.upsert_cwe(self._run_id, cwe_id,
                                                  name=mitre_result.name,
                                                  description=mitre_result.description,
                                                  source=mitre_result.source,
                                                  last_queried=datetime.now(timezone.utc),
                                                  status_code=0)
                        logger.info(f"Added details for '{cwe_id}'")
                    except (RequestException, Exception) as e:
                        # handle failed to get cwe
                        details = {'cwe_id': cwe_id}
                        if hasattr(e, 'response'):
                            details.update({'status_code': e.response.status_code})
                        self._database.log_error(self._run_id, Stage.VULN, e, details=details)
                        self._database.upsert_cwe(self._run_id, cwe_id,
                                                  last_queried=datetime.now(timezone.utc), status_code=1)
                # associate cve to cwe
                self._database.associate_cve_and_cwe(self._run_id, cve_id, cwe_id)

        except (RequestException, CVENotFoundError, Exception) as e:
            # handle failed to get cve
            logger.error_exp(e)
            details = None
            if isinstance(e, RequestException):
                details = {'status_code': e.response.status_code} if hasattr(e, 'response') else None
            if isinstance(e, CVENotFoundError):
                details = {'cve_id': e.cve_id}
            self._database.log_error(self._run_id, Stage.VULN, e, details=details)
            self._database.upsert_cve(self._run_id, cve_id, last_queried=datetime.now(timezone.utc), status_code=1)

    def _handle_none_message(self) -> Literal['continue', 'break']:
        """
        Handle when get none message
        """
        # not using the analyzer or are using and done flag is set - means no more cves will be added
        if not self._analyzer_done_flag or self._analyzer_done_flag.is_set():
            return 'break'
        # else using the analyzer and cves still coming
        logger.warn(
            f"Found no CVEs to download but analyzer is still running, sleeping for {RETRY_SLEEP}s. . .")
        time.sleep(RETRY_SLEEP)
        return 'continue'

    def _poll_consumer_queue(self) -> str | None:
        """
        Get a message from the database
        """
        return self._database.get_cve_for_update()

    def _pre_start(self, **kwargs: Any) -> None:
        """
        Set the working directory to download jars to

        :param root_dir: Temp root directory working in
        """
        # if using the analyzer, wait until find a hit
        # todo - option to skip wait
        if self._analyzer_first_hit_flag:
            logger.info("Waiting for CVE to query. . .")
            self._analyzer_first_hit_flag.wait()
            logger.info("CVE found, starting. . .")

    def print_statistics_message(self) -> None:
        """
        Print worker specific statistic messages
        """
        pass

    def set_analyzer_first_hit_flag(self, flag: Event) -> None:
        """
        Set the first hit flag

        :param: Flag to indicate that the analyzer added a CVE if using analyzer
        """
        self._analyzer_first_hit_flag = flag

    def set_analyzer_done_flag(self, flag: Event) -> None:
        """
        Set the done flag

        :param: Flag to indicate that the analyzer is finished if using analyzer
        """
        self._analyzer_done_flag = flag


def _fetch_cwe(cwe_id: str) -> MITREResult:
    """
    Parse CWE name, description, and website link from MITRE’s CWE site

    :param cwe_id: A string like "CWE-79", "CWE-89", etc.
    :raises RequestException: If fail to get CWE page
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
