import os
from dataclasses import dataclass
from datetime import datetime
from threading import Semaphore
from typing import List

from logger import logger

"""
File: message.py

Description: Collection of standardized messages for queues

@author Derek Garcia
"""


@dataclass
class DownloadMessage:
    jar_url: str
    jar_publish_date: datetime


class GeneratorMessage:
    def __init__(self, url: str, publish_date: datetime, download_limit: Semaphore, working_dir_path: str):
        """
        Generator metadata object with details about the downloaded jar

        :param url: URL of the jar
        :param publish_date: Timestamp when the jar was added
        :param download_limit: Limit of the max number of downloads allowed at a time
        :param working_dir_path: Path to working directory to save jar to
        """
        self._url = url
        self._publish_date = publish_date
        self._download_limit = download_limit
        self._filename = self._url.split("/")[-1]
        self._working_dir_path = working_dir_path
        self._is_open = True

    def cleanup(self) -> None:
        """
        Deletes the jar and release the semaphore

        CALL THIS WHEN DONE OR THERE WILL BE CONSEQUENCES!!!
        """
        # don't attempt to close if not open
        if not self._is_open:
            return
        # delete files before release lock
        try:
            os.remove(self.get_file_path())
        except Exception as e:
            logger.error_exp(e)

        self._download_limit.release()
        self._is_open = False

    @property
    def url(self) -> str:
        """
        :return: URL of the jar
        """
        return self._url

    @property
    def publish_date(self) -> datetime:
        """
        :return: publish date of jar
        """
        return self._publish_date

    @property
    def working_dir_path(self) -> str:
        """
        :return: The working directory path
        """
        return self._working_dir_path

    def get_file_path(self) -> str:
        """
        :return: The file path to the downloaded jar
        """
        return f"{self._working_dir_path}{os.sep}{self._filename}"

    def get_syft_file_path(self) -> str:
        """
        :return: The file path to the syft sbom
        """
        return f"{self.get_file_path()}.syft.json"


class AnalysisMessage:
    def __init__(self, url: str, publish_date: datetime, syft_sbom_path: str, working_dir_path: str):
        """
        Task metadata object with details about the downloaded jar

        :param url: URL of the jar
        :param publish_date: Timestamp when the jar was added
        :param syft_sbom_path: Path to the syft SBOM to scan
        :param working_dir_path: Path to working directory to save jar to
        """
        self._url = url
        self._publish_date = publish_date
        self._syft_sbom_path = syft_sbom_path
        self._working_dir_path = working_dir_path
        self._is_open = True

    def cleanup(self) -> None:
        """
        Deletes the files

        CALL THIS WHEN DONE OR THERE WILL BE CONSEQUENCES!!!
        """
        # don't attempt to close if not open
        if not self._is_open:
            return
        # delete files before release lock
        try:
            os.remove(self.syft_sbom_path)
        except Exception as e:
            logger.error_exp(e)
        try:
            os.remove(self.get_grype_file_path())
        except Exception as e:
            logger.error_exp(e)
        self._is_open = False

    @property
    def url(self) -> str:
        """
        :return: URL of the jar
        """
        return self._url

    @property
    def publish_date(self) -> datetime:
        """
        :return: publish date of jar
        """
        return self._publish_date

    @property
    def syft_sbom_path(self) -> str:
        """
        :return: The file path to the generated SBOM
        """
        return self._syft_sbom_path

    def get_grype_file_path(self) -> str:
        """
        :return: The file path to the grype report
        """
        return f"{self.syft_sbom_path}.grype.json"


@dataclass
class ScribeMessage:
    url: str
    publish_date: datetime
    cve_ids: List[str]
    last_scanned: datetime
