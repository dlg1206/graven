"""
File: analysis_task.py

Description: Metadata for a jar file to be scanned

@author Derek Garcia
"""
import os
import threading
from datetime import datetime

from log.logger import logger


class AnalysisTask:
    def __init__(self, url: str, publish_date: str, download_limit: threading.Semaphore, working_dir_path: str):
        """
        Task metadata object with details about the downloaded jar

        :param url: URL of the jar
        :param publish_date: Timestamp when the jar was added
        :param download_limit: Limit of the max number of downloads allowed at a time
        :param working_dir_path: Path to working directory to save jar to
        """
        self._url = url
        self._publish_date = datetime.strptime(publish_date, "%Y-%m-%d %H:%M")
        self._download_limit = download_limit
        self._filename = self._url.split("/")[-1]
        self._working_dir_path = working_dir_path

    def cleanup(self) -> None:
        """
        Deletes the files and release the semaphore

        CALL THIS WHEN DONE OR THERE WILL BE CONSEQUENCES!!!
        """
        try:
            os.remove(self.get_file_path())
        except Exception as e:
            logger.error(e)
        try:
            os.remove(self.get_grype_file_path())
        except Exception as e:
            logger.error(e)
        self._download_limit.release()

    def get_url(self) -> str:
        """
        :return: URL of the jar
        """
        return self._url

    def get_publish_date(self) -> datetime:
        """
        :return: publish date of jar
        """
        return self._publish_date

    def get_filename(self) -> str:
        """
        :return: Name of file
        """
        return self._filename

    def get_file_path(self) -> str:
        """
        :return: The file path to the downloaded jar
        """
        return f"{self._working_dir_path}{os.sep}{self._filename}"

    def get_grype_file_path(self) -> str:
        """
        :return: The file path to the grype report
        """
        return f"{self.get_file_path()}.json"
