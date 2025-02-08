"""
File: analysis_task.py

Description: Metadata for a jar file to be scanned

@author Derek Garcia
"""
import os
from asyncio import Semaphore
from datetime import datetime
from tempfile import TemporaryDirectory

from aiohttp import ClientResponse


class AnalysisTask:
    def __init__(self, url: str, publish_date: str, download_limit: Semaphore):
        """
        Task metadata object with details about the downloaded jar

        :param url: URL of the jar
        :param publish_date: Timestamp when the jar was added
        :param download_limit: Limit of the max number of downloads allowed at a time
        """
        self._url = url
        self._publish_date = datetime.strptime(publish_date, "%Y-%m-%d %H:%M")
        self._download_limit = download_limit
        self._filename = None
        self._tmp_dir = TemporaryDirectory()

    def __enter__(self):
        """
        Context manager for the task
        :return: AnalysisTask
        """
        return self

    def __exit__(self):
        """
        Delete the temporary directory and release the semaphore
        """
        self.close()

    def get_publish_date(self) -> datetime:
        """
        :return: publish date of jar
        """
        return self._publish_date

    def get_url(self) -> str:
        """
        :return: URL of the jar
        """
        return self._url

    def get_file_path(self) -> str:
        """
        :return: The file path to the downloaded jar
        """
        return f"{self._tmp_dir.name}{os.sep}{self._filename}"
        # return self._filename

    def get_working_directory(self) -> str:
        """
        :return: The file path to the temp directory
        """
        return self._tmp_dir.name

    def close(self) -> None:
        """
        Deletes the temporary directory and release the semaphore
        """
        if self._tmp_dir:
            self._tmp_dir.cleanup()
        self._download_limit.release()

    async def save_file(self, response: ClientResponse) -> None:
        """
        Download the jar to a temporary workspace directory

        :param response: aiohttp response to download the jar from
        """
        # build path
        self._tmp_dir = TemporaryDirectory()
        self._filename = self._url.split("/")[-1]
        # download file
        with open(self.get_file_path(), "wb") as file:
            # with open(self._filename, "wb") as file:
            file.write(await response.read())
