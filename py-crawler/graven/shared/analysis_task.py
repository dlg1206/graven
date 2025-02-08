"""
File: analysis_task.py

Description: Metadata for a jar file to be scanned

@author Derek Garcia
"""
from asyncio import Semaphore
from tempfile import TemporaryDirectory

from aiohttp import ClientResponse

from log.logger import logger


class AnalysisTask:
    def __init__(self, url: str, timestamp: str, download_limit: Semaphore):
        """
        Task metadata object with details about the downloaded jar

        :param url: URL of the jar
        :param timestamp: Timestamp when the jar was added
        :param download_limit: Limit of the max number of downloads allowed at a time
        """
        self._url = url
        self._timestamp = timestamp
        self._download_limit = download_limit
        self._filename = None
        self._tmp_dir = None

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
        with open(f"{self._tmp_dir}{os.sep}{self._filename}", "wb") as file:
            async for chunk in response.content.iter_chunked(8192):
                file.write(await chunk)
        logger.debug_msg(f"Downloaded {self._filename}")
