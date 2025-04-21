from datetime import datetime
from threading import Semaphore

from qmodel.file import JarFile, GrypeFile, SyftFile

"""
File: message.py

Description: Collection of standardized messages for queues

@author Derek Garcia
"""


class Message:
    def __init__(self, domain_url: str, jar_url: str, publish_date: datetime):
        """
        Generator metadata object with details about the downloaded jar

        :param domain_url: The domain of this jar url was spawned from
        :param jar_url: URL of the jar
        :param publish_date: Timestamp when the jar was added
        """
        self._jar_id = jar_url.split("/")[-1]
        self._domain_url = domain_url
        self._jar_url = jar_url
        self._publish_date = publish_date
        self.jar_file: JarFile | None = None
        self.syft_file: SyftFile | None = None
        self.grype_file: GrypeFile | None = None

    def open_jar_file(self, work_dir: str, download_limit: Semaphore) -> None:
        """
        Create a new jar file

        :param work_dir: Working directory to create file
        :param download_limit: Download limit of number of jars
        """
        if not self.jar_file:
            self.jar_file = JarFile(work_dir, self._jar_id, download_limit)

    def open_syft_file(self, work_dir: str) -> None:
        """
        Create a new syft file

        :param work_dir: Working directory to create file
        """
        if not self.syft_file:
            self.syft_file = SyftFile(work_dir, self._jar_id)

    def open_grype_file(self, work_dir: str) -> None:
        """
        Create a new grype file

        :param work_dir: Working directory to create file
        """
        if not self.grype_file:
            self.grype_file = GrypeFile(work_dir, self._jar_id)

    def close(self) -> None:
        """
        Close any open files
        """
        # delete jar
        if self.jar_file:
            self.jar_file.close()
            self.jar_file = None
        # delete syft
        if self.syft_file:
            self.syft_file.close()
            self.syft_file = None
        # delete grype
        if self.grype_file:
            self.grype_file.close()
            self.grype_file = None

    @property
    def domain_url(self) -> str:
        """
        :return: Domain url
        """
        return self._domain_url

    @property
    def jar_id(self) -> str:
        """
        :return: Jar id
        """
        return self._jar_id

    @property
    def jar_url(self) -> str:
        """
        :return: URL of the jar
        """
        return self._jar_url

    @property
    def publish_date(self) -> datetime:
        """
        :return: publish date of jar
        """
        return self._publish_date
