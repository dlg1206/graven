from qmodel.file import JarFile, GrypeFile, SyftFile
from shared.cache_manager import CacheManager

"""
File: message.py

Description: Collection of standardized messages for queues

@author Derek Garcia
"""


class Message:
    def __init__(self, jar_url: str, jar_uid: str):
        """
        Generator metadata object with details about the downloaded jar

        :param jar_url: URL of the jar
        :param jar_uid: UID of the jar
        """
        self._jar_url = jar_url
        self._jar_id = jar_uid
        self.jar_file: JarFile | None = None
        self.syft_file: SyftFile | None = None
        self.grype_file: GrypeFile | None = None

    def init_jar_file(self, cache: CacheManager, work_dir: str) -> None:
        """
        Init a new jar file

        :param cache: Cache where file is stored
        :param work_dir: Working directory to create file
        """
        self.jar_file = JarFile(cache, work_dir, self._jar_id)

    def init_syft_file(self, cache: CacheManager, work_dir: str) -> None:
        """
        Init a new syft file

        :param cache: Cache where file is stored
        :param work_dir: Working directory to create file
        """
        self.syft_file = SyftFile(cache, work_dir, self._jar_id)

    def init_grype_file(self, cache: CacheManager, work_dir: str) -> None:
        """
        Create a new grype file

        :param cache: Cache where file is stored
        :param work_dir: Working directory to create file
        """
        self.grype_file = GrypeFile(cache, work_dir, self._jar_id)

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
