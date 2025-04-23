import os
from threading import Semaphore

from shared.logger import logger

"""
File: file.py

Description: Util class to handle removing files from after usage

@author Derek Garcia
"""


class File:
    def __init__(self, work_dir: str, file_name: str, file_ext: str) -> None:
        """
        Create a new file object

        :param work_dir: Working directory to save the file in
        :param file_name: Name of the file
        :param file_ext: Extension of the file
        """
        self._file_name = file_name.replace(".jar", file_ext)
        self._file_path = f"{work_dir}{os.sep}{self._file_name}"
        self._open = True

    def close(self) -> None:
        """
        Delete the file
        """
        # don't attempt to close if not open
        if not os.path.exists(self._file_path):
            return
        # delete file
        try:
            os.remove(self._file_path)
        except Exception as e:
            logger.error_exp(e)
        self._open = False

    @property
    def file_name(self) -> str:
        """
        :return: Name of this file
        """
        return self._file_name

    @property
    def file_path(self) -> str:
        """
        :return: Path to this file
        """
        return self._file_path

    @property
    def is_open(self) -> bool:
        """
        :return: whether this file is exists or not
        """
        return self._open


class JarFile(File):
    def __init__(self, work_dir: str, file_name: str, download_limit: Semaphore):
        """
        Create a new jar file object with limit lock

        :param work_dir: Working directory to save the file in
        :param file_name: Name of the file
        :param download_limit: Semaphore lock to limit downloads
        """
        super().__init__(work_dir, file_name, ".jar")
        self._download_limit = download_limit

    def close(self) -> None:
        """
        Delete the file and release the lock
        """
        super().close()
        self._download_limit.release()


class SyftFile(File):
    def __init__(self, work_dir: str, file_name: str):
        """
        Create a new syft file

        :param work_dir: Working directory to save the file in
        :param file_name: Name of the file
        """
        super().__init__(work_dir, file_name, ".syft")


class GrypeFile(File):
    def __init__(self, work_dir: str, file_name: str):
        """
        Create a new grype file

        :param work_dir: Working directory to save the file in
        :param file_name: Name of the file
        """
        super().__init__(work_dir, file_name, ".grype")
