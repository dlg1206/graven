"""
File: file.py

Description: Util class to handle removing files from after usage

@author Derek Garcia
"""

import os
from threading import Semaphore

from shared.cache_manager import CacheManager
from shared.logger import logger


class File:
    """
    Wrapper for handling file representation
    """

    def __init__(self, cache: CacheManager, work_dir: str, file_name: str, file_ext: str) -> None:
        """
        Create a new file object

        :param cache: Cache where file is stored
        :param work_dir: Working directory to save the file in
        :param file_name: Name of the file
        :param file_ext: Extension of the file
        """
        self._cache = cache
        self._file_name = file_name.replace(".jar", file_ext)
        self._file_path = f"{work_dir}{os.sep}{self._file_name}"
        self._open = False

    def get_file_size(self) -> int:
        """
        :return: size of the file in bytes
        """
        # ensure file exists
        if not os.path.exists(self._file_path):
            return 0
        # get size
        return os.path.getsize(self._file_path)

    def open(self) -> None:
        """
        Open the file and ensure cache is updated - must be on the system
        """
        self._cache.update_space(
            self._file_name, os.path.getsize(
                self._file_path))
        self._open = True

    def close(self) -> None:
        """
        Delete the file
        """
        self._open = False
        # don't attempt to close if not open
        if not os.path.exists(self._file_path):
            return
        # delete file
        try:
            os.remove(self._file_path)
            self._cache.free_space(self._file_name)
        except Exception as e:
            logger.error_exp(e)

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
    """
    Wrapper for a jar file
    """

    def __init__(self, cache: CacheManager, work_dir: str, file_name: str, jar_limit_semaphore: Semaphore = None):
        """
        Create a new jar file object with limit lock

        :param cache: Cache where file is stored
        :param work_dir: Working directory to save the file in
        :param file_name: Name of the file
        :param jar_limit_semaphore: Optional limit to number of jars downloaded at one time
        """
        super().__init__(cache, work_dir, file_name, ".jar")
        self._jar_limit_semaphore = jar_limit_semaphore

    def close(self) -> None:
        """
        Delete the file and release semaphore if using it
        """
        super().close()
        if self._jar_limit_semaphore:
            self._jar_limit_semaphore.release()
            self._jar_limit_semaphore = None  # ensure cannot release more than once


class SyftFile(File):
    """
    Wrapper for a syft file
    """

    def __init__(self, cache: CacheManager, work_dir: str, file_name: str):
        """
        Create a new syft file

        :param cache: Cache where file is stored
        :param work_dir: Working directory to save the file in
        :param file_name: Name of the file
        """
        super().__init__(cache, work_dir, file_name, ".syft")


class GrypeFile(File):
    """
    Wrapper for a grype file
    """

    def __init__(self, cache: CacheManager, work_dir: str, file_name: str):
        """
        Create a new grype file

        :param cache: Cache where file is stored
        :param work_dir: Working directory to save the file in
        :param file_name: Name of the file
        """
        super().__init__(cache, work_dir, file_name, ".grype")
