"""
File: cache_manager.py
Description:

@author Derek Garcia
"""
import math
from contextlib import contextmanager
from threading import Lock

from shared.logger import logger

BYTES_PER_MB = 1024 ** 2
BYTES_PER_GB = 1024 ** 3

DEFAULT_MAX_CAPACITY = 5 * BYTES_PER_GB  # 5 gb

RESERVE_BACKOFF_TIMEOUT = 5  # backoff time to allow for cache to be cleared


class ExceedsCacheLimitError(MemoryError):
    """
    Attempt to save item that exceeds allowed space
    """

    def __init__(self, file_name: str, file_size: int, exceeds_by: int):
        super().__init__(f"Data exceeds allocated cache by {bytes_to_mb(exceeds_by):.2f} MB")
        self.file_name = file_name
        self.file_size = file_size
        self.exceeds_by = exceeds_by


class CacheManager:
    """
    Cache manager that handles the files available on the system
    """

    def __init__(self, max_capacity: int = DEFAULT_MAX_CAPACITY):
        """
        Create new cache manager

        :param max_capacity: Max size in bytes the cache can hold
        """
        self._lock = Lock()
        self._index = {}
        self._current_capacity = 0
        self._max_capacity = max_capacity

    @contextmanager
    def _open_critical_section(self) -> None:
        """
        Create a critical section
        """
        try:
            self._lock.acquire()
            yield
        finally:
            self._lock.release()

    def reserve_space(self, file_uid: str, file_size: int) -> bool:
        """
        Attempt to reserve space in cache

        :param file_uid: ID of file to reference
        :param file_size: Size of space to reserve
        :returns: True if space reserved, false otherwise
        """
        file_size = math.ceil(file_size)
        # ensure doesn't exceed limit
        if file_size > self._max_capacity:
            raise ExceedsCacheLimitError(file_uid, file_size, file_size - self._max_capacity)
        # attempt to reserve space
        with self._open_critical_section():
            space_available = self._current_capacity + file_size < self._max_capacity
            if space_available:
                self._index[file_uid] = file_size
                self._current_capacity += file_size
                logger.debug_msg(f"Reserved '{file_uid}' | reserved: {file_size} | available space: {self._current_capacity}")
            return space_available

    def update_space(self, file_uid: str, file_size: int) -> None:
        """
        Update the cache with corrected file size

        :param file_uid: ID of file to reference
        :param file_size: Size of space to update
        """
        file_size = math.ceil(file_size)
        # only update if size mismatch
        if self._index[file_uid] == file_size:
            return
        # else update
        with self._open_critical_section():
            diff = self._index[file_uid] - file_size  # before - after
            # remove previous estimate
            self._current_capacity -= self._index[file_uid]
            # set with corrected estimate
            self._index[file_uid] = file_size
            self._current_capacity += file_size
            logger.debug_msg(f"Updated '{file_uid}' | diff: {diff} | available space: {self._current_capacity}")

    def free_space(self, file_uid: str) -> None:
        """
        Free space from the cache)
        param file_uid: ID of file to reference
        """
        with self._open_critical_section():
            free = self._index.pop(file_uid, 0)
            self._current_capacity -= free
            logger.debug_msg(f"Freed '{file_uid}' | freed: {free} | available space: {self._current_capacity}")


def bytes_to_mb(size: int) -> float:
    """
    Convert bytes to MB

    :param size: size of bytes to covert
    """
    return size / BYTES_PER_MB


def mb_to_bytes(size: float) -> int:
    """
    Convert MB to bytes

    :param size: number of MB to convert to bytes
    """
    return size * BYTES_PER_MB
