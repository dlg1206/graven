"""
File: utils.py

Description: Defaults for different parts of graven

@author Derek Garcia
"""
import os
import time
from queue import Queue

from log.logger import logger

DEFAULT_MAX_CONCURRENT_REQUESTS = os.cpu_count()


class Timer:
    def __init__(self):
        """
        Create new timer
        """
        self._start_time = None
        self._end_time = None

    def start(self) -> None:
        """
        Start the timer
        """
        self._start_time = time.time()

    def stop(self) -> None:
        """
        Stop the timer
        """
        self._end_time = time.time()

    def _validate(self) -> None:
        """
        Check the timer has been started and stopped
        """
        if not self._end_time:
            raise RuntimeError("Timer was never started")
        if not self._end_time:
            raise RuntimeError("Timer was never ended")

    def get_count_per_second(self, count: int) -> float:
        """
        Calculate the count per second

        :param count: Number of items processed over the duration of the timer
        :return: Number of items processed per second
        """
        self._validate()
        return count / (self._end_time - self._start_time)

    def format_time(self) -> str:
        """
        Format elapsed seconds into hh:mm:ss string

        :return: hours:minutes:seconds
        """
        self._validate()
        return format_time(self._end_time - self._start_time)


def format_time(elapsed_seconds: float) -> str:
    """
    Format elapsed seconds into hh:mm:ss string

    :param elapsed_seconds: Elapsed time in seconds
    :return: hours:minutes:seconds
    """
    hours, remainder = divmod(int(elapsed_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return "{:02}:{:02}:{:02}".format(hours, minutes, seconds)


def first_time_wait_for_tasks(queue_name: str, queue: Queue) -> None:
    """
    Blocking get from queue

    :param queue_name: name of queue
    :param queue: Queue to get item from
    """
    queue_name = queue_name.lower()
    logger.info(f"{queue_name.capitalize()} waiting for tasks, this may take some time before populating")
    wait_start = time.time()
    # EDGE CASE - if the crawler runs out of urls before this is called the program will wait forever
    queue.put(queue.get())  # block until item and immediately re-add
    logger.info(f"Tasks have been added to the {queue_name} queue, waited for {format_time(time.time() - wait_start)}.")
