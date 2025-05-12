"""
File: timer.py

Description: Util timer for tracking duration

@author Derek Garcia
"""

import time


class Timer:
    """
    Util timer for tracking duration
    """

    def __init__(self, start: bool = False):
        """
        Create new timer

        :param start: Start the timer when created (Default: False)
        """
        self._start_time = time.time() if start else None
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
        if not self._start_time:
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
        if not self._end_time - self._start_time:
            return 0
        return count / (self._end_time - self._start_time)

    def format_time(self, end_timer: bool = True) -> str:
        """
        Format elapsed seconds into hh:mm:ss string

        :param end_timer: End the timer (Default: True)
        :return: hours:minutes:seconds
        """
        if end_timer:
            self.stop()
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
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
