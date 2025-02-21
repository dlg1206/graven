"""
File: heartbeat.py

Description: Heartbeat logger to post updates of queue status

@author Derek Garcia
"""
import time

from common.logger import Level, logger

DEFAULT_HEARTBEAT_INTERVAL = 5


class Heartbeat:
    def __init__(self, queue_name: str, interval: int = DEFAULT_HEARTBEAT_INTERVAL):
        """
        Create a new heartbeat to print snapshot details about the current state of the crawler
        Is disabled if logging is at debug level

        :param queue_name: Name of queue the heartbeat is of
        :param interval: Time in seconds between heartbeat messages
        """
        self.queue_name = queue_name
        self._interval = interval
        self._last_heartbeat = None
        self._last_count = None

    def beat(self, queue_size: int) -> None:
        """
        Log a heartbeat message

        :param queue_size: Current size of the crawler queue
        """
        # skip if running in debug mode
        if logger.get_logging_level() == Level.DEBUG:
            return
            # skip if not time for heartbeat
        if self._last_heartbeat and time.time() - self._last_heartbeat < self._interval:
            return
        # calc change and print
        if self._last_count == 0:
            # 0 to any %
            if queue_size:
                percent_change = 100
            # no change
            else:
                percent_change = 0
        else:
            percent_change = ((queue_size - self._last_count) / self._last_count) * 100 if self._last_count else 100

        logger.info(f"{self.queue_name} Queue: {queue_size} ( {percent_change:.2f}% )")
        self._last_count = queue_size
        self._last_heartbeat = time.time()
