import os
import time
from queue import Queue, Empty
from threading import Event

from shared.logger import logger
from shared.timer import format_time

"""
File: utils.py

Description: Defaults for different parts of graven

@author Derek Garcia
"""
DEFAULT_MAX_CONCURRENT_REQUESTS = os.cpu_count()


def first_time_wait_for_tasks(queue_name: str, queue: Queue, terminate_flag: Event) -> None:
    """
    Blocking get from queue

    :param queue_name: name of queue
    :param terminate_flag: Flag if triggered terminate blocking wait
    :param queue: Queue to get item from
    """
    queue_name = queue_name.lower()
    logger.info(f"{queue_name.capitalize()} waiting for tasks, this may take some time before populating")
    wait_start = time.time()
    # semi-busy loop because otherwise will wait forever if crawler finds nothing
    while not terminate_flag.is_set():
        try:
            queue.put(queue.get(timeout=1))  # block until item and immediately re-add
            # will only reach here once queue has been populated
            break
        except Empty:
            continue
    # report status based on termination flag
    if terminate_flag.is_set():
        logger.warn(f"Notified that no tasks will be added to the {queue_name} queue")
    else:
        logger.info(
            f"Tasks have been added to the {queue_name} queue, waited for {format_time(time.time() - wait_start)}.")
