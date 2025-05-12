import concurrent
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, Future
from queue import Queue, Empty
from threading import Event
from typing import Any, Literal

from db.graven_database import GravenDatabase
from qmodel.message import Message
from shared.logger import logger
from shared.timer import Timer

"""
File: worker.py

Description: Generic worker to handle common tasks

@author Derek Garcia
"""

QUEUE_POLL_TIMEOUT = 1


class Worker(ABC):

    def __init__(self, master_terminate_flag: Event, database: GravenDatabase, name: str):
        """
        A generic worker interface that handles polling and pushing messages between queues

        :param master_terminate_flag: Interrupt flag to signal shutdown
        :param database: Graven Database interface to use
        :param name: Name of worker
        """
        self._master_terminate_flag = master_terminate_flag
        self._database = database
        self._name = name
        self._consumer_queue = None
        self._producer_queue = None
        self._timer = Timer()
        # to be added at runtime
        self._run_id = None
        self._thread_pool_executor: ThreadPoolExecutor | None = None
        self._tasks = []

    def _handle_shutdown(self, message: Message) -> None:
        """
        Handle shutdown when interrupt is given

        :param message: Message to close
        """
        message.close()
        self._database.update_jar_status(message.jar_id, None)  # reset
        if self._consumer_queue:
            self._consumer_queue.task_done()

    def _poll_consumer_queue(self) -> Message | str | None:
        """
        Default poll consumer queue

        :return: Message from queue
        """
        if not self._consumer_queue:
            raise ValueError(f"'{self._name}' has no consumer queue")
        return self._consumer_queue.get(timeout=QUEUE_POLL_TIMEOUT)

    def _handle_empty_consumer_queue(self) -> Literal['continue', 'break']:
        """
        Util wrapper for handling an empty consumer queue

        Default always continue
        :return: continue or break
        """
        return 'continue'

    def _handle_none_message(self) -> Literal['continue', 'break']:
        """
        Util wrapper for handling an none message / poison pill

        Default check to make sure only poison pill left
        :return: continue or break
        """
        # no consumer queue, must exit
        if not self._consumer_queue:
            return 'break'
        self._consumer_queue.put(None)
        # only the poison pill is left
        if self._consumer_queue.qsize() == 1:
            return 'break'
        # other tasks left to process
        return 'continue'

    def _pre_start(self, **kwargs: Any) -> None:
        """
        Optional pre start conditions to handle

        :param kwargs: Any pre start configuration
        """
        pass

    def _post_start(self) -> None:
        """
        Optional post start conditions to handle
        """
        pass

    def set_consumer_queue(self, consumer_queue: Queue[Any | None]) -> None:
        """
        Set consumer queue

        :param consumer_queue: Optional consumer queue to poll data from
        """
        self._consumer_queue = consumer_queue

    def set_producer_queue(self, producer_queue: Queue[Any | None]) -> None:
        """
        Set producer queue

        :param producer_queue: Optional producer queue to submit data to
        """
        self._producer_queue = producer_queue

    def start(self, run_id: int, thread_pool_executor: ThreadPoolExecutor = None, **kwargs: Any) -> None:
        """
        Main run function that starts the worker

        :param run_id: Run ID that this run belongs to
        :param thread_pool_executor: Optional executor to submit jobs to
        :param kwargs: Any runtime needed arguments for the worker
        """
        self._run_id = run_id
        self._thread_pool_executor = thread_pool_executor
        self._pre_start(**kwargs)
        logger.info(f"Starting {self._name}. . .")
        # loop until interrupt or complete
        self._timer.start()
        while not self._master_terminate_flag.is_set():
            try:
                message = self._poll_consumer_queue()
                # handle poison pill
                if not message:
                    if self._handle_none_message() == 'continue':
                        continue
                    break
                # add task
                task = self._handle_message(message)
                if task:
                    self._tasks.append(task)
            except Empty:
                """
                To prevent deadlocks, the forced timeout with throw this error 
                for another iteration of the loop to check conditions
                """
                # determine whether to continue or break
                if self._handle_empty_consumer_queue() == 'continue':
                    continue
                break
        # stop
        self._timer.stop()
        logger.info(f"{self._name} | Completed in {self._timer.format_time()}")

        # log exit type
        if self._master_terminate_flag.is_set():
            logger.warn(f"{self._name} | Stop order received, exiting. . .")
        else:
            logger.warn(f"{self._name} | No more messages to process, waiting for remaining tasks to finish. . .")
        # safe exit
        concurrent.futures.wait(self._tasks)
        logger.info(f"{self._name} | All tasks finished, exiting. . .")
        # poison queue to signal stop if has producer queue
        if self._producer_queue:
            logger.debug_msg(f"{self._name} | Signaled downstream to stop")
            self._producer_queue.put(None)

        # run any worker-specific post run operations
        self._post_start()
        self.print_statistics_message()

    @abstractmethod
    def _handle_message(self, message: Message | str) -> Future | None:
        """
        Handle a message from the queue and return the future submitted to the executor

        :param message: The message to handle
        :return: The Future task or None if now task made
        """
        pass

    @abstractmethod
    def print_statistics_message(self) -> None:
        """
        Print worker specific statistic messages
        """
        pass
