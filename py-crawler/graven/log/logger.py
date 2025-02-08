# Standard lib
import asyncio
import concurrent.futures
import inspect
import sys
from datetime import datetime
from enum import Enum
from typing import Literal, Any, Iterable

# 3rd Party
from tqdm import tqdm

# Local
# -- None -

"""
File: Logger.py
Description: Logger for actions

Adapted from https://github.com/dlg1206/threat-actor-database/blob/main/src/threat_actor_db/log/logger.py

@author Derek Garcia
"""

CLEAR = '\033[00m'
CALLER_FRAME_DISTANCE = 3


class Level(Enum):
    """
    Util ascii color codes
    """
    SILENT = (1, '')
    INFO = (2, '\033[97m')
    WARN = (2, '\033[93m')
    ERROR = (4, '\033[91m')
    DEBUG = (5, '\033[96m')
    FATAL = (-1, '\033[91m')

    def __init__(self, priority: int, color: str):
        """
        :param priority: Priority of level
        :param color: ANSI color code
        """
        self.priority = priority
        self._color = color

    def __lt__(self, other):
        # 1 has priority over N, even if 1 < N
        return self.value > other.value

    def __str__(self):
        """
        :return: Status name in its color
        """
        return f"{self._color}{self.name}{CLEAR}"


def _get_caller_module_name(caller_frame_distance: int = CALLER_FRAME_DISTANCE) -> str | None:
    """
    Search the stack from to get the caller module name

    :param caller_frame_distance: Distance between the current frame and target module
    :return: the caller module, None if none
    """
    # Get caller frame
    frame = inspect.currentframe()
    for _ in range(caller_frame_distance):
        frame = frame.f_back

    caller_module = inspect.getmodule(frame)
    return caller_module.__name__ if caller_module else None


class Logger:
    """
    Custom logger
    """
    _instance = None

    def __new__(cls):
        """
        Create new logger instance
        """
        # init if not created
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._initialize_logger()
        return cls._instance

    def _initialize_logger(self,
                           logging_level: Literal[Level.SILENT, Level.INFO, Level.ERROR, Level.DEBUG] = Level.INFO):
        """
        Create new logger instance. Can be SILENT, INFO, ERROR, or DEBUG

        :param logging_level: Logging level (default: INFO)
        """
        if logging_level not in [Level.SILENT, Level.INFO, Level.ERROR, Level.DEBUG]:
            raise ValueError(f"Invalid logging level: '{logging_level}'. "
                             f"Must be one of "
                             f"{[Level.SILENT.name, Level.INFO.name, Level.ERROR.name, Level.DEBUG.name]}")
        self._logging_level = logging_level

    def _log(self, level: Level, msg: str, exception: Exception | None = None) -> None:
        """
        Print log message

        :param level: logging level
        :param msg: Message to print
        :param exception: Optional exception type to print
        """
        # Don't print if level lower than the logger
        if level < self._logging_level:
            return

        # Build log message
        log_msg = f"{datetime.now()} | {level} {' ' * (5 - len(level.name))}"

        caller = _get_caller_module_name()
        if caller:
            log_msg += f" | {caller} "

        if exception:
            log_msg += f"| {type(exception).__name__} "
        # print
        print(f"{log_msg}| {msg}")

    def set_log_level(self, logging_level: str) -> None:
        """
         Set logging level. Can be SILENT, INFO, ERROR, or DEBUG

         :param logging_level: Logging level
         """
        match logging_level.upper():
            case 'SILENT':
                self._initialize_logger(Level.SILENT)
            case 'INFO':
                self._initialize_logger(Level.INFO)
            case 'WARN':
                self._initialize_logger(Level.WARN)
            case 'ERROR':
                self._initialize_logger(Level.ERROR)
            case 'DEBUG':
                self._initialize_logger(Level.DEBUG)
            case _:
                raise ValueError(f"Invalid logging level: '{logging_level}'. "
                                 f"Must be one of "
                                 f"{[member.name for member in Level]}")

    def get_logger(self):
        """
        Get logger instance
        """
        return self

    def get_logging_level(self) -> Level:
        """
        Get the current logging level
        """
        return self._logging_level

    def get_data_queue(self, data: Iterable[Any], description: str, unit: str, is_async: bool = False,
                       is_threaded: bool = False) -> Iterable[Any]:
        """
        Create a dynamic loading bar if in INFO mode


        :param data: Data to be looped over
        :param description: Description of the process
        :param unit: Unit of the process
        :param is_async: if the data need to be awaited (default: false)
        :param is_threaded: if the data needs to be completed (default: false)
        :return: iterable data
        """
        # use pretty loading bar if INFO level
        if self._logging_level == Level.INFO:
            desc = f"{datetime.now()} | {Level.INFO}   | {_get_caller_module_name(2)} | {description}"
            # todo handle either one or other
            if is_async:
                return tqdm(asyncio.as_completed(data),
                            desc=desc, unit=f"{unit}", file=sys.stdout, total=len(list(data)))
            if is_threaded:
                return tqdm(concurrent.futures.as_completed(data),
                            desc=desc, unit=f"{unit}", file=sys.stdout, total=len(list(data)))
            # return non-async
            return tqdm(data, desc=desc, unit=f"{unit}", file=sys.stdout)
        # else just return data, awaited if needed
        return asyncio.as_completed(data) if is_async else data

    def debug_msg(self, msg: str) -> None:
        """
        Print debug message

        :param msg: Message to print
        """
        self._log(Level.DEBUG, msg)

    def debug_exp(self, exception: Exception) -> None:
        """
        Print debug error message

        :param exception: exception
        """
        self._log(Level.DEBUG, exception.__str__(), exception)

    def info(self, msg: str) -> None:
        """
        Print info message

        :param msg: Message to print
        """
        self._log(Level.INFO, msg)

    def warn(self, msg: str, exception: Exception | None = None) -> None:
        """
        Print warn message

        :param msg: Message to print
        :param exception: Optional exception type to print
        """
        self._log(Level.WARN, msg, exception)

    def error_msg(self, msg: str, exception: Exception | None = None) -> None:
        """
        Print error message with a message

        :param msg: Message to print
        :param exception: Optional exception type to print
        """
        self._log(Level.ERROR, msg, exception)

    def error_exp(self, exception: Exception) -> None:
        """
        Print the exception and exception error

        :param exception: Optional exception type to print
        """
        self._log(Level.ERROR, exception.__str__(), exception)

    def fatal(self, exception: Exception) -> None:
        """
        Report fail message and exit

        :param exception: Optional exception type to print
        """
        self._log(Level.FATAL, exception.__str__(), exception)
        exit(1)


# Global logger
logger = Logger()
