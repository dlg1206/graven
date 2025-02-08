"""
File: defaults.py

Description: Defaults for different parts of graven

@author Derek Garcia
"""

DEFAULT_MAX_CONCURRENT_REQUESTS = 20


def format_time(elapsed_seconds: float) -> str:
    """
    Format elapsed seconds into hh:mm:ss string

    :param elapsed_seconds: Elapsed time in seconds
    :return: hours:minutes:seconds
    """
    hours, remainder = divmod(int(elapsed_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return "{:02}:{:02}:{:02}".format(hours, minutes, seconds)
