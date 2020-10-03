#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Logging utility."""

import ctypes
from datetime import datetime as dt
import logging
import shutil
import sys
import time

# from logging.handlers import TimedRotatingFileHandler

from .const import __dev_mode__

BASIC_FMT = "%(asctime)s.%(msecs)03d %(message)s"
BASIC_DATEFMT = "%H:%M:%S"
BASIC_LEVEL = logging.INFO

BANDW_SUFFIX = "%(error_text)s%(comment)s"
COLOR_SUFFIX = "%(red)s%(error_text)s%(cyan)s%(comment)s"

try:
    from colorlog import ColoredFormatter  # default_log_colors
except ModuleNotFoundError:
    COLOR_SUFFIX = BANDW_SUFFIX

# basicConfig must be called after importing colorlog to ensure its handlers wrap the
# correct streams
logging.basicConfig(level=BASIC_LEVEL, format=BASIC_FMT, datefmt=BASIC_DATEFMT)

# HH:MM:SS.sss vs YYYY-MM-DDTHH:MM:SS.ssssss, shorter format for the console
CONSOLE_COLS = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns - 1)
CONSOLE_FMT = "%(time).12s " + f"%(message).{CONSOLE_COLS - 13}s"
PKT_LOG_FMT = "%(date)sT%(time)s %(_packet)s"
MSG_LOG_FMT = "%(date)sT%(time)s %(message)s"

if __dev_mode__:
    CONSOLE_FMT = MSG_LOG_FMT  # Do this to have longer-format console messages
# How to strip ASCII colour from a text file:
#   sed -r "s/\x1B\[(([0-9]{1,2})?(;)?([0-9]{1,2})?)?[m,K,H,f,J]//g" file_name

LOG_COLOURS = {
    "DEBUG": "white",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "bold_red",
    "CRITICAL": "bold_red",
}  # default_log_colors


class FILETIME(ctypes.Structure):
    """Data structure for GetSystemTimePreciseAsFileTime()."""

    _fields_ = [("dwLowDateTime", ctypes.c_uint), ("dwHighDateTime", ctypes.c_uint)]


def dt_now() -> dt:
    """Return the time now as a UTC datetime object."""
    return dt.fromtimestamp(time_time())


def dt_str() -> str:
    """Return the time now as a isoformat string."""
    now = time_time()
    mil = f"{now%1:.6f}".lstrip("0")
    return time.strftime(f"%Y-%m-%dT%H:%M:%S{mil}", time.localtime(now))


def time_time() -> float:
    """Return the number of seconds since the Unix epoch.

    Return an accurate value, even for Windows-based systems.
    """  # see: https://www.python.org/dev/peps/pep-0564/
    if sys.platform != "win32":
        return time.time()  # since 1970-01-01T00:00:00Z, time.gmtime(0)
    file_time = FILETIME()
    ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(file_time))
    _time = (file_time.dwLowDateTime + (file_time.dwHighDateTime << 32)) / 1e7
    return _time - 134774 * 24 * 60 * 60  # otherwise, is since 1601-01-01T00:00:00Z


def set_logging(
    logger,
    stream=sys.stderr,
    cons_fmt=CONSOLE_FMT,
    file_fmt=MSG_LOG_FMT,
    file_name=None,
) -> None:
    """Create/configure handlers, formatters, etc."""
    logger.propagate = False

    if COLOR_SUFFIX == BANDW_SUFFIX:
        formatter = logging.Formatter(fmt=cons_fmt)
    else:
        formatter = ColoredFormatter(
            f"%(log_color)s{cons_fmt}", reset=True, log_colors=LOG_COLOURS
        )

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(formatter)
    handler.setLevel(logging.WARNING)
    # handler.addFilter(DebugFilter())

    logger.addHandler(handler)

    if stream == sys.stdout:
        handler = logging.StreamHandler(stream=stream)
        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG)  # TODO: should be WARNING, but breaks logging
        handler.addFilter(InfoFilter())

        logger.addHandler(handler)

    if file_name:
        # if log_rotate_days:
        #     err_handler = logging.handlers.TimedRotatingFileHandler(
        #         err_log_file_name, when="midnight", backupCount=log_rotate_days
        #     )
        # else:
        #     err_handler = logging.FileHandler(err_log_path, mode="w", delay=True)

        # err_handler.setLevel(logging.INFO if verbose else logging.WARNING)
        # err_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))

        handler = logging.FileHandler(file_name)
        handler.setFormatter(logging.Formatter(fmt=file_fmt))
        handler.setLevel(logging.DEBUG)
        handler.addFilter(DebugFilter())  # TODO: was InfoFilter()

        logger.addHandler(handler)


class InfoFilter(logging.Filter):
    """Log only INFO-level messages."""

    def filter(self, record) -> bool:
        """Filter out all but INFO/DEBUG packets."""
        return record.levelno in (logging.INFO, logging.DEBUG)


class DebugFilter(logging.Filter):
    """Don't Log DEBUG-level messages."""

    def filter(self, record) -> bool:
        """Filter out all DEBUG packets."""
        return record.levelno != logging.DEBUG  # TODO: use less than / more than?
