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

try:
    import colorlog

    _use_color_ = True
except ModuleNotFoundError:
    _use_color_ = False

from .const import _dev_mode_

DEFAULT_FMT = "%(asctime)s.%(msecs)03d %(message)s"
DEFAULT_DATEFMT = "%H:%M:%S"
DEFAULT_LEVEL = logging.INFO

# basicConfig must be called after importing colorlog to ensure its handlers wrap the
# correct streams
logging.basicConfig(level=DEFAULT_LEVEL, format=DEFAULT_FMT, datefmt=DEFAULT_DATEFMT)

CONSOLE_COLS = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns - 1)
# HH:MM:SS.sss vs YYYY-MM-DDTHH:MM:SS.ssssss, shorter format for the console
if _dev_mode_:  # Do this to have longer-format console messages
    CONSOLE_FMT = "%(date)sT%(time)s %(message)s"
else:
    CONSOLE_FMT = "%(time).12s " + f"%(message).{CONSOLE_COLS - 13}s"
PKT_LOG_FMT = "%(date)sT%(time)s %(_packet)s"

# How to strip ASCII colour from a text file:
#   sed -r "s/\x1B\[(([0-9]{1,2})?(;)?([0-9]{1,2})?)?[m,K,H,f,J]//g" file_name

# used with packet logging
BANDW_SUFFIX = "%(error_text)s%(comment)s"
COLOR_SUFFIX = "%(red)s%(error_text)s%(cyan)s%(comment)s"

LOG_COLOURS = {
    "DEBUG": "white",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "bold_red",
    "CRITICAL": "bold_red",
}  # default_log_colors

_LOGGER = logging.getLogger(__name__)
if False or _dev_mode_:
    _LOGGER.setLevel(logging.DEBUG)

if not _use_color_:
    _LOGGER.warning("Consider installing the colorlog library for colored output")


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


def set_pkt_logging(logger, file_name=None, cc_stdout=False, rotate_days=None) -> None:
    """Create/configure handlers, formatters, etc."""
    logger.propagate = False

    if _use_color_:
        cons_fmt = colorlog.ColoredFormatter(
            f"%(log_color)s{CONSOLE_FMT + COLOR_SUFFIX}",
            reset=True,
            log_colors=LOG_COLOURS,
        )
    else:
        cons_fmt = logging.Formatter(fmt=CONSOLE_FMT + BANDW_SUFFIX)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(cons_fmt)
    handler.setLevel(logging.WARNING)
    handler.addFilter(StdErrFilter())
    logger.addHandler(handler)

    if cc_stdout:
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(cons_fmt)
        handler.setLevel(logging.DEBUG)
        handler.addFilter(StdOutFilter())
        logger.addHandler(handler)

    if file_name:
        if rotate_days:
            handler = logging.handlers.TimedRotatingFileHandler(
                file_name, when="midnight", backupCount=rotate_days
            )
        else:
            handler = logging.FileHandler(file_name)
        handler.setFormatter(logging.Formatter(fmt=PKT_LOG_FMT + BANDW_SUFFIX))
        handler.setLevel(logging.INFO)  # INFO (usually), or DEBUG
        handler.addFilter(FileFilter())
        logger.addHandler(handler)


class StdErrFilter(logging.Filter):
    """For sys.stderr, process only wanted packets."""

    def filter(self, record) -> bool:
        """Return True if the record is to be processed. """
        return record.levelno >= logging.WARNING


class StdOutFilter(logging.Filter):
    """For sys.stdout, process only wanted packets."""

    def filter(self, record) -> bool:
        """Return True if the record is to be processed. """
        return record.levelno < logging.WARNING


class FileFilter(logging.Filter):
    """For packet logs file, process only wanted packets."""

    def filter(self, record) -> bool:
        """Return True if the record is to be processed. """
        return record.levelno in (logging.INFO, logging.WARNING)
