"""Logging utility."""

import ctypes
import logging
import os
import time

# from logging.handlers import TimedRotatingFileHandler
import shutil
import sys

BANDW_SUFFIX = "%(error_text)s%(comment)s"
COLOR_SUFFIX = "%(red)s%(error_text)s%(cyan)s%(comment)s"

# HH:MM:SS.sss vs YYYY-MM-DDTHH:MM:SS.ssssss
CONSOLE_COLS = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns - 1)
CONSOLE_FMT = "%(time).12s " + f"%(message).{CONSOLE_COLS - 13}s"
PKT_LOG_FMT = "%(date)sT%(time)s %(_packet)s"  # TODO: _packet is a hack for space @ end
MSG_LOG_FMT = "%(date)sT%(time)s %(message)s"


class FILETIME(ctypes.Structure):
    """Data structure for GetSystemTimePreciseAsFileTime()."""

    _fields_ = [("dwLowDateTime", ctypes.c_uint), ("dwHighDateTime", ctypes.c_uint)]


def time_stamp() -> str:
    """Return a time stamp as a string."""
    now = time_time()
    mil = f"{now%1:.6f}".lstrip("0")
    return time.strftime(f"%Y-%m-%dT%H:%M:%S{mil}", time.localtime(now))


def time_time():
    """Return an accurate time, even for Windows-based systems."""
    # see: https://www.python.org/dev/peps/pep-0564/
    if os.name == "posix":
        return time.time()  # since 1970-01-01T00:00:00Z
    # if os.name == "nt":
    file_time = FILETIME()
    ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(file_time))
    _time = (file_time.dwLowDateTime + (file_time.dwHighDateTime << 32)) / 1e7
    return _time - 134774 * 24 * 60 * 60  # since 1601-01-01T00:00:00Z


def set_logging(
    logger,
    stream=sys.stderr,
    cons_fmt=CONSOLE_FMT,
    file_fmt=MSG_LOG_FMT,
    file_name=None,
):
    """Create/configure handlers, formatters, etc."""
    logger.propagate = False

    try:  # formatter = ...
        from colorlog import ColoredFormatter, default_log_colors

        # # basicConfig must be called after importing colorlog in order to
        # # ensure that the handlers it sets up wraps the correct streams.
        # logging.basicConfig(level=logging.INFO)

        formatter = ColoredFormatter(
            f"%(log_color)s{cons_fmt}", reset=True, log_colors=default_log_colors,
        )
    except ModuleNotFoundError:
        formatter = logging.Formatter(fmt=cons_fmt)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(formatter)
    handler.setLevel(logging.WARNING)
    # handler.addFilter(DebugFilter())

    logger.addHandler(handler)

    if stream == sys.stdout:
        handler = logging.StreamHandler(stream=stream)
        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG)
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

    def filter(self, record):
        """Filter only INFO/DEBUG packets."""
        return record.levelno in [logging.INFO, logging.DEBUG]


class DebugFilter(logging.Filter):
    """Don't Log DEBUG-level messages."""

    def filter(self, record):
        """Filter only all but DEBUG packets."""
        return record.levelno != logging.DEBUG  # TODO: use less than / more than?
