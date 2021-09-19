#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

This module wraps logger to provide bespoke functionality, especially for timestamps.
"""

import logging
import shutil
import sys
from datetime import datetime as dt

from .const import __dev_mode__
from .schema import LOG_FILE_NAME, LOG_ROTATE_BYTES, LOG_ROTATE_COUNT
from .version import VERSION

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

try:
    import colorlog
except ModuleNotFoundError:
    _use_color_ = False
    _LOGGER.warning("Consider installing the colorlog library for colored logging")
else:
    _use_color_ = True
    # logging.basicConfig(format=DEFAULT_FMT, datefmt=DEFAULT_DATEFMT)  # Causes issues

DEFAULT_FMT = "%(asctime)s.%(msecs)03d %(message)s"
DEFAULT_DATEFMT = "%H:%M:%S"

# TODO: make account for the non-printing characters
CONSOLE_COLS = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns - 1)

if DEV_MODE:  # Do this to have longer-format console messages
    # HH:MM:SS.sss vs YYYY-MM-DDTHH:MM:SS.ssssss, shorter format for the console
    CONSOLE_FMT = f"%(asctime)s%(frame).{CONSOLE_COLS - 27}s"
else:
    CONSOLE_FMT = f"%(asctime)s%(frame).{CONSOLE_COLS - 13}s"

PKT_LOG_FMT = "%(asctime)s%(frame)s"

BANDW_SUFFIX = "%(message)s%(error_text)s%(comment)s"
COLOR_SUFFIX = "%(yellow)s%(message)s%(red)s%(error_text)s%(cyan)s%(comment)s"

# How to strip ASCII colour from a text file:
#   sed -r "s/\x1B\[(([0-9]{1,2})?(;)?([0-9]{1,2})?)?[m,K,H,f,J]//g" file_name

LOG_COLOURS = {
    "DEBUG": "white",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "bold_red",
    "CRITICAL": "bold_red",
}  # default_log_colors


class _Logger(logging.Logger):  # use pkt.dtm for the log record timestamp
    """Logger instances represent a single logging channel."""

    def makeRecord(
        self,
        name,
        level,
        fn,
        lno,
        msg,
        args,
        exc_info,
        func=None,
        extra=None,
        sinfo=None,
    ):
        """Create a specialized LogRecord with a bespoke timestamp.

        Will overwrite created and msecs (and thus asctime), but not relativeCreated.
        """

        extra = dict(extra)
        extra["frame"] = extra.pop("_frame", "")
        if extra["frame"]:
            extra["frame"] = f" {extra['frame']}"

        rv = super().makeRecord(
            name, level, fn, lno, msg, args, exc_info, func, extra, sinfo
        )

        if hasattr(rv, "dtm"):  # if dtm := extra.get("dtm"):
            ct = rv.dtm.timestamp()
            rv.created = ct
            rv.msecs = (ct - int(ct)) * 1000

        if rv.msg:
            rv.msg = f" < {rv.msg}"

        if getattr(rv, "error_text", None):
            rv.error_text = f" * {rv.error_text}"

        if getattr(rv, "comment", None):
            rv.comment = f" # {rv.comment}"

        return rv


class _Formatter:  # format asctime with configurable precision
    """Formatter instances convert a LogRecord to text."""

    converter = None
    default_time_format = "%Y-%m-%dT%H:%M:%S.%f"
    precision = 6

    def formatTime(self, record, datefmt=None) -> str:
        """Return the creation time (asctime) of the LogRecord as formatted text.

        Allows for sub-millisecond precision, using datetime instead of time objects.
        """
        result = dt.fromtimestamp(record.created).strftime(
            datefmt or self.default_time_format
        )
        if "f" not in self.default_time_format:
            return result
        precision = self.precision or -1
        return result[: precision - 6] if -1 <= precision < 6 else result


class ColoredFormatter(_Formatter, colorlog.ColoredFormatter):
    pass


class Formatter(_Formatter, logging.Formatter):
    pass


class PktLogFilter(logging.Filter):  # record.levelno in (logging.INFO, logging.WARNING)
    """For packet log files, process only wanted packets."""

    def filter(self, record) -> bool:
        """Return True if the record is to be processed."""
        # if record._frame[4:] or record.comment or record.error_text:
        return record.levelno in (logging.INFO, logging.WARNING)


class StdErrFilter(logging.Filter):  # record.levelno >= logging.WARNING
    """For sys.stderr, process only wanted packets."""

    def filter(self, record) -> bool:
        """Return True if the record is to be processed."""
        return record.levelno >= logging.WARNING  # WARNING-30, ERROR-40


class StdOutFilter(logging.Filter):  # record.levelno < logging.WARNING
    """For sys.stdout, process only wanted packets."""

    def filter(self, record) -> bool:
        """Return True if the record is to be processed."""
        return record.levelno < logging.WARNING  # INFO-20, DEBUG-10


def getLogger(name=None, pkt_log=None):  # permits a bespoke Logger class
    """Return a logger with the specified name, creating it if necessary.

    Used to set record timestamps to its packet timestamp instead of the current time.
    """
    if name is None or not pkt_log:
        return logging.getLogger(name)

    logging._acquireLock()  # HACK: So no-one else uses our Logger class
    klass = logging.getLoggerClass()
    logging.setLoggerClass(_Logger)

    logger = logging.getLogger(name)

    logging.setLoggerClass(klass)
    logging._releaseLock()

    return logger


def set_logger_timesource(dtm_now):
    """Set a custom record factory, with a bespoke source of timestamps.

    Used to have records with the same datetime as the most recent packet log record.
    """

    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)

        ct = dtm_now().timestamp()
        record.created = ct
        record.msecs = (ct - int(ct)) * 1000

        return record

    old_factory = logging.getLogRecordFactory()

    logging.setLogRecordFactory(record_factory)


def set_pkt_logging(logger, dt_now=None, cc_console=False, **kwargs) -> None:
    """Create/configure handlers, formatters, etc.

    Parameters:
    - backup_count: keep this many copies, and rotate at midnight unless...
    - max_bytes: rotate log files when log > rotate_size
    """

    logger.propagate = False  # log file is distinct from any app/debug logging
    logger.setLevel(logging.DEBUG)  # must be at least .INFO

    if file_name := kwargs.get(LOG_FILE_NAME, 0):
        max_bytes = kwargs.get(LOG_ROTATE_BYTES, None)
        bkp_count = kwargs.get(LOG_ROTATE_COUNT, 0)

        if max_bytes:
            bkp_count = bkp_count or 2
            handler = logging.handlers.RotatingFileHandler(
                file_name, maxBytes=max_bytes, backupCount=bkp_count
            )
        elif bkp_count:
            handler = logging.handlers.TimedRotatingFileHandler(
                file_name, when="midnight", backupCount=bkp_count
            )
        else:
            handler = logging.FileHandler(file_name)

        logfile_fmt = Formatter(fmt=PKT_LOG_FMT + BANDW_SUFFIX)

        handler.setFormatter(logfile_fmt)
        handler.setLevel(logging.INFO)  # .INFO (usually), or .DEBUG
        handler.addFilter(PktLogFilter())  # record.levelno in (.INFO, .WARNING)
        logger.addHandler(handler)

    elif cc_console:
        logger.addHandler(logging.NullHandler())

    else:
        logger.setLevel(logging.CRITICAL)
        return

    if cc_console:
        if _use_color_:
            console_fmt = ColoredFormatter(
                fmt=f"%(log_color)s{CONSOLE_FMT + COLOR_SUFFIX}",
                reset=True,
                log_colors=LOG_COLOURS,
            )
        else:
            console_fmt = Formatter(fmt=CONSOLE_FMT + BANDW_SUFFIX)

        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(console_fmt)
        handler.setLevel(logging.WARNING)  # musr be .WARNING or less
        handler.addFilter(StdErrFilter())  # record.levelno >= .WARNING
        logger.addHandler(handler)

        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(console_fmt)
        handler.setLevel(logging.DEBUG)  # must be .INFO or less
        handler.addFilter(StdOutFilter())  # record.levelno < .WARNING
        logger.addHandler(handler)

    extras = {
        "_frame": "",
        "error_text": "",
        "comment": f"ramses_rf {VERSION}",
    }
    logger.warning("", extra=extras)
