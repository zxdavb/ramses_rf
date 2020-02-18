"""Logging utility."""

import logging
# from logging.handlers import TimedRotatingFileHandler
import shutil
import sys


CONSOLE_FORMAT = "%(time).12s %(message)s"
LOGFILE_FORMAT = "%(date)sT%(time)s %(message)s"


def set_logging(logger, stream=sys.stderr, file_name=None):
    """Create/configure handlers, formatters, etc."""
    logger.propagate = False

    cons_cols = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns)
    cons_fmt = f"{CONSOLE_FORMAT[:-1]}.{cons_cols - 13}s"

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(fmt=cons_fmt))
    handler.setLevel(logging.WARNING)

    logger.addHandler(handler)

    if stream == sys.stdout:
        handler = logging.StreamHandler(stream=stream)
        handler.setFormatter(logging.Formatter(fmt=cons_fmt))
        handler.setLevel(logging.DEBUG)
        handler.addFilter(InfoFilter())

        logger.addHandler(handler)

    if file_name:
        # handler = logging.TimedRotatingFileHandler(
        #   file_name, when="d", interval=1, backupCount=7
        # )  # TODO: rotate logs

        handler = logging.FileHandler(file_name)
        handler.setFormatter(logging.Formatter(fmt=LOGFILE_FORMAT))
        handler.setLevel(logging.INFO)
        handler.addFilter(InfoFilter())

        logger.addHandler(handler)


class InfoFilter(logging.Filter):
    """Log only INFO-level messages."""
    def filter(self, record):
        return record.levelno in [logging.INFO, logging.DEBUG]
