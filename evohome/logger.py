"""Logging utility."""

import logging
import shutil
import sys


CONSOLE_FORMAT = "%(time).12s %(message)s"
LOGFILE_FORMAT = "%(date)sT%(time)s %(message)s"


def set_logging(logger, stream=sys.stderr, file_name=None):
    """Create/configure handlers, formatters, etc."""
    logger.propagate = False

    cons_cols = shutil.get_terminal_size(fallback=(1e4, 24)).columns - 13
    cons_fmt = f"{CONSOLE_FORMAT[:-1]}.{cons_cols}s"

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
        handler = logging.FileHandler(file_name)
        handler.setFormatter(logging.Formatter(fmt=LOGFILE_FORMAT))
        handler.setLevel(logging.INFO)
        handler.addFilter(InfoFilter())

        logger.addHandler(handler)


class InfoFilter(logging.Filter):
    """Log only INFO-level messages."""
    def filter(self, record):
        return record.levelno in [logging.INFO, logging.DEBUG]


# class TimestampFormatter(logging.Formatter):
#     """Display only short timestamps."""
#     def format(self, record):
#         if self._fmt == CONSOLE_FORMAT:
#             if 'timestamp' in record.__dict__.keys():
#                 record.timestamp = record.timestamp[11:]
#         return super().format(record)

# LOGGING_FILE = "debug_logging.tst"
# CON_FORMAT = "%(message).164s"  # Virtual
# CON_FORMAT = "%(message).236s"  # Laptop
# CON_FORMAT = "%(message).292s"  # Monitor
# CON_FORMAT = "%(asctime)s.%(msecs)03d %(message)s"  # Whenever
# LOG_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s"
# LOG_FORMAT = "%(message)s"


# logging.basicConfig(
#     level=logging.WARNING,
#     format=LOG_FORMAT,
#     datefmt="%Y-%m-%dT%H:%M:%S",
#     filename=LOGGING_FILE,
#     filemode="a",
# )

# _CONSOLE = logging.StreamHandler()
# _CONSOLE.setLevel(logging.INFO)
# _CONSOLE.setFormatter(logging.Formatter(CON_FORMAT, datefmt="%H:%M:%S"))
# # _LOGGER.addHandler(_CONSOLE)

# _ROTATOR = TimedRotatingFileHandler(LOGGING_FILE, when="d", interval=1, backupCount=7)
# # _LOGGER.addHandler(_ROTATOR)

