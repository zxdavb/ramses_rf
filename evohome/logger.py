"""Evohome serial."""

import logging
from logging.handlers import TimedRotatingFileHandler

from .const import LOGGING_FILE

# CON_FORMAT = "%(message).164s"  # Virtual
# CON_FORMAT = "%(message).236s"  # Laptop
# CON_FORMAT = "%(message).292s"  # Monitor
CON_FORMAT = "%(message)s"  # Whenever
# LOG_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s"
LOG_FORMAT = "%(levelname)-8s %(message)s"

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
    filename=LOGGING_FILE,
    filemode="a",
)
_LOGGER = logging.getLogger(__name__)

_CONSOLE = logging.StreamHandler()
_CONSOLE.setLevel(logging.DEBUG)
_CONSOLE.setFormatter(logging.Formatter(CON_FORMAT, datefmt="%H:%M:%S"))
_LOGGER.addHandler(_CONSOLE)

_ROTATOR = TimedRotatingFileHandler(LOGGING_FILE, when="d", interval=1, backupCount=7)
_LOGGER.addHandler(_ROTATOR)
