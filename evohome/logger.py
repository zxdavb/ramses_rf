"""Evohome serial."""

import logging

from .const import LOGGING_FILE

# CON_FORMAT = "%(message).164s"  # Virtual
CON_FORMAT = "%(message).220s"  # Laptop
# CON_FORMAT = "%(message).292s"  # Monitor
LOG_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s"

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
    filename=LOGGING_FILE,
    filemode="a",
)
_CONSOLE = logging.StreamHandler()
_CONSOLE.setLevel(logging.DEBUG)
_CONSOLE.setFormatter(logging.Formatter(CON_FORMAT, datefmt="%H:%M:%S"))

_LOGGER = logging.getLogger(__name__)
_LOGGER.addHandler(_CONSOLE)
