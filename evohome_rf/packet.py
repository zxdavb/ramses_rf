#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser.

Decode/process a packet (packet that was received).
"""

from datetime import datetime as dt, timedelta as td
import logging
import shutil
import sys
from types import SimpleNamespace
from typing import Optional, Tuple

try:
    import colorlog
    _use_color_ = True
except ModuleNotFoundError:
    _use_color_ = False

from .command import Command, Priority, _pkt_header
from .const import MESSAGE_REGEX, NUL_DEVICE, _dev_mode_
from .helpers import extract_addrs


DEV_MODE = _dev_mode_

DEFAULT_FMT = "%(asctime)s.%(msecs)03d %(message)s"
DEFAULT_DATEFMT = "%H:%M:%S"
DEFAULT_LEVEL = logging.INFO

# basicConfig must be called after importing colorlog to ensure its handlers wrap the
# correct streams
logging.basicConfig(level=DEFAULT_LEVEL, format=DEFAULT_FMT, datefmt=DEFAULT_DATEFMT)

CONSOLE_COLS = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns - 1)
# HH:MM:SS.sss vs YYYY-MM-DDTHH:MM:SS.ssssss, shorter format for the console
if DEV_MODE:  # Do this to have longer-format console messages
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
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

if not _use_color_:
    _LOGGER.warning("Consider installing the colorlog library for colored output")


POLLER_TASK = "poller_task"

SERIAL_CONFIG = {
    "baudrate": 115200,
    "timeout": 0,  # None
    "dsrdtr": False,
    "rtscts": False,
    "xonxoff": True,  # set True to remove \x11
}

Pause = SimpleNamespace(
    NONE=td(seconds=0),
    MINIMUM=td(seconds=0.01),
    SHORT=td(seconds=0.05),
    DEFAULT=td(seconds=0.15),
    LONG=td(seconds=0.5),
)

INIT_QOS = {"priority": Priority.ASAP, "retries": 24, "disable_backoff": True}
INIT_CMD = Command(" I", NUL_DEVICE.id, "0001", "00FFFF0200", qos=INIT_QOS)
# INIT_CMD = Command(" I", HGI_DEVICE.id, "0001", "00FFFF0200", qos=INIT_QOS)

# tx (from sent to gwy, to get back from gwy) seems to takes approx. 0.025s
QOS_TX_TIMEOUT = td(seconds=0.05)  # 0.20 OK, but too high?
QOS_TX_RETRIES = 2

QOS_RX_TIMEOUT = td(seconds=0.20)  # 0.10 too low sometimes
QOS_MAX_BACKOFF = 3  # 4 = 16x, is too many?

DEV_MODE = _dev_mode_ or True

_PKT_LOGGER = logging.getLogger(f"{__name__}-log")  # don't setLevel here

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.INFO)  # DEBUG may have too much detail


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


def extra(dtm, pkt=None):
    _date, _time = dtm[:26].split("T")
    return {
        "date": _date,
        "time": _time,
        "_packet": str(pkt) + " " if pkt else "",
        "error_text": "",
        "comment": "",
    }


def split_pkt_line(packet_line: str) -> Tuple[str, str, str]:
    # line format: 'datetime packet < parser-message: * evofw3-errmsg # evofw3-comment'
    def _split(text: str, char: str) -> Tuple[str, str]:
        _list = text.split(char, maxsplit=1)
        return _list[0].strip(), _list[1].strip() if len(_list) == 2 else ""

    packet_tmp, comment = _split(packet_line, "#")
    packet_tmp, error = _split(packet_tmp, "*")
    packet, _ = _split(packet_tmp, "<")
    return packet, f"* {error} " if error else "", f"# {comment} " if comment else ""


class Packet:
    """The packet class."""

    def __init__(self, dtm, pkt, raw_pkt) -> None:
        """Create a packet."""
        self.dtm = dtm
        self.date, self.time = dtm.split("T")  # dtm assumed to be valid

        self._dtm = dt.fromisoformat(self.dtm)
        self._pkt_str = pkt
        self._raw_pkt_str = raw_pkt
        self.packet, self.error_text, self.comment = split_pkt_line(pkt)
        self._packet = self.packet + " " if self.packet else ""  # NOTE: hack 4 logging

        self.addrs = [None] * 3
        self.src_addr = self.dst_addr = None

        self._is_valid = None
        self._is_valid = self.is_valid

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return str(self._raw_pkt_str if self._raw_pkt_str else self._pkt_str)

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""
        return self.packet if self.packet else ""

    def __eq__(self, other) -> bool:
        if not hasattr(other, "packet"):
            return NotImplemented
        return self.packet == other.packet

    @property
    def is_valid(self) -> Optional[bool]:
        """Return True if a valid packets, otherwise return False/None & log it."""
        # 'good' packets are not logged here, as they may be for silent discarding

        def invalid_addresses() -> bool:
            """Return True if the address fields are invalid (create any addresses)."""
            try:
                self.src_addr, self.dst_addr, self.addrs = extract_addrs(self.packet)
            except TypeError:
                return True

        if self._is_valid is not None or not self._pkt_str:
            return self._is_valid

        if self.error_text:  # log all packets with an error
            if self.packet:
                _PKT_LOGGER.warning("%s < Bad packet: ", self, extra=self.__dict__)
            else:
                _PKT_LOGGER.warning("< Bad packet: ", extra=self.__dict__)
            return False

        if not self.packet and self.comment:  # log null packets only if has a comment
            _PKT_LOGGER.warning("", extra=self.__dict__)  # normally a warning
            return False

        # TODO: these packets shouldn't go to the packet log, only STDERR?
        err_msg = ""
        if not MESSAGE_REGEX.match(self.packet):
            err_msg = "invalid packet structure"
        elif int(self.packet[46:49]) > 48:
            err_msg = "excessive payload length"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "mismatched payload length"
        elif invalid_addresses():
            err_msg = "invalid packet addresses"
        else:
            _PKT_LOGGER.info("%s ", self.packet, extra=self.__dict__)
            return True

        _PKT_LOGGER.warning("%s < Bad packet: %s ", self, err_msg, extra=self.__dict__)
        return False

    @property
    def _header(self) -> Optional[str]:
        """Return the QoS header of this packet."""

        if self.is_valid:
            return _pkt_header(self.packet)
