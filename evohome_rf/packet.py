#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser.

Decode/process a packet (packet that was received).
"""

import logging
import shutil
import sys
from datetime import datetime as dt
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from typing import Optional, Tuple

try:
    import colorlog

    _use_color_ = True
except ModuleNotFoundError:
    _use_color_ = False

from .command import _pkt_header
from .const import MESSAGE_REGEX, __dev_mode__
from .exceptions import CorruptAddrSetError
from .helpers import extract_addrs
from .schema import LOG_FILE_NAME, LOG_ROTATE_BYTES, LOG_ROTATE_COUNT

DEV_MODE = __dev_mode__  # or True

DEFAULT_FMT = "%(asctime)s.%(msecs)03d %(message)s"
DEFAULT_DATEFMT = "%H:%M:%S"
DEFAULT_LEVEL = logging.INFO
# basicConfig must be called after importing colorlog to ensure its handlers wrap the
# correct streams
# logging.basicConfig(level=DEFAULT_LEVEL, format=DEFAULT_FMT, datefmt=DEFAULT_DATEFMT)

# TODO: make account for the non-printing characters
CONSOLE_COLS = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns - 1)
# HH:MM:SS.sss vs YYYY-MM-DDTHH:MM:SS.ssssss, shorter format for the console
if DEV_MODE:  # Do this to have longer-format console messages
    CONSOLE_FMT = "%(date)sT%(time)s " + f"%(message).{CONSOLE_COLS - 27}s"
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

_PKT_LOGGER = logging.getLogger(f"{__name__}_log")
# NOTE: cant _PKT_LOGGER.setLevel() here, use set_pkt_logging()

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)  # DEBUG may have too much detail

if not _use_color_:
    _LOGGER.warning("Consider installing the colorlog library for colored output")


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

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.prev_record = None

    def filter(self, record) -> bool:
        """Return True if the record is to be processed."""
        return record.levelno in (logging.INFO, logging.WARNING)

        # HACK: to stop duplicate logging...
        if not hasattr(record, "dtm"):
            self.prev_record = None
        elif self.prev_record:
            if self.prev_record.dtm != record.dtm:
                record, self.prev_record = self.prev_record, record
        else:
            self.prev_record = record
            return False

        return record.levelno in (logging.INFO, logging.WARNING)


def set_pkt_logging(logger, cc_stdout=False, **kwargs) -> None:
    """Create/configure handlers, formatters, etc.

    Parameters:
    - backup_count: keep this many copies, and rotate at midnight unless...
    - max_bytes: rotate log files when log > rotate_size
    """
    file_name = kwargs.get(LOG_FILE_NAME, 0)
    backup_count = kwargs.get(LOG_ROTATE_COUNT, 0)
    max_bytes = kwargs.get(LOG_ROTATE_BYTES, None)

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

    if not file_name:
        return

    if max_bytes:
        backup_count = backup_count or 2
        handler = RotatingFileHandler(
            file_name, maxBytes=max_bytes, backupCount=backup_count
        )
    elif backup_count:
        handler = TimedRotatingFileHandler(
            file_name, when="midnight", backupCount=backup_count
        )
    else:
        handler = logging.FileHandler(file_name)

    handler.setFormatter(logging.Formatter(fmt=PKT_LOG_FMT + BANDW_SUFFIX))
    handler.setLevel(logging.INFO)  # INFO (usually), or DEBUG
    handler.addFilter(FileFilter())
    logger.addHandler(handler)


class Packet:
    """The packet class."""

    def __init__(
        self, pkt_dtm: dt, dtm_str: str, pkt_line: str, raw_pkt_line: str
    ) -> None:
        """Create a packet."""
        self._dtm = pkt_dtm
        self.dtm = dtm_str
        self.date, self.time = self.dtm.split("T")

        self._pkt_str = pkt_line
        self._raw_pkt_str = raw_pkt_line
        self.packet, self.error_text, self.comment = self._split_pkt_line(pkt_line)
        self._packet = self.packet + " " if self.packet else ""  # NOTE: hack 4 logging

        self.addrs = [None] * 3
        self.src_addr = self.dst_addr = None
        self._pkt_header = None

        self._is_valid = None
        if not self.is_valid:
            raise ValueError("not a valid packet")

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return str(self._raw_pkt_str or self._pkt_str)

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""
        return self.packet or ""

    def __eq__(self, other) -> bool:
        if not hasattr(other, "packet"):
            return NotImplemented
        return self.packet == other.packet

    @staticmethod
    def _split_pkt_line(pkt_line: str) -> Tuple[str, str, str]:
        # format: 'datetime packet < parser-message: * evofw3-errmsg # evofw3-comment'

        packet_str, _, pkt_line = pkt_line.partition("<")
        _, _, pkt_line = pkt_line.partition("*")
        packet_err, _, packet_comment = pkt_line.partition("#")
        return (
            packet_str.strip(),
            f"* {packet_err.strip()} " if packet_err else "",
            f"# {packet_comment.strip()} " if packet_comment else "",
        )

    @property
    def is_valid(self) -> Optional[bool]:
        """Return True if a valid packets, otherwise return False/None & log it."""
        # 'good' packets are not logged here, as they may be for silent discarding

        def invalid_addresses() -> bool:
            """Return True if the address fields are invalid (create any addresses)."""
            try:
                self.src_addr, self.dst_addr, self.addrs = extract_addrs(
                    self.packet[11:40]
                )
                # print(extract_addrs.cache_info())
            except CorruptAddrSetError:
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
            _PKT_LOGGER.warning("", extra=self.__dict__)  # best as a debug?
            return False

        # TODO: these packets shouldn't go to the packet log, only STDERR?
        if not MESSAGE_REGEX.match(self.packet):
            err_msg = "invalid packet structure"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "mismatched payload length"
        elif invalid_addresses():
            err_msg = "invalid packet addresses"
        else:
            _PKT_LOGGER.info("%s ", self.packet, extra=self.__dict__)
            return True

        _PKT_LOGGER.debug("%s < Bad packet: %s ", self, err_msg, extra=self.__dict__)
        return False

    @property
    def _header(self) -> Optional[str]:
        """Return the QoS header of this packet."""

        # TODO: a mess: extract_addrs, an expensive function, is possibly called twice
        if self._pkt_header is None and self.is_valid:
            self._pkt_header = _pkt_header(self.packet)
        return self._pkt_header
