#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a packet (packet that was received).
"""

import logging
import shutil
import sys
from datetime import datetime as dt
from typing import Optional, Tuple

from .address import pkt_addrs
from .command import pkt_header
from .const import MESSAGE_REGEX, __dev_mode__
from .exceptions import CorruptAddrSetError
from .helpers import dt_str
from .ramses import pkt_has_array, pkt_has_idx
from .schema import LOG_FILE_NAME, LOG_ROTATE_BYTES, LOG_ROTATE_COUNT
from .version import __version__

DEV_MODE = __dev_mode__  # or True

DEFAULT_FMT = "%(asctime)s.%(msecs)03d %(message)s"
DEFAULT_DATEFMT = "%H:%M:%S"

try:
    import colorlog
except ModuleNotFoundError:
    _use_color_ = False
else:
    _use_color_ = True
    # basicConfig must be called after importing colorlog to ensure its handlers wrap
    # the correct streams
    # logging.basicConfig(format=DEFAULT_FMT, datefmt=DEFAULT_DATEFMT)
    # logging.basicConfig()

# TODO: make account for the non-printing characters
CONSOLE_COLS = int(shutil.get_terminal_size(fallback=(2e3, 24)).columns - 1)
# HH:MM:SS.sss vs YYYY-MM-DDTHH:MM:SS.ssssss, shorter format for the console
if False and DEV_MODE:  # Do this to have longer-format console messages
    CONSOLE_FMT = "%(_date)sT%(_time)s " + f"%(message).{CONSOLE_COLS - 27}s"
else:
    CONSOLE_FMT = "%(_time).12s " + f"%(message).{CONSOLE_COLS - 13}s"
PKT_LOG_FMT = "%(_date)sT%(_time)s %(packet)s"

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

_PKT_LOGGER = logging.getLogger(f"{__name__}_log")

if not _use_color_:
    _LOGGER.warning("Consider installing the colorlog library for colored output")


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


class FileFilter(logging.Filter):  # record.levelno in (logging.INFO, logging.WARNING)
    """For packet log files, process only wanted packets."""

    def filter(self, record) -> bool:
        """Return True if the record is to be processed."""
        return record.levelno in (logging.INFO, logging.WARNING)


def set_pkt_logging(logger=_PKT_LOGGER, cc_stdout=False, **kwargs) -> None:
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

        handler.setFormatter(logging.Formatter(fmt=PKT_LOG_FMT + BANDW_SUFFIX))
        handler.setLevel(logging.INFO)  # .INFO (usually), or .DEBUG
        handler.addFilter(FileFilter())  # record.levelno in (.INFO, .WARNING)
        logger.addHandler(handler)

    else:
        handler = logging.NullHandler()
        logger.addHandler(handler)

    if cc_stdout:
        if _use_color_:
            cons_fmt = colorlog.ColoredFormatter(
                fmt=f"%(log_color)s{CONSOLE_FMT + COLOR_SUFFIX}",
                reset=True,
                log_colors=LOG_COLOURS,
            )
        else:
            cons_fmt = logging.Formatter(fmt=CONSOLE_FMT + BANDW_SUFFIX)

        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(cons_fmt)
        handler.setLevel(logging.WARNING)  # musr be .WARNING or less
        handler.addFilter(StdErrFilter())  # record.levelno >= .WARNING
        logger.addHandler(handler)

        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(cons_fmt)
        handler.setLevel(logging.DEBUG)  # must be .INFO or less
        handler.addFilter(StdOutFilter())  # record.levelno < .WARNING
        logger.addHandler(handler)

    _date, _time = dt_str()[:26].split("T")
    extras = {
        "_date": _date,
        "_time": _time,
        "packet": "",
        "error_text": "",
        "comment": f"# ramses_rf {__version__}",
    }
    logger.warning("", extra=extras)


class Packet:
    """The packet class."""

    def __init__(
        self, dtm: dt, frame: str, dtm_str: str = None, frame_raw=None
    ) -> None:
        """Create a packet.

        if dtm_str:
            assert dtm == dt.fromisoformat(dtm_str), "should be True"
        """

        self.dtm = dtm
        self._date, self._time = (dtm_str or dtm.isoformat(sep="T")).split("T")

        self._frame = frame
        self._frame_raw = frame_raw
        self.packet, self.error_text, self.comment = self._split_pkt_line(frame)

        # addrs are populated in self.is_valid()
        self.addrs = [None] * 3
        self.src = self.dst = None
        self._is_valid = None
        if not self.is_valid:
            raise ValueError(f"not a valid packet: {frame}")

        # TODO: these are not presently used
        self.rssi = self.packet[0:3]
        self.verb = self.packet[4:6]
        self.seqn = self.packet[7:10]
        self.code = self.packet[41:45]
        self.len = int(self.packet[46:49])
        self.payload = self.packet[50:]

        # these are calculated if/when required
        self.__header = None
        self.__has_array = None
        self.__has_idx = None
        self.__idx = None

    @classmethod
    def from_log_line(cls, dtm: str, frame: str):
        """Constructor to create a packet from a log file line (a frame)."""
        return cls(dt.fromisoformat(dtm), frame, dtm_str=dtm)

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return str(self._frame_raw or self._frame)

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""
        return self.packet

    def __eq__(self, other) -> bool:
        if not hasattr(other, "packet"):
            return NotImplemented
        return self.packet == other.packet

    @staticmethod
    def _split_pkt_line(log_line: str) -> Tuple[str, str, str]:
        """Split a packet log line (i.e. no dtm prefix) into its parts.

        Format: packet[ < parser-hint: ...][ * evofw3-err_msg][ # evofw3-comment]
        """

        fragment, _, comment = log_line.partition("#")
        fragment, _, err_msg = fragment.partition("*")
        pkt_line, _, _ = fragment.partition("<")  # discard any parser hints
        return (
            pkt_line.strip(),
            f" * {err_msg.strip()}" if err_msg else " *" if "*" in log_line else "",
            f" # {comment.strip()}" if comment else "",
        )

    @property
    def is_valid(self) -> Optional[bool]:
        """Return True if the packet is valid (will log all packets, regardless)."""

        def invalid_addresses(addr_set: str) -> Optional[bool]:
            """Return True if the address fields are invalid (create any addresses)."""
            try:
                self.src, self.dst, self.addrs = pkt_addrs(addr_set)
                # print(pkt_addrs.cache_info())
            except CorruptAddrSetError:
                return True

        if self._is_valid is not None or not self._frame:
            return self._is_valid

        self._is_valid = False
        if self.error_text:  # log all packets with an error
            if self.packet:
                _PKT_LOGGER.warning("%s < Bad packet:", self, extra=self.__dict__)
            else:
                _PKT_LOGGER.warning("< Bad packet:", extra=self.__dict__)
            return False

        if not self.packet and self.comment:  # log null packets only if has a comment
            _PKT_LOGGER.warning(
                "< Null packet", extra=self.__dict__
            )  # best as a debug?
            return False

        # TODO: these packets shouldn't go to the packet log, only STDERR?
        if not MESSAGE_REGEX.match(self.packet):
            err_msg = "invalid packet structure"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "mismatched payload length"
        elif invalid_addresses(self.packet[11:40]):
            err_msg = "invalid packet addresses"
        else:
            _PKT_LOGGER.info("%s", self.packet, extra=self.__dict__)
            self._is_valid = True
            return True

        _PKT_LOGGER.warning("%s < Bad packet: %s", self, err_msg, extra=self.__dict__)
        return False

    @property
    def _header(self) -> Optional[str]:
        """Return the QoS header of this packet."""

        if self.__header is None and self.is_valid:
            self.__header = pkt_header(self)
        return self.__header

    @property
    def _has_array(self) -> Optional[bool]:
        """Return True if the packet payload is an array (NB: false -ves)."""

        if self.__has_array is None and self.is_valid:
            self.__has_array = bool(pkt_has_array(self))
        return self.__has_array

    @property
    def _idx(self) -> Optional[str]:
        """Return the index/ordinal of a packet header, if any.

        Used to distinguish packets from a device that have the same code, but distinct
        contexts (e.g. all sensors in a zone). Returns ??? if there is none such, or if
        it is undetermined.
        """

        if self.__idx is None and self.is_valid:
            self.__idx = pkt_has_idx(self) or False
        return self.__idx
