"""Packet processor."""

import asyncio
from collections import namedtuple
import logging

# import re

from serial import SerialException
from serial_asyncio import open_serial_connection
from string import printable
from typing import Optional

from .command import PAUSE_SHORT
from .const import MESSAGE_REGEX, __dev_mode__
from .logger import time_stamp

BAUDRATE = 115200
READ_TIMEOUT = 0.5
XON_XOFF = True

RAW_PKT = namedtuple("Packet", ["datetime", "packet", "bytearray"])

_LOGGER = logging.getLogger(__name__)


def split_pkt_line(packet_line: str) -> (str, str, str):
    def _split(text: str, char: str) -> (str, str):
        _list = text.split(char, maxsplit=1)
        return _list[0].strip(), _list[1].strip() if len(_list) == 2 else ""

    packet_tmp, comment = _split(packet_line, "#")
    packet, error = _split(packet_tmp, "*")
    return packet, f"* {error} " if error else "", f"# {comment} " if comment else ""


class Packet:
    """The packet class."""

    def __init__(self, raw_pkt) -> None:
        """Create a packet."""
        self.date, self.time = raw_pkt.datetime.split("T")
        self.packet, self.error_text, self.comment = split_pkt_line(raw_pkt.packet)

        self._pkt_line = raw_pkt.packet
        self._raw_pkt_line = raw_pkt.bytearray

        self._packet = self.packet + " " if self.packet else ""  # TODO: hack 4 logging

        self._is_valid = None
        self._is_valid = self.is_valid

    def __str__(self) -> str:
        """Represent the packet as a string."""
        return self.packet if self.packet else ""

    def __repr__(self):
        """Represent the packet in an umabiguous manner."""
        return str(self._raw_pkt_line if self._raw_pkt_line else self._pkt_line)

    @property
    def is_valid(self) -> bool:
        """Return True if the packet is valid in structure.

        All exceptions are to be trapped, and logged appropriately.
        """
        if self._is_valid is not None:
            return self._is_valid

        if not self._pkt_line:  # don't log null packets at all
            return False

        if self.error_text:  # log all packets with an error
            # return False  # TODO: return here is only for TESTING
            if self.packet:
                _LOGGER.warning("%s < Bad packet: ", self, extra=self.__dict__)
            else:
                _LOGGER.warning("< Bad packet: ", extra=self.__dict__)
            return False

        if not self.packet and self.comment:  # log null packets only if has a comment
            _LOGGER.warning("", extra=self.__dict__)  # normally a warning
            return False

        # TODO: these packets shouldn't go to the packet log, only STDERR?
        if not MESSAGE_REGEX.match(self.packet):
            err_msg = "invalid packet structure"
        elif int(self.packet[46:49]) > 48:
            err_msg = "excessive payload length"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "mismatched payload length"
        # TODO: maybe should rely upon parsers for this?
        elif "--:------" not in self.packet:
            err_msg = "three device addresses"
        # TODO: definitely should rely upon parsers for this
        # elif not re.match("(0[0-9AB]|21|F[89ABCF])", self.packet[50:53]):
        #     err_msg = "dodgy zone idx/domain id"
        else:  # it is a valid packet!
            # NOTE: don't log good packets here: we may want to silently discard some
            return True

        _LOGGER.warning("%s < Bad packet: %s ", self, err_msg, extra=self.__dict__)
        return False


class PortPktProvider:
    """Base class for packets from a serial port."""

    def __init__(self, serial_port, loop, timeout=READ_TIMEOUT) -> None:
        # self.serial_port = "rfc2217://localhost:5000"
        self.serial_port = serial_port
        self.baudrate = BAUDRATE
        self.timeout = timeout
        self.xonxoff = XON_XOFF
        self.loop = loop

        self.reader = self.write = None

    async def __aenter__(self):
        # TODO: Add ValueError, SerialException wrapper
        self.reader, self.writer = await open_serial_connection(
            loop=self.loop,
            url=self.serial_port,
            baudrate=self.baudrate,
            timeout=self.timeout,
            # write_timeout=None,
            xonxoff=self.xonxoff,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        pass

    async def get_pkt(self):
        """Get the next packet line from a serial port."""

        def _logger_msg(func, msg):
            # TODO: this is messy...
            date, time = timestamp.split("T")
            func(
                "%s < %s",
                raw_pkt,
                msg,
                extra={
                    "date": date,
                    "time": time,
                    "error_text": "",
                    "comment": "",
                    "_packet": raw_pkt,
                },
            )

        try:
            raw_pkt = await self.reader.readline()
        except SerialException:
            return RAW_PKT(time_stamp(), None, None)

        timestamp = time_stamp()  # done here & now for most-accurate timestamp
        if __dev_mode__:
            _logger_msg(_LOGGER.debug, "Raw packet")

        try:
            pkt = "".join(
                c
                for c in raw_pkt.decode("ascii", errors="strict").strip()
                if c in printable
            )
        except UnicodeDecodeError:
            _logger_msg(_LOGGER.warning, "Bad (raw) packet")
            return RAW_PKT(time_stamp, None, None)

        # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

        return RAW_PKT(timestamp, pkt, raw_pkt)

    async def put_pkt(self, cmd, logger):  # TODO: logger is a hack
        """Get the next packet line from a serial port."""

        # logger.debug("# Data was sent to %s: %s", self.serial_port, cmd)
        self.writer.write(bytearray(f"{cmd}\r\n".encode("ascii")))

        # cmd.dispatch_dtm = time_stamp()
        if str(cmd).startswith("!"):  # traceflag to evofw
            await asyncio.sleep(PAUSE_SHORT)
        else:
            await asyncio.sleep(cmd.pause)


class FilePktProvider:
    """WIP: Base class for packets from a source file."""

    def __init__(self, file_name) -> None:
        self.file_name = file_name

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        pass

    async def get_next_pkt(self) -> Optional[str]:
        """Get the next packet line from a source file."""
        return
