"""Packet processor."""
import asyncio
from datetime import datetime as dt
import logging
import re
from string import printable
from threading import Lock

# from time import sleep
from typing import Optional

from serial import SerialException
from serial_asyncio import open_serial_connection

from .command import PAUSE_DEFAULT, PAUSE_SHORT
from .const import ISO_FORMAT_REGEX, MESSAGE_REGEX, __dev_mode__
from .logger import time_stamp

BAUDRATE = 115200
READ_TIMEOUT = 0.5
XON_XOFF = True

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

    def __init__(self, dtm, pkt, raw_pkt) -> None:
        """Create a packet."""
        # self._dtm = dt.fromisoformat(dtm)
        self.date, self.time = dtm.split("T")

        self._pkt_line = pkt
        self._raw_pkt_line = raw_pkt
        self.packet, self.error_text, self.comment = split_pkt_line(pkt)

        self._packet = self.packet + " " if self.packet else ""  # TODO: hack 4 logging

        self._is_valid = self._is_wanted = None
        self._is_valid = self.is_valid

    def __str__(self) -> str:
        return self.packet if self.packet else ""

    def __repr__(self):
        return str(self._raw_pkt_line if self._raw_pkt_line else self._pkt_line)

    def __eq__(self, other) -> bool:
        if not hasattr(other, "packet"):
            return NotImplemented
        return self.packet == other.packet

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
        elif int(self.packet[46:49]) > 48:  # TODO: need to test < 1?
            err_msg = "excessive payload length"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "mismatched payload length"
        # TODO: maybe should rely upon parsers for this?
        elif "--:------" not in self.packet:
            err_msg = "three device addresses"
        else:  # it is a valid packet!
            # NOTE: don't log good packets here: we may want to silently discard some

            # TODO: Check that expected RQ/RP pair happened

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

        self._lock = Lock()

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

    async def get_pkt(self) -> (str, str, Optional[bytearray]):
        """Get the next packet line (dtm, pkt, pkt_bytes) from a serial port."""

        def _logger_msg(func, msg):  # TODO: this is messy...
            date, time = dtm_str.split("T")
            extra = {"date": date, "time": time, "_packet": pkt_bytes}
            extra.update({"error_text": "", "comment": ""})
            func("%s < %s", pkt_bytes, msg, extra=extra)

        try:
            pkt_bytes = await self.reader.readline()
        except SerialException:
            return time_stamp(), "", None

        dtm_str = time_stamp()  # done here & now for most-accurate timestamp
        if __dev_mode__:
            _logger_msg(_LOGGER.debug, "Raw packet")

        try:
            pkt_str = "".join(
                c
                for c in pkt_bytes.decode("ascii", errors="strict").strip()
                if c in printable
            )
        except UnicodeDecodeError:
            _logger_msg(_LOGGER.warning, "Bad (raw) packet")
            return dtm_str, "", pkt_bytes

        # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

        return dtm_str, pkt_str, pkt_bytes

    async def put_pkt(self, cmd, logger):  # TODO: logger is a hack
        """Put the next packet line to a serial port."""

        # self._lock.acquire()
        logger.debug("# Data was sent to %s: %s", self.serial_port, cmd)
        self.writer.write(bytearray(f"{cmd}\r\n".encode("ascii")))

        # cmd.dispatch_dtm = time_stamp()
        if str(cmd).startswith("!"):  # traceflag to evofw
            await asyncio.sleep(PAUSE_SHORT)
        else:
            await asyncio.sleep(max(cmd.pause, PAUSE_DEFAULT))

        # self._lock.release()

        if cmd.retry is True:  # == "RQ":
            cmd.dtm = time_stamp()
            # self._window.append(cmd)


class FilePktProvider:
    """WIP: Base class for packets from a source file."""

    def __init__(self, file_name) -> None:
        self.file_name = file_name

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        pass

    async def get_pkt(self) -> Optional[str]:
        """Get the next packet line from a source file."""
        return


async def port_pkts(manager, relay=None):
    while True:
        pkt = Packet(*(await manager.get_pkt()))
        if pkt.is_valid:
            if relay:  # TODO: handle socket close
                asyncio.create_task(relay.write(pkt.packet))
            yield pkt

        await asyncio.sleep(0)  # at least 0, to enable a Ctrl-C


async def file_pkts(fp):
    for ts_pkt in fp:
        try:
            assert re.match(ISO_FORMAT_REGEX, ts_pkt[:26])
            dt.fromisoformat(ts_pkt[:26])
        except (AssertionError, ValueError):  # TODO: log these, or not?
            _LOGGER.debug("Packet line has invalid timestamp: %s", ts_pkt[:26])
            continue

        pkt = Packet(ts_pkt[:26], ts_pkt[27:].strip(), None)
        if pkt.is_valid:
            yield pkt

        await asyncio.sleep(0)  # usu. 0, to enable a Ctrl-C
