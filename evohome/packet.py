"""Packet processor."""
import asyncio
from datetime import datetime as dt
import logging
import re
from string import printable
from threading import Lock
from time import sleep
from typing import Optional

from serial import SerialException
from serial_asyncio import open_serial_connection

from .command import PAUSE_SHORT
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

    def is_wanted(self, dev_whitelist=None, dev_blacklist=None, **kwargs) -> bool:
        """Return True is a packet is not to be filtered out."""

        return True  # TODO needs fixing ASAP

        if self._is_wanted is not None:
            return self._is_wanted

        def has_wanted_dev(dev_whitelist=None, dev_blacklist=None) -> bool:
            """Return True only if a packet contains 'wanted' devices."""
            if " 18:" in self.packet:  # TODO: should we allow blacklisting of a HGI80?
                return True
            if dev_whitelist:
                return any(device in self.packet for device in dev_whitelist)
            return not any(device in self.packet for device in dev_blacklist)

        # silently drop packets with unwanted (e.g. neighbour's) devices
        self._is_wanted = has_wanted_dev(dev_whitelist, dev_blacklist)

        if self._is_wanted:
            _LOGGER.info("%s ", self, extra=self.__dict__)

        return self._is_wanted


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

    async def get_pkt(self):  # returns a tuple
        """Get the next packet line from a serial port."""

        def _logger_msg(func, msg):
            # TODO: this is messy...
            date, time = dtm.split("T")
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
            return time_stamp(), None, None

        dtm = time_stamp()  # done here & now for most-accurate timestamp
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
            return dtm, None, raw_pkt

        # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

        return dtm, pkt, raw_pkt

    async def put_pkt(self, cmd, logger):  # TODO: logger is a hack
        """Get the next packet line from a serial port."""

        self._lock.acquire()
        # logger.debug("# Data was sent to %s: %s", self.serial_port, cmd)
        self.writer.write(bytearray(f"{cmd}\r\n".encode("ascii")))

        # cmd.dispatch_dtm = time_stamp()
        if str(cmd).startswith("!"):  # traceflag to evofw
            sleep(PAUSE_SHORT)
        else:
            sleep(cmd.pause)

        self._lock.release()

        # if cmd.verb == "RQ":
        #     cmd.dtm = time_stamp()
        #     self._window.append(cmd)


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


async def port_pkts(manager, relay=None, **kwargs):
    while True:
        pkt = Packet(*(await manager.get_pkt()))
        if pkt.is_valid and pkt.is_wanted(kwargs):
            if relay:  # TODO: handle socket close
                asyncio.create_task(relay.write(pkt.packet))
            yield pkt

        await asyncio.sleep(0.1)  # at least 0, to enable a Ctrl-C


async def file_pkts(fp, **kwargs):
    for ts_pkt in fp:
        try:
            assert re.match(ISO_FORMAT_REGEX, ts_pkt[:26])
            dt.fromisoformat(ts_pkt[:26])
        except (AssertionError, ValueError):  # TODO: log these, or not?
            _LOGGER.debug("Packet line has invalid timestamp: %s", ts_pkt[:26])
            continue

        pkt = Packet(ts_pkt[:26], ts_pkt[27:].strip(), None)
        if pkt.is_valid and pkt.is_wanted(kwargs):
            yield pkt

        await asyncio.sleep(0.1)  # at least 0, to enable a Ctrl-C
