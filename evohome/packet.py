"""Packet processor."""
import asyncio
from datetime import datetime as dt
import logging
import re
from string import printable
from threading import Lock

# from time import sleep
from typing import Optional, Tuple

from serial import SerialException
from serial_asyncio import open_serial_connection

from .command import PAUSE_DEFAULT, PAUSE_SHORT
from .const import (
    ISO_FORMAT_REGEX,
    MESSAGE_REGEX,
    NON_DEVICE,
    NUL_DEVICE,
    Address,
    __dev_mode__,
)
from .logger import time_stamp

BAUDRATE = 115200
READ_TIMEOUT = 0.5
XON_XOFF = True

_LOGGER = logging.getLogger(__name__)


def split_pkt_line(packet_line: str) -> Tuple[str, str, str]:
    def _split(text: str, char: str) -> Tuple[str, str]:
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

        self.addrs = [None] * 3
        self.src_addr = self.dst_addr = None

        self._is_valid = None
        _ = self.is_valid

    def __str__(self) -> str:
        return self.packet if self.packet else ""

    def __repr__(self):
        return str(self._raw_pkt_line if self._raw_pkt_line else self._pkt_line)

    def __eq__(self, other) -> bool:
        if not hasattr(other, "packet"):
            return NotImplemented
        return self.packet == other.packet

    @property
    def is_valid(self) -> Optional[bool]:
        """Return True if a valid packets, otherwise return False/None & log it."""
        # 'good' packets are not logged here, as they may be for silent discarding

        def _validate_addresses() -> Optional[bool]:
            """Return True if the address fields are valid (create any addresses)."""
            for idx, addr in enumerate(
                [self.packet[i : i + 9] for i in range(11, 32, 10)]
            ):
                self.addrs[idx] = Address(id=addr, type=addr[:2])

            # This check will invalidate these rare pkts (which are never transmitted)
            # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF02FF
            # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF0200
            if not all(
                (
                    self.addrs[0].id not in (NON_DEVICE.id, NUL_DEVICE.id),
                    (self.addrs[1].id, self.addrs[2].id).count(NON_DEVICE.id) == 1,
                )
            ) and not all(
                (
                    self.addrs[2].id not in (NON_DEVICE.id, NUL_DEVICE.id),
                    self.addrs[0].id == self.addrs[1].id == NON_DEVICE.id,
                )
            ):
                return False

            device_addrs = list(filter(lambda x: x.type != "--", self.addrs))

            self.src_addr = device_addrs[0]
            self.dst_addr = device_addrs[1] if len(device_addrs) > 1 else NON_DEVICE

            if (
                self.src_addr.id != self.dst_addr.id
                and self.src_addr.type == self.dst_addr.type
            ):
                # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5 (invalid)
                return False

            return len(device_addrs) < 3

        if self._is_valid is not None or not self._pkt_line:
            return self._is_valid

        if self.error_text:  # log all packets with an error
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
        elif not _validate_addresses():
            err_msg = "invalid packet addresses"
        elif int(self.packet[46:49]) > 48:
            err_msg = "excessive payload length"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "mismatched payload length"
        else:  # it is a valid packet
            # TODO: Check that an expected RP arrived for an RQ sent by this library
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

    async def get_pkt(self) -> Tuple[str, str, Optional[bytearray]]:
        """Get the next packet line (dtm, pkt, pkt_bytes) from a serial port."""

        def _logger_msg(func, msg):  # TODO: this is messy...
            try:
                date, time = dtm_str.split("T")
            except ValueError:
                date, time = dt.min.isoformat().split("T")
            extra = {"date": date, "time": time, "_packet": pkt_bytes}
            extra.update({"error_text": "", "comment": ""})
            func("%s < %s", pkt_bytes, msg, extra=extra)

        try:
            pkt_bytes = await self.reader.readline()
        except SerialException:
            return time_stamp(), "", None

        dtm_str = time_stamp()  # done here & now for most-accurate timestamp
        if False and __dev_mode__:
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
        # logger.debug("# Data was sent to %s: %s", self.serial_port, cmd)
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
    # TODO handle badly-formed dt strings - presently, they will crash
    def _logger_msg(func, msg):  # TODO: this is messy...
        # ValueError: not enough values to unpack (expected 2, got 1) [e.g. blank line]
        try:
            date, time = ts_pkt[:26].split("T")
        except ValueError:
            date, time = dt.min.isoformat().split("T")
        extra = {"date": date, "time": time, "_packet": ts_pkt}
        extra.update({"error_text": "", "comment": ""})
        func("%s < %s", ts_pkt.strip(), msg, extra=extra)

    for ts_pkt in fp:
        if ts_pkt.strip() == "":  # handle black lines
            continue
        try:
            assert re.match(ISO_FORMAT_REGEX, ts_pkt[:26])
            dt.fromisoformat(ts_pkt[:26])
        except (AssertionError, ValueError):  # TODO: log these, or not?
            _logger_msg(_LOGGER.debug, "Packet line has invalid timestamp")
            # _LOGGER.debug("Packet line has invalid timestamp: %s", ts_pkt[:26])
            continue

        pkt = Packet(ts_pkt[:26], ts_pkt[27:].strip(), None)
        if pkt.is_valid:
            yield pkt

        await asyncio.sleep(0)  # usu. 0, to enable a Ctrl-C
