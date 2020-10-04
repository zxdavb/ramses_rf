#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Packet processor."""

import asyncio
from datetime import datetime as dt, timedelta
import logging
from string import printable
from threading import Lock
from types import SimpleNamespace
from typing import ByteString, Optional, Tuple

from serial import SerialException, serial_for_url  # noqa
from serial_asyncio import SerialTransport

from .command import Command, _pkt_header
from .const import (
    DTM_LONG_REGEX,
    MESSAGE_REGEX,
    NON_DEVICE,
    NUL_DEVICE,
    __dev_mode__,
    id_to_address,
)
from .logger import dt_str

BAUDRATE = 115200
READ_TIMEOUT = 0.5
XONXOFF = True

SERIAL_CONFIG = {"baudrate": BAUDRATE, "xonxoff": XONXOFF}

Pause = SimpleNamespace(
    NONE=timedelta(seconds=0),
    MINIMUM=timedelta(seconds=0.01),
    SHORT=timedelta(seconds=0.05),
    DEFAULT=timedelta(seconds=0.15),
    LONG=timedelta(seconds=0.5),
)

# tx (from sent to gwy, to get back from gwy) seems to takes 0.025
DISABLE_QOS_CODE = False
MAX_BUFFER_LEN = 1
MAX_SEND_COUNT = 1
# RETRANS_TIMEOUT = timedelta(seconds=0.03)
# 0.060 gives false +ve for 10E0?
# 0.065 too low when stressed with (e.g.) schedules, log entries
EXPIRY_TIMEOUT = timedelta(seconds=2.0)  # say 0.5


QOS_RETRY_LIMIT = 2
QOS_TIMEOUT_SECS_RQ = timedelta(seconds=0.2)  # 0.2 too low?
QOS_TIMEOUT_SECS_RP = timedelta(seconds=1.0)

_LOGGER = logging.getLogger(__name__)
if True or __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


def extra(dtm, pkt=None):
    _date, _time = dtm[:26].split("T")
    return {
        "date": _date,
        "time": _time,
        "_packet": str(pkt) + " " if pkt else "",
        "error_text": "",
        "comment": "",
    }


def _logger(log_msg, pkt, dtm_now):
    _LOGGER.warning("%s < %s", pkt, log_msg, extra=extra(dtm_now.isoformat(), pkt))


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

        self._pkt_line = pkt
        self._raw_pkt_line = raw_pkt
        self.packet, self.error_text, self.comment = split_pkt_line(pkt)
        self._packet = self.packet + " " if self.packet else ""  # NOTE: hack 4 logging

        self.addrs = [None] * 3
        self.src_addr = self.dst_addr = None

        self._is_valid = None
        self._is_valid = self.is_valid

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return str(self._raw_pkt_line if self._raw_pkt_line else self._pkt_line)

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

        def validate_addresses() -> Optional[bool]:
            """Return True if the address fields are valid (create any addresses)."""
            for idx, addr in enumerate(
                [self.packet[i : i + 9] for i in range(11, 32, 10)]
            ):
                self.addrs[idx] = id_to_address(addr)

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

            if self.src_addr.id == self.dst_addr.id:
                self.src_addr = self.dst_addr
            elif self.src_addr.type == self.dst_addr.type:
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
        elif not validate_addresses():
            err_msg = "invalid packet addresses"
        elif int(self.packet[46:49]) > 48:  # TODO: is 02/I/22C9 > 24?
            err_msg = "excessive payload length"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "mismatched payload length"
        else:  # it is a valid packet
            # TODO: Check that an expected RP arrived for an RQ sent by this library
            return True

        _LOGGER.warning("%s < Bad packet: %s ", self, err_msg, extra=self.__dict__)
        return False

    def is_wanted(self, include: list = None, exclude: list = None) -> bool:
        """Silently drop packets with unwanted (e.g. neighbour's) devices.

        Packets to/from HGI80: are never ignored.
        """

        def is_wanted_pkt() -> bool:
            """Return True is a packet is not to be filtered out."""

            if " 18:" in self.packet:  # NOTE: " 18:", leading space is required
                return True
            if include:
                return any(device in self.packet for device in include)
            if exclude:
                return not any(device in self.packet for device in exclude)
            return True

        if is_wanted_pkt():
            _LOGGER.info("%s ", self.packet, extra=self.__dict__)
            return True
        return False

    @property
    def _header(self) -> Optional[str]:
        """Return the QoS header of this packet."""

        if self.is_valid:
            return _pkt_header(str(self))


async def file_pkts(fp):

    for ts_pkt in fp:
        ts_pkt = ts_pkt.strip()
        if ts_pkt == "":  # ignore blank lines
            continue

        try:
            dtm, pkt = ts_pkt[:26], ts_pkt[27:]
            # assuming a completely valid log file, asserts allows for -O for inc. speed
            assert DTM_LONG_REGEX.match(dtm)
            assert dt.fromisoformat(dtm)

        except (AssertionError, TypeError, ValueError):
            _LOGGER.warning(
                "%s < Packet line has an invalid timestamp (ignoring)",
                ts_pkt,
                extra=extra(dt_str(), ts_pkt),
            )
            continue

        pkt = Packet(dtm, pkt, None)
        if pkt.is_valid:  # and pkt.is_wanted(include=include, exclude=exclude):
            yield pkt

        await asyncio.sleep(0)  # usu. 0, only to enable a Ctrl-C


class SerialProtocol(asyncio.Protocol):
    def __init__(self, queue, pkt_handler) -> None:
        # _LOGGER.debug("SerialProtocol.__init__()")

        self._queue = queue
        self._callback = pkt_handler

        self._transport = None
        self._pause_writing = None
        self._recv_buffer = bytes()

        self._qos_lock = Lock()
        self._qos_cmd = None
        self._qos_rp_hdr = None
        self._qos_rq_hdr = None
        self._qos_timeout = None

    def connection_made(self, transport: SerialTransport) -> None:
        """Called when a connection is made."""

        # _LOGGER.debug("SerialProtocol.connection_made(%s)", transport)
        self._transport = transport
        # self._transport.serial.rts = False

    def data_received(self, data: ByteString):
        """Called when some data is received."""

        # _LOGGER.debug("SerialProtocol.data_received(%s)", data)
        # if b'\n' in data:
        #     self._transport.close()

        def create_pkt(pkt_raw: ByteString) -> Packet:
            dtm_str = dt_str()  # done here & now for most-accurate timestamp
            # _LOGGER.debug("%s < Raw pkt", pkt_raw, extra=extra(dtm_str, pkt_raw))

            try:
                pkt_str = "".join(
                    c
                    for c in pkt_raw.decode("ascii", errors="strict").strip()
                    if c in printable
                )
            except UnicodeDecodeError:
                _LOGGER.warning("%s < Bad pkt", pkt_raw, extra=extra(dtm_str, pkt_raw))
                return Packet(dtm_str, "", pkt_raw)

            # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

            return Packet(dtm_str, pkt_str, pkt_raw)

        def qos_data_received() -> Packet:
            if self._qos_rq_hdr or self._qos_rp_hdr:
                self._qos_lock.acquire()
                if self._qos_rq_hdr == pkt._header:
                    self._qos_rq_hdr = None
                    self._qos_timeout = dt.now() + QOS_TIMEOUT_SECS_RP
                elif self._qos_rp_hdr == pkt._header:
                    self._qos_rp_hdr = None
                    # self._qos_timeout = None
                self._qos_lock.release()

        self._recv_buffer += data
        if b"\r\n" in self._recv_buffer:
            lines = self._recv_buffer.split(b"\r\n")
            self._recv_buffer = lines[-1]

            for line in lines[:-1]:
                pkt = create_pkt(line)
                if pkt.is_valid:
                    self._callback(pkt)
                    qos_data_received()

    async def _write_data(self, data: bytearray) -> None:
        """Called when some data is to be sent (not a callaback)."""

        # _LOGGER.debug("SerialProtocol.send_data(%s)", data)
        while self._pause_writing or not self._transport:
            await asyncio.sleep(0.005)

        while self._transport.serial.out_waiting:
            await asyncio.sleep(0.005)

            # if cmd.verb == " W" or cmd.code in ("0004", "0404", "0418"):
            #     cmd.dtm_timeout = dtm_now + Pause.DEFAULT
            # elif cmd.verb == "RQ":
            #     cmd.dtm_timeout = dtm_now + Pause.SHORT
            # else:
            #     cmd.dtm_timeout = dtm_now + Pause.DEFAULT

        self._transport.write(data)
        # await asyncio.sleep(0.3)  # HACK: until all the other stuff is working

    async def send_data(self, cmd: Command) -> None:
        """Called when some data is to be sent (not a callaback)."""

        while self._qos_rq_hdr or self._qos_rp_hdr:
            await asyncio.sleep(0.005)
            continue

        await self._write_data(bytearray(f"{cmd}\r\n".encode("ascii")))

        self._qos_lock.acquire()
        self._qos_rq_hdr = cmd._rq_header  # Could be None
        self._qos_rp_hdr = cmd._rp_header  # Could be None, esp. if RQ hdr is None
        self._qos_lock.release()

        if self._qos_rq_hdr:
            self._qos_cmd = cmd
            self._qos_retrys = cmd.qos.get("retry_limit", QOS_RETRY_LIMIT)
            self._qos_timeout = dt.now() + QOS_TIMEOUT_SECS_RQ

        while self._qos_rq_hdr or self._qos_rp_hdr:
            if self._qos_timeout > dt.now():
                await asyncio.sleep(0.005)
                continue

            if self._qos_retrys == 0:
                # print("TIMED OUT - EXPIRED!")
                self._qos_lock.acquire()
                self._qos_rq_hdr = self._qos_rp_hdr = None
                self._qos_lock.release()
                break
            # print("TIMED OUT - RETRANSMITTING!")

            await self._write_data(bytearray(f"{self._qos_cmd}\r\n".encode("ascii")))
            self._qos_retrys -= 1
            self._qos_timeout = dt.now() + QOS_TIMEOUT_SECS_RQ

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""

        # _LOGGER.debug("SerialProtocol.connection_lost(%s)", exc)
        if exc is not None:
            pass
        self._transport.loop.stop()

    def pause_writing(self) -> None:
        """Called when the transport's buffer goes over the high-water mark."""

        # _LOGGER.debug("SerialProtocol.pause_writing()")
        print(self._transport.get_write_buffer_size())

        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called when the transport's buffer drains below the low-water mark."""

        # _LOGGER.debug("SerialProtocol.resume_writing()")
        print(self._transport.get_write_buffer_size())

        self._pause_writing = False
