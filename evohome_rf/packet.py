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
XONXOFF = True
SERIAL_CONFIG = {"baudrate": BAUDRATE, "xonxoff": XONXOFF}

Pause = SimpleNamespace(
    NONE=timedelta(seconds=0),
    MINIMUM=timedelta(seconds=0.01),
    SHORT=timedelta(seconds=0.05),
    DEFAULT=timedelta(seconds=0.15),
    LONG=timedelta(seconds=0.5),
)

# tx (from sent to gwy, to get back from gwy) seems to takes approx. 0.025s
__version__ = 2
if __version__ == 1:
    QOS_RETRIES = 2
    QOS_TIMEOUT_RQ = timedelta(seconds=0.2)  # 0.2 too low?
    QOS_TIMEOUT_RP = timedelta(seconds=1.0)

else:
    QOS_RETRIES = 2
    QOS_TIMEOUT_RQ = timedelta(seconds=0.05)  # 0.20 OK, but too high?
    QOS_TIMEOUT_RP = timedelta(seconds=0.15)  # 0.05 too low sometimes

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.ERROR)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)

_PKT_LOGGER = logging.getLogger(f"{__name__}-log")
_PKT_LOGGER.setLevel(logging.DEBUG)


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
        elif not validate_addresses():
            err_msg = "invalid packet addresses"
        elif int(self.packet[46:49]) > 48:  # TODO: is 02/I/22C9 > 24?
            err_msg = "excessive payload length"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "mismatched payload length"
        else:
            _PKT_LOGGER.info("%s ", self.packet, extra=self.__dict__)
            return True

        _PKT_LOGGER.warning("%s < Bad packet: %s ", self, err_msg, extra=self.__dict__)
        return False

    @property
    def _header(self) -> Optional[str]:
        """Return the QoS header of this packet."""

        if self.is_valid:
            return _pkt_header(str(self))


async def file_pkts(fp):
    """Yield valid packets from a text stream."""

    for ts_pkt in fp:
        ts_pkt = ts_pkt.strip()
        dtm, pkt = ts_pkt[:26], ts_pkt[27:]
        try:
            # assuming a completely valid log file, asserts allows for -O for inc. speed
            assert DTM_LONG_REGEX.match(dtm)
            dt.fromisoformat(dtm)

        except (AssertionError, TypeError, ValueError):
            if ts_pkt != "" and dtm.strip()[:1] != "#":
                _PKT_LOGGER.warning(
                    "%s < Packet line has an invalid timestamp (ignoring)",
                    ts_pkt,
                    extra=extra(dt_str(), ts_pkt),
                )
            continue

        pkt = Packet(dtm, pkt, None)
        if pkt.is_valid:
            yield pkt

        await asyncio.sleep(0)  # usu. 0, only to enable a Ctrl-C


class GatewayProtocol(asyncio.Protocol):
    """Interface for a packet protocol."""

    def __init__(self, gwy, pkt_handler) -> None:
        _LOGGER.debug("GwyProtocol.__init__()")

        self._gwy = gwy
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
        _LOGGER.debug("GwyProtocol.connection_made(%s)", transport)

        self._transport = transport
        # self._transport.serial.rts = False

    def data_received(self, data: ByteString):
        """Called when some data is received."""
        # _LOGGER.debug("GwyProtocol.data_rcvd(%s)", data)

        def create_pkt(pkt_raw: ByteString) -> Packet:
            dtm_str = dt_str()  # done here & now for most-accurate timestamp
            _LOGGER.debug("GwyProtocol.data_rcvd(%s)", pkt_raw)
            # _PKT_LOGGER.debug("%s < Raw pkt", pkt_raw, extra=extra(dtm_str, pkt_raw))

            try:
                pkt_str = "".join(
                    c
                    for c in pkt_raw.decode("ascii", errors="strict").strip()
                    if c in printable
                )
            except UnicodeDecodeError:
                _PKT_LOGGER.warning(
                    "%s < Bad pkt", pkt_raw, extra=extra(dtm_str, pkt_raw)
                )
                return Packet(dtm_str, "", pkt_raw)

            # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

            return Packet(dtm_str, pkt_str, pkt_raw)

        def qos_data_received() -> Packet:
            _LOGGER.warning(
                "GwyProtocol.data_rcvd(%s): timeout=%s, rq_hdr=%s, rp_hdr=%s, cmd=%s",
                pkt._header,
                self._qos_timeout,
                self._qos_rq_hdr,
                self._qos_rp_hdr,
                self._qos_cmd,
            )
            if self._qos_cmd is not None:
                if pkt._header == self._qos_rq_hdr:
                    _LOGGER.warning("GwyProtocol.Data_rcvd(%s): %s", pkt._header, pkt)
                    self._qos_rq_hdr = None
                    self._qos_timeout = dt.now() + (
                        QOS_TIMEOUT_RP * 2 ** (self._qos_tx_cnt - 1)
                        if __version__ == 2
                        else QOS_TIMEOUT_RP
                    )

                elif pkt._header == self._qos_rp_hdr:
                    _LOGGER.warning("GwyProtocol.dAta_rcvd(%s): %s", pkt._header, pkt)
                    self._qos_lock.acquire()
                    self._qos_cmd = None
                    self._qos_lock.release()

                else:
                    _LOGGER.warning("GwyProtocol.daTa_rcvd(%s): %s", pkt._header, pkt)

            else:
                _LOGGER.warning("GwyProtocol.datA_rcvd(%s): %s", pkt._header, pkt)

        self._recv_buffer += data
        if b"\r\n" in self._recv_buffer:
            lines = self._recv_buffer.split(b"\r\n")
            self._recv_buffer = lines[-1]

            for line in lines[:-1]:
                pkt = create_pkt(line)
                if pkt.is_valid:
                    qos_data_received()
                    self._callback(pkt)

    async def _write_data(self, data: bytearray) -> None:
        """Called when some data is to be sent (not a callaback)."""
        # _LOGGER.debug("GwyProtocol._write_data(%s)", data)  # should be debug

        while self._pause_writing or not self._transport:
            await asyncio.sleep(0.005)

        while self._transport.serial.out_waiting:
            await asyncio.sleep(0.005)

        self._transport.write(data)
        # _LOGGER.warning("GwyProtocol.sent_data(%s)", data)  # should be debug

    async def send_data(self, cmd: Command) -> None:
        """Called when some data is to be sent (not a callaback)."""
        _LOGGER.warning("GwyProtocol.send_data(%s)", cmd)  # should be debug

        while self._qos_cmd is not None:
            await asyncio.sleep(0.005)
            continue

        await self._write_data(bytearray(f"{cmd}\r\n".encode("ascii")))

        self._qos_lock.acquire()
        self._qos_cmd = cmd
        self._qos_lock.release()

        if self._qos_cmd:
            self._qos_rq_hdr = cmd._rq_header  # Could be None
            self._qos_rp_hdr = cmd._rp_header  # Could be None, esp. if RQ hdr is None
            self._qos_retries = cmd.qos.get("retries", QOS_RETRIES)
            self._qos_tx_cnt = 1
            self._qos_timeout = dt.now() + cmd.qos.get("timeout", QOS_TIMEOUT_RQ)

        while self._qos_cmd is not None:
            if self._qos_timeout > dt.now():
                await asyncio.sleep(0.005)
                continue

            if self._qos_tx_cnt > self._qos_retries:
                _LOGGER.warning("GwyProtocol.send_data(%s): expired", self._qos_cmd)
                self._qos_lock.acquire()
                self._qos_cmd = None
                self._qos_lock.release()
                break

            _LOGGER.warning("GwyProtocol.send_data(%s): resending", self._qos_cmd)
            await self._write_data(bytearray(f"{self._qos_cmd}\r\n".encode("ascii")))
            self._qos_tx_cnt += 1
            self._qos_timeout = dt.now() + (
                cmd.qos.get("timeout", QOS_TIMEOUT_RQ)  # * 2 ** self._qos_tx_cnt
                if __version__ == 2
                else cmd.qos.get("timeout", QOS_TIMEOUT_RQ)
            )  # no backoff for RQ, only RP

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""
        _LOGGER.debug("GwyProtocol.connection_lost(%s)", exc)

        if exc is not None:
            pass
        self._transport.loop.stop()  # TODO: what is this for?

    def pause_writing(self) -> None:
        """Called when the transport's buffer goes over the high-water mark."""
        _LOGGER.debug("GwyProtocol.pause_writing()")
        # self._transport.get_write_buffer_size()

        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called when the transport's buffer drains below the low-water mark."""
        _LOGGER.debug("GwyProtocol.resume_writing()")
        # self._transport.get_write_buffer_size()

        self._pause_writing = False
