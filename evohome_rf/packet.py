#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Packet processor."""

import asyncio
from datetime import datetime as dt, timedelta
import logging
from multiprocessing import Process
from queue import Queue
from string import printable
from threading import Thread, Lock

# import time
from types import SimpleNamespace
from typing import ByteString, Optional, Tuple

from serial import Serial, SerialException, serial_for_url  # noqa
from serial_asyncio import SerialTransport

from .command import Command, Priority, _pkt_header
from .const import (
    DTM_LONG_REGEX,
    MESSAGE_REGEX,
    HGI_DEVICE,
    NUL_DEVICE,
    _dev_mode_,
)
from .helpers import extract_addrs
from .logger import dt_str

SERIAL_CONFIG = {
    "baudrate": 115200,
    "timeout": 0,  # None
    "dsrdtr": False,
    "rtscts": False,
    "xonxoff": False,
}

Pause = SimpleNamespace(
    NONE=timedelta(seconds=0),
    MINIMUM=timedelta(seconds=0.01),
    SHORT=timedelta(seconds=0.05),
    DEFAULT=timedelta(seconds=0.15),
    LONG=timedelta(seconds=0.5),
)

INIT_QOS = {"priority": Priority.ASAP, "retries": 24, "disable_backoff": True}
INIT_CMD = Command(" I", NUL_DEVICE.id, "0001", "00FFFF0200", qos=INIT_QOS)
# INIT_CMD = Command(" I", HGI_DEVICE.id, "0001", "00FFFF0200", qos=INIT_QOS)

# tx (from sent to gwy, to get back from gwy) seems to takes approx. 0.025s
QOS_TX_TIMEOUT = timedelta(seconds=0.05)  # 0.20 OK, but too high?
QOS_TX_RETRIES = 2

QOS_RX_TIMEOUT = timedelta(seconds=0.20)  # 0.10 too low sometimes
QOS_MAX_BACKOFF = 3  # 4 = 16x, is too many?

_PKT_LOGGER = logging.getLogger(f"{__name__}-log")
# _PKT_LOGGER.setLevel(logging.DEBUG)  # can do DEBUG, minimum should be INFO

_LOGGER = logging.getLogger(__name__)
if True or _dev_mode_:
    _LOGGER.setLevel(logging.INFO)


def stream_to_line(func):
    """Convert a stream of bytes to a raw packet."""

    def wrapper(self, data: ByteString, *args, **kwargs) -> Optional[dict]:

        self._recv_buffer += data
        if b"\r\n" in self._recv_buffer:
            lines = self._recv_buffer.split(b"\r\n")
            self._recv_buffer = lines[-1]

            for line in lines[:-1]:
                func(self, line)

    return wrapper


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


def _normalise(pkt_line) -> str:
    """Perform any firmware-level hacks, as required.

    Ensure an evofw3 provides the exact same output as a HGI80.
    """

    # 095  I --- 18:013393 18:000730 --:------ 0001 005 00FFFF0200 # HGI80
    # 000  I --- 18:140805 18:140805 --:------ 0001 005 00FFFF0200 # evofw3
    if pkt_line[10:14] == " 18:" and pkt_line[11:20] == pkt_line[21:30]:
        pkt_line = pkt_line[:21] + HGI_DEVICE.id + pkt_line[30:]
        _LOGGER.debug("evofw3 packet line has been normalised (0x00)")

    elif pkt_line[10:14] in (" 08:", " 31:") and pkt_line[-16:] == "* Checksum error":
        pkt_line = pkt_line[:-17] + " # Checksum error (ignored)"
        # _LOGGER.debug("Packet line has been normalised (0x01)")

    return pkt_line


async def file_pkts(fp):
    """Yield valid packets from a text stream."""

    for dtm_pkt_line in fp:
        dtm_pkt_line = dtm_pkt_line.strip()  # TODO: needed?
        dtm_str, pkt_line = dtm_pkt_line[:26], dtm_pkt_line[27:]

        try:
            # assuming a completely valid log file, asserts allows for -O for inc. speed
            assert DTM_LONG_REGEX.match(dtm_str)
            dt.fromisoformat(dtm_str)

        except (AssertionError, TypeError, ValueError):
            if dtm_pkt_line != "" and dtm_str.strip()[:1] != "#":
                _PKT_LOGGER.error(
                    "%s < Packet line has an invalid timestamp (ignoring)",
                    dtm_pkt_line,
                    extra=extra(dt_str(), dtm_pkt_line),
                )
            continue

        pkt = Packet(dtm_str, _normalise(pkt_line), None)
        if pkt.is_valid:
            yield pkt

        await asyncio.sleep(0)  # usu. 0, only to enable a Ctrl-C


class WinSerTransport(Process):
    """Interface for a packet transport - Experimental."""

    def __init__(self, loop, protocol, ser_port, extra=None):
        _LOGGER.debug("WinTransport.__init__()")

        self._loop = loop
        self._protocol = protocol
        self._ser_port = ser_port
        self._extra = {} if extra is None else extra

        self.serial = None
        self._is_closing = None
        self._poller = None
        self._write_queue = None

        self.start()

    def start(self):
        _LOGGER.debug("WinTransport.start()")
        self._write_queue = Queue(maxsize=200)

        self.serial = serial_for_url(self._ser_port[0], **self._ser_port[1])
        self.serial.timeout = 0

        self._poller = Thread(target=self._polling_loop, daemon=True)
        self._poller.start()

        self._protocol.connection_made(self)

    def _polling_loop(self):
        _LOGGER.error("WinTransport._polling_loop()")

        # asyncio.set_event_loop(self._loop)
        asyncio.get_running_loop()  # TODO: this fails

        self._protocol.connection_made(self)

        while self.serial.is_open:
            if self.serial.in_waiting:
                # print("read")
                self._protocol.data_received(
                    # self.serial.readline()
                    self.serial.read()
                    # self.serial.read(self.serial.in_waiting)
                )
                # time.sleep(0.005)
                continue

            if self.serial.out_waiting:
                # print("wait")
                # time.sleep(0.005)
                continue

            if not self._write_queue.empty():
                print("write")
                cmd = self._write_queue.get()
                self.serial.write(bytearray(f"{cmd}\r\n".encode("ascii")))
                self._write_queue.task_done()
                # time.sleep(0.005)
                continue

            # print("sleep")
            # time.sleep(0.005)

    def write(self, cmd):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it to be sent out
        asynchronously.
        """
        _LOGGER.debug("WinTransport.write(%s)", cmd)

        # self.serial.write(bytearray(f"{cmd}\r\n".encode("ascii")))
        self._write_queue.put_nowait(cmd)


class GatewayProtocol(asyncio.Protocol):
    """Interface for a packet protocol."""

    def __init__(self, gwy, pkt_handler) -> None:
        _LOGGER.debug("GwyProtocol.__init__()")

        self._gwy = gwy
        self._callback = pkt_handler

        self._transport = None
        self._pause_writing = True
        self._recv_buffer = bytes()

        self._qos_lock = Lock()
        self._qos_cmd = None
        self._tx_hdr = None
        self._rx_hdr = None
        self._rx_timeout = None
        self._tx_retries = None
        self._tx_retry_limit = None

        self._backoff = 0
        self._timeout_full = None
        self._timeout_half = None

        if not self._gwy.config["disable_sending"]:
            asyncio.create_task(self.send_data(INIT_CMD))  # HACK: port wakeup

    def connection_made(self, transport: SerialTransport) -> None:
        """Called when a connection is made."""
        _LOGGER.debug("GwyProtocol.connection_made(%s)", transport)

        # print(transport.serial)  # TODO: evofw_flag here
        # for attr in dir(transport.serial):
        #     print("obj.%s = %r" % (attr, getattr(transport, attr)))

        # from time import sleep
        # sleep(4)

        # print(transport.serial)  # TODO: evofw_flag here
        # for attr in dir(transport.serial):
        #     print("obj.%s = %r" % (attr, getattr(transport, attr)))

        self._transport = transport
        self._pause_writing = False  # TODO: needs work

    def _timeouts(self, dtm: dt) -> Tuple[dt, dt]:
        if self._qos_cmd:
            timeout = QOS_TX_TIMEOUT if self._tx_hdr else self._rx_timeout
            self._timeout_full = dtm + timeout * 2 ** self._backoff
            self._timeout_half = dtm + timeout * 2 ** (self._backoff - 1)

        # if self._timeout_half >= dtm:
        #     self._backoff = max(self._backoff - 1, 0)
        # if self._timeout_full >= dtm:
        #     self._backoff = min(self._backoff + 1, QOS_MAX_BACKOFF)

        # _LOGGER.debug("%s %s %s", self._backoff, timeout, self._timeout_full)

    @stream_to_line
    def data_received(self, data: ByteString) -> None:
        """Called when some data is received. Adjust backoff as required."""

        def _logger_rcvd(logger, msg: str) -> None:
            if self._qos_cmd is None:
                wanted = None
            elif self._tx_hdr:
                wanted = self._tx_hdr
            else:
                wanted = self._rx_hdr

            logger(
                "GwyProtocol.data_rcvd(%s): boff=%s, want=%s, tout=%s: %s",
                pkt._header,
                self._backoff,
                wanted,
                self._timeout_full,
                msg,
            )

        def create_pkt(pkt_raw: ByteString) -> Packet:
            dtm_str = dt_str()  # done here & now for most-accurate timestamp

            try:
                pkt_line = "".join(
                    c
                    for c in pkt_raw.decode("ascii", errors="strict").strip()
                    if c in printable
                )
            except UnicodeDecodeError:
                _PKT_LOGGER.warning(
                    "%s < Bad pkt", pkt_raw, extra=extra(dtm_str, pkt_raw)
                )
                return Packet(dtm_str, "", pkt_raw)

            if (
                "# evofw3" in pkt_line
                and self._gwy.config["evofw_flag"]
                and self._gwy.config["evofw_flag"] != "!V"
            ):
                flag = self._gwy.config["evofw_flag"]
                data = bytearray(f"{flag}\r\n".encode("ascii"))
                asyncio.create_task(self._write_data(data, True))

            _PKT_LOGGER.debug("%s < Raw pkt", pkt_raw, extra=extra(dtm_str, pkt_raw))

            return Packet(dtm_str, _normalise(pkt_line), pkt_raw)

        pkt = create_pkt(data)
        if not pkt.is_valid:
            return

        if self._qos_cmd:
            # _logger_rcvd(_LOGGER.debug, "CHECKING")

            if pkt._header == self._tx_hdr and self._rx_hdr is None:
                # the (echo of) the transmited pkt - no response is expected
                msg = "matched Tx (now done)"
                self._qos_cmd = None

            elif pkt._header == self._tx_hdr:
                # the (echo of) the transmited pkt - a response is expected
                msg = "matched Tx (now wanting Rx)"
                self._tx_hdr = None

            elif pkt._header == self._rx_hdr:
                # the response packet that was expected
                msg = "matched Rx (now done)"
                self._qos_cmd = None

            elif pkt._header == self._qos_cmd.tx_header:
                # an (echo of) the transmitted pkt, but had already got one!
                msg = "duplicated Tx (still wanting Rx)"  # TODO: increase backoff?

            else:  # not the packet that was expected
                msg = "unmatched (still wanting " + ("Tx)" if self._tx_hdr else "Rx)")

            self._timeouts(dt.now())
            _logger_rcvd(_LOGGER.debug, f"CHECKED - {msg}")

        # else:  # throttle down the backoff
        #     self._timeouts(dt.now())
        #     _logger_rcvd(_LOGGER.debug, "xxx")

        self._callback(pkt)

    async def _write_data(self, data: bytearray, ignore_pause=False) -> None:
        """Send a bytearray to the transport (serial) interface.

        The _pause_writing flag can be ignored, is useful for sending traceflags.
        """
        if not ignore_pause:
            while self._pause_writing:
                await asyncio.sleep(0.005)
        while self._transport.serial.out_waiting:
            await asyncio.sleep(0.005)
        self._transport.write(data)

    async def send_data(self, cmd: Command) -> None:
        """Called when some data is to be sent (not a callback)."""

        def _logger_send(logger, msg: str) -> None:
            logger(
                "GwyProtocol.send_data(%s): boff=%s, want=%s, tout=%s: %s",
                cmd.tx_header,
                self._backoff,
                self._tx_hdr if self._tx_hdr else self._rx_hdr,
                self._timeout_full,
                msg,
            )

        if self._gwy.config["disable_sending"]:
            raise RuntimeError("Sending is disabled")

        if not cmd.is_valid:
            _LOGGER.warning(
                "GwyProtocol.send_data(%s): invalid command: %s", cmd.tx_header, cmd
            )
            return

        # _logger_send(_LOGGER.debug, "SENDING")

        while self._qos_cmd is not None:
            if self._qos_cmd == cmd:
                print("*** WOOPS ***")
            await asyncio.sleep(0.005)

        self._qos_lock.acquire()
        self._qos_cmd = cmd
        self._qos_lock.release()
        self._tx_hdr = cmd.tx_header
        self._rx_hdr = cmd.rx_header  # Could be None
        self._rx_timeout = cmd.qos.get("timeout", QOS_RX_TIMEOUT)
        self._tx_retries = 0
        self._tx_retry_limit = cmd.qos.get("retries", QOS_TX_RETRIES)

        self._timeouts(dt.now())
        await self._write_data(bytearray(f"{cmd}\r\n".encode("ascii")))
        # _logger_send(_LOGGER.debug, "SENT")

        while self._qos_cmd is not None:  # until sent (may need re-transmit) or expired
            if self._timeout_full > dt.now():
                await asyncio.sleep(0.005)

            elif self._qos_cmd is None:  # can be set to None by data_received
                continue

            elif self._tx_retries < self._tx_retry_limit:
                self._tx_hdr = cmd.tx_header
                self._tx_retries += 1
                if not self._qos_cmd.qos.get("disable_backoff", False):
                    self._backoff = min(self._backoff + 1, QOS_MAX_BACKOFF)
                self._timeouts(dt.now())
                await self._write_data(bytearray(f"{cmd}\r\n".encode("ascii")))
                _logger_send(
                    _LOGGER.info,
                    f"RE-SENT ({self._tx_retries}/{self._tx_retry_limit})",
                )

            else:
                self._qos_cmd = None  # give up
                _logger_send(_LOGGER.info, "EXPIRED")
                self._backoff = 0
                break

        else:
            if self._timeout_half >= dt.now():
                self._backoff = max(self._backoff - 1, 0)
            # _logger_send(_LOGGER.debug, "SUCCEEDED")

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
