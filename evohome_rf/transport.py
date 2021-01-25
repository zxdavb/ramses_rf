#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - RAMSES-II compatble Packet processor.

Operates at the pkt layer of: app - msg - pkt - h/w
"""

import asyncio
from datetime import datetime as dt, timedelta as td
import logging
from multiprocessing import Process
import os
from queue import Queue
import re
from string import printable
from threading import Thread, Lock
from types import SimpleNamespace
from typing import ByteString, Callable, Optional, Tuple

from serial import serial_for_url  # Serial, SerialException, serial_for_url
from serial_asyncio import SerialTransport as SerialTransportAsync

from .command import Command, Priority
from .const import DTM_LONG_REGEX, HGI_DEVICE, NUL_DEVICE, _dev_mode_
from .helpers import dt_str
from .packet import _PKT_LOGGER, Packet
from .protocol import create_protocol_factory
from .schema import DISABLE_SENDING, ENFORCE_ALLOWLIST, ENFORCE_BLOCKLIST, EVOFW_FLAG
from .version import __version__

DEV_MODE = _dev_mode_ or True

ERR_MSG_REGEX = re.compile(r"^([0-9A-F]{2}\.)+$")

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

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.INFO)  # DEBUG may have too much detail


class SerTransportFile(asyncio.Transport):
    """Interface for a packet transport using a file - Experimental."""

    def __init__(self, loop, protocol, packet_log, extra=None):
        _LOGGER.debug("SerTransFile.__init__() *** PACKET_LOG VERSION ***")

        # self._loop = loop
        self._protocol = protocol
        self.fp = packet_log
        self._extra = {} if extra is None else extra

        self._start()

    def _start(self):
        async def _polling_loop():
            _LOGGER.debug("SerTransFile._polling_loop() BEGUN")
            self._protocol.pause_writing()
            self._protocol.connection_made(self)

            for dtm_pkt_line in self.fp:
                self._protocol.data_received(dtm_pkt_line.strip())
                # await asyncio.sleep(0)

            _LOGGER.debug("SerTransFile._polling_loop() ENDED")
            self._protocol.connection_lost(exc=None)

        _LOGGER.debug("SerTransFile._start()")

        self._extra[POLLER_TASK] = asyncio.create_task(_polling_loop())

    def write(self, cmd):
        """Write some data bytes to the transport."""
        _LOGGER.debug("SerTransFile.write(%s)", cmd)

        raise NotImplementedError


class SerTransportPoller(asyncio.Transport):
    """Interface for a packet transport using polling."""

    MAX_BUFFER_SIZE = 500

    def __init__(self, loop, protocol, ser_instance, extra=None):
        _LOGGER.warning("SerTransPoll.__init__() *** POLLING VERSION ***")

        self._loop = loop
        self._protocol = protocol
        self.serial = ser_instance
        self._extra = {} if extra is None else extra

        self._is_closing = None
        self._write_queue = None

        self._start()

    def _start(self):
        async def _polling_loop():
            _LOGGER.debug("SerTransPoll._polling_loop() BEGUN")
            self._protocol.connection_made(self)

            while self.serial.is_open:
                await asyncio.sleep(0.001)

                if self.serial.in_waiting:
                    self._protocol.data_received(
                        self.serial.read(self.serial.in_waiting)
                    )  # NOTE: cant use readline(), as it blocks until a newline
                    continue

                if self.serial.out_waiting:
                    continue

                if not self._write_queue.empty():
                    self.serial.write(self._write_queue.get())
                    self._write_queue.task_done()
                    continue

            _LOGGER.error("SerTransPoll._polling_loop() ENDED")
            self._protocol.connection_lost()

        _LOGGER.debug("SerTransPoll._start()")
        self._write_queue = Queue(maxsize=self.MAX_BUFFER_SIZE)

        self._extra[POLLER_TASK] = asyncio.create_task(_polling_loop())

    def write(self, cmd):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it to be sent out
        asynchronously.
        """
        _LOGGER.debug("SerTransPoll.write(%s)", cmd)

        self._write_queue.put_nowait(cmd)


class SerTransportProcess(Process):  # TODO: WIP
    """Interface for a packet transport using a process - WIP."""

    def __init__(self, loop, protocol, ser_port, extra=None):
        _LOGGER.warning("SerTransProc.__init__() *** PROCESS VERSION***")

        self._loop = loop
        self._protocol = protocol
        self._ser_port = ser_port
        self._extra = {} if extra is None else extra

        self.serial = None
        self._is_closing = None
        self._poller = None
        self._write_queue = None

        self._start()

    def _start(self):
        def _polling_loop(self):
            _LOGGER.error("WinTransport._polling_loop()")

            # asyncio.set_event_loop(self._loop)
            asyncio.get_running_loop()  # TODO: this fails

            self._protocol.connection_made(self)

            while self.serial.is_open:
                if self.serial.in_waiting:
                    self._protocol.data_received(
                        # self.serial.readline()
                        self.serial.read()
                        # self.serial.read(self.serial.in_waiting)
                    )
                    # time.sleep(0.005)
                    continue

                if self.serial.out_waiting:
                    # time.sleep(0.005)
                    continue

                if not self._write_queue.empty():
                    cmd = self._write_queue.get()
                    self.serial.write(bytearray(f"{cmd}\r\n".encode("ascii")))
                    self._write_queue.task_done()
                    # time.sleep(0.005)
                    continue

                # print("sleep")
                # time.sleep(0.005)

        _LOGGER.debug("SerTransProc.start()")
        self._write_queue = Queue(maxsize=200)

        self.serial = serial_for_url(self._ser_port[0], **self._ser_port[1])
        self.serial.timeout = 0

        self._poller = Thread(target=self._polling_loop, daemon=True)
        self._poller.start()

        self._protocol.connection_made(self)

    def write(self, cmd):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it to be sent out
        asynchronously.
        """
        _LOGGER.debug("SerTransProc.write(%s)", cmd)

        self._write_queue.put_nowait(cmd)


class PacketProtocol(asyncio.Protocol):
    """Interface for a packet protocol (no Qos).

    ex transport: self.data_received(bytes) -> self._callback(pkt)
    to transport: self.send_data(cmd)       -> self._transport.write(bytes)
    """

    def __init__(self, gwy, pkt_receiver: Callable) -> None:
        _LOGGER.debug("PktProtocol.__init__(%s, %s)", gwy, pkt_receiver)

        self._gwy = gwy
        self._callback = pkt_receiver

        self._transport = None
        self._pause_writing = True
        self._recv_buffer = bytes()

        # TODO: this is a little messy...
        self._include = list(gwy._include) if gwy.config[ENFORCE_ALLOWLIST] else []
        self._exclude = list(gwy._exclude) if gwy.config[ENFORCE_BLOCKLIST] else []

        self._has_initialized = None
        if not self._gwy.config[DISABLE_SENDING]:
            asyncio.create_task(self.send_data(INIT_CMD))  # HACK: port wakeup

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Called when a connection is made."""
        _LOGGER.debug("PktProtocol.connection_made(%s)", transport)

        # print(transport.serial)  # TODO: evofw_flag here
        # for attr in dir(transport.serial):
        #     print("obj.%s = %r" % (attr, getattr(transport, attr)))

        # from time import sleep
        # sleep(4)

        # print(transport.serial)  # TODO: evofw_flag here
        # for attr in dir(transport.serial):
        #     print("obj.%s = %r" % (attr, getattr(transport, attr)))

        _PKT_LOGGER.warning(
            "# evohome_rf %s", __version__, extra=self._extra(dt_str(), "")
        )

        self._transport = transport
        # self._transport.serial.rts = False

        self._pause_writing = False  # TODO: needs work

    @staticmethod
    def is_wanted(pkt, include_list, exclude_list) -> bool:
        """Parse the packet, return True if the packet is not to be filtered out."""
        if " 18:" in str(pkt):  # NOTE: " 18:", leading space is required
            return True
        if include_list:
            return any(device in str(pkt) for device in include_list)
        if exclude_list:
            return not any(device in str(pkt) for device in exclude_list)
        return True

    @staticmethod
    def _normalise(pkt_line: str) -> str:
        """Perform any firmware-level hacks, as required.

        Ensure an evofw3 provides the exact same output as a HGI80.
        """

        # bug fixed in evofw3 v0.6.x...
        # 095  I --- 18:013393 18:000730 --:------ 0001 005 00FFFF0200 # HGI80
        # 000  I --- 18:140805 18:140805 --:------ 0001 005 00FFFF0200 # evofw3
        if pkt_line[10:14] == " 18:" and pkt_line[11:20] == pkt_line[21:30]:
            pkt_line = pkt_line[:21] + HGI_DEVICE.id + pkt_line[30:]
            _LOGGER.debug("evofw3 packet line has been normalised (0x00)")

        # non-RAMSES-II packets...
        elif (
            pkt_line[10:14] in (" 08:", " 31:") and pkt_line[-16:] == "* Checksum error"
        ):
            pkt_line = pkt_line[:-17] + " # Checksum error (ignored)"
            # _LOGGER.debug("Packet line has been normalised (0x01)")

        # bug fixed in evofw3 v0.6.x...
        elif pkt_line.startswith("!C"):
            pkt_line = "# " + pkt_line
            # _LOGGER.debug("Packet line has been normalised (0x02)")

        # old packet logs
        elif ERR_MSG_REGEX.match(pkt_line):
            pkt_line = "# " + pkt_line
            # _LOGGER.debug("Packet line has been normalised (0x03)")

        return pkt_line

    def _data_received(  # sans QoS
        self, pkt_dtm: str, pkt_str: Optional[str], pkt_raw: Optional[ByteString] = None
    ) -> None:
        """Called when some normalised data is received (no QoS)."""

        pkt = Packet(pkt_dtm, pkt_str, raw_pkt_line=pkt_raw)
        if not pkt.is_valid:
            return
        elif self._has_initialized is None:
            self._has_initialized = True

        if self.is_wanted(pkt, self._include, self._exclude):
            self._callback(pkt)  # only wanted PKTs up to the MSG transport's handler

    def data_received(self, data: ByteString) -> None:
        """Called when some data is received."""
        _LOGGER.debug("PktProtocol.data_received(%s)", data)

        def create_pkt(pkt_raw: ByteString) -> Tuple:
            dtm_str = dt_str()  # done here & now for most-accurate timestamp

            try:
                pkt_str = "".join(
                    c
                    for c in pkt_raw.decode("ascii", errors="strict").strip()
                    if c in printable
                )
            except UnicodeDecodeError:
                _PKT_LOGGER.warning(
                    "%s < Bad pkt", pkt_raw, extra=self._extra(dtm_str, pkt_raw)
                )
                return dtm_str, None, pkt_raw

            if (  # "# evofw3" in pkt_str
                "# evofw3" in pkt_str
                and self._gwy.config[EVOFW_FLAG]
                and self._gwy.config[EVOFW_FLAG] != "!V"
            ):
                flag = self._gwy.config[EVOFW_FLAG]
                data = bytes(f"{flag}\r\n".encode("ascii"))
                asyncio.create_task(self._send_data(data, ignore_pause=True))

            _PKT_LOGGER.debug("Rx: %s", pkt_raw, extra=self._extra(dtm_str, pkt_raw))

            return dtm_str, self._normalise(pkt_str), pkt_raw

        self._recv_buffer += data
        if b"\r\n" in self._recv_buffer:
            lines = self._recv_buffer.split(b"\r\n")
            self._recv_buffer = lines[-1]

            for line in lines[:-1]:
                self._data_received(*create_pkt(line))

    async def _send_data(self, data: ByteString, ignore_pause=False) -> None:
        """Send a bytearray to the transport (serial) interface.

        The _pause_writing flag can be ignored, is useful for sending traceflags.
        """
        if not ignore_pause:
            while self._pause_writing:
                await asyncio.sleep(0.005)
        while self._transport is None or self._transport.serial.out_waiting:
            await asyncio.sleep(0.005)
        _PKT_LOGGER.debug("Tx:     %s", data, extra=self._extra(dt_str(), data))
        self._transport.write(data)
        # await asyncio.sleep(0.05)

    async def send_data(self, cmd: Command) -> None:
        """Called when some data is to be sent (not a callback)."""
        _LOGGER.debug("PktProtocol.send_data(%s)", cmd)

        if self._gwy.config[DISABLE_SENDING]:
            raise RuntimeError("Sending is disabled")

        if not cmd.is_valid:
            _LOGGER.warning(
                "PktProtocol.send_data(%s): invalid command: %s", cmd.tx_header, cmd
            )
            return

        await self._send_data(bytes(f"{cmd}\r\n".encode("ascii")))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""
        _LOGGER.debug("PktProtocol.connection_lost(%s)", exc)

        if exc is not None:
            pass

    def pause_writing(self) -> None:
        """Called when the transport's buffer goes over the high-water mark."""
        _LOGGER.debug("PktProtocol.pause_writing()")
        # self._transport.get_write_buffer_size()

        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called when the transport's buffer drains below the low-water mark."""
        _LOGGER.debug("PktProtocol.resume_writing()")
        # self._transport.get_write_buffer_size()

        self._pause_writing = False

    @staticmethod
    def _extra(dtm, pkt=None) -> dict:  # HACK: untidy: needs sorting, eventually
        """Create the dict required for logging"""
        _date, _time = dtm[:26].split("T")
        return {
            "date": _date,
            "time": _time,
            "_packet": str(pkt) + " " if pkt else "",
            "error_text": "",
            "comment": "",
        }


class PacketProtocolFile(PacketProtocol):
    """Interface for a packet protocol (for packet log)."""

    def data_received(self, data: str) -> None:
        """Called when some data is received."""
        _LOGGER.debug("PktProtocolFile.data_received(%s)", data)

        pkt_dtm, pkt_str = data[:26], data[27:]

        try:
            assert DTM_LONG_REGEX.match(pkt_dtm)
            dt.fromisoformat(pkt_dtm)

        except (AssertionError, TypeError, ValueError):
            if data != "" and pkt_dtm.strip()[:1] != "#":
                _PKT_LOGGER.debug(
                    "%s < Packet line has an invalid timestamp (ignoring)",
                    data,  # TODO: None?
                    extra=self._extra(dt_str(), data),
                )

        else:
            self._data_received(pkt_dtm, self._normalise(pkt_str), None)


class PacketProtocolQos(PacketProtocol):
    """Interface for a packet protocol (includes QoS)."""

    def __init__(self, gwy, pkt_handler: Callable) -> None:
        super().__init__(gwy, pkt_handler)

        self._qos_lock = Lock()
        self._qos_cmd = None
        self._tx_hdr = None
        self._rx_hdr = None
        self._tx_retries = None
        self._tx_retry_limit = None

        self._backoff = 0
        self._timeout_full = None
        self._timeout_half = None

    def _timeouts(self, dtm: dt) -> Tuple[dt, dt]:
        if self._qos_cmd:
            if self._tx_hdr:
                timeout = QOS_TX_TIMEOUT
            else:
                timeout = self._qos_cmd.qos.get("timeout", QOS_RX_TIMEOUT)
            self._timeout_full = dtm + timeout * 2 ** self._backoff
            self._timeout_half = dtm + timeout * 2 ** (self._backoff - 1)

        # if self._timeout_half >= dtm:
        #     self._backoff = max(self._backoff - 1, 0)
        # if self._timeout_full >= dtm:
        #     self._backoff = min(self._backoff + 1, QOS_MAX_BACKOFF)

        # _LOGGER.debug("%s %s %s", self._backoff, timeout, self._timeout_full)

    def _data_received(  # with Qos
        self, pkt_dtm: str, pkt_str: Optional[str], pkt_raw: Optional[ByteString] = None
    ) -> None:
        """Called when some data is received. Adjust backoff as required."""

        def _logger_rcvd(logger, msg: str) -> None:
            if self._qos_cmd is None:
                wanted = None
            elif self._tx_hdr:
                wanted = self._tx_hdr
            else:
                wanted = self._rx_hdr

            logger(
                "PktProtocol.data_rcvd(%s): boff=%s, want=%s, tout=%s: %s",
                pkt._header,
                self._backoff,
                wanted,
                self._timeout_full,
                msg,
            )

        pkt = Packet(pkt_dtm, pkt_str, raw_pkt_line=pkt_raw)
        if not pkt.is_valid:
            return
        elif self._has_initialized is None:
            self._has_initialized = True

        if self._qos_cmd:
            # _logger_rcvd(_LOGGER.debug, "CHECKING")

            if pkt._header == self._tx_hdr and self._rx_hdr is None:  # echo of tx pkt
                msg = "matched Tx (now done)"  # no response is expected
                self._qos_lock.acquire()
                self._qos_cmd = None
                self._qos_lock.release()

            elif pkt._header == self._tx_hdr:  # echo of (expected) tx pkt
                msg = "matched Tx (now wanting Rx)"
                self._tx_hdr = None

            elif pkt._header == self._rx_hdr:  # rcpt of (expected) rx pkt
                msg = "matched Rx (now done)"
                self._qos_lock.acquire()
                self._qos_cmd = None
                self._qos_lock.release()

            elif pkt._header == self._qos_cmd.tx_header:  # rcpt of (duplicate!) rx pkt
                msg = "duplicated Tx (still wanting Rx)"
                self._timeouts(dt.now())  # TODO: increase backoff?

            else:  # not the packet that was expected
                msg = "unmatched (still wanting " + ("Tx)" if self._tx_hdr else "Rx)")

            self._timeouts(dt.now())
            _logger_rcvd(_LOGGER.debug, f"CHECKED - {msg}")

        else:  # throttle down the backoff
            # self._timeouts(dt.now())
            _logger_rcvd(_LOGGER.debug, "XXXXXXX - ")

        if self.is_wanted(pkt, self._include, self._exclude):
            self._callback(pkt)  # only wanted PKTs up to the MSG transport's handler

    async def send_data(self, cmd: Command) -> None:
        """Called when some data is to be sent (not a callback)."""
        _LOGGER.debug("PktProtocolQos.send_data(%s)", cmd)

        def _logger_send(logger, msg: str) -> None:
            logger(
                "PktProtocol.send_data(%s): boff=%s, want=%s, tout=%s: %s",
                cmd.tx_header,
                self._backoff,
                self._tx_hdr if self._tx_hdr else self._rx_hdr,
                self._timeout_full,
                msg,
            )

        if self._gwy.config[DISABLE_SENDING]:
            raise RuntimeError("Sending is disabled")

        if not cmd.is_valid:
            _LOGGER.warning(
                "PktProtocol.send_data(%s): invalid command: %s", cmd.tx_header, cmd
            )
            return

        # _logger_send(_LOGGER.debug, "SENDING")

        while self._qos_cmd is not None:
            await asyncio.sleep(0.005)

        self._qos_lock.acquire()
        self._qos_cmd = cmd
        self._qos_lock.release()
        self._tx_hdr = cmd.tx_header
        self._rx_hdr = cmd.rx_header  # Could be None
        self._tx_retries = 0
        self._tx_retry_limit = cmd.qos.get("retries", QOS_TX_RETRIES)

        self._timeouts(dt.now())
        await self._send_data(bytes(f"{cmd}\r\n".encode("ascii")))

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
                await self._send_data(bytes(f"{cmd}\r\n".encode("ascii")))
                _logger_send(
                    _LOGGER.warning,
                    f"RE-SENT ({self._tx_retries}/{self._tx_retry_limit})"
                )

            else:
                if self._qos_cmd.code != "7FFF":  # HACK: why expired when shouldn't
                    _logger_send(_LOGGER.error, "EXPIRED")
                self._qos_lock.acquire()
                self._qos_cmd = None
                self._qos_lock.release()
                self._backoff = 0  # TODO: need a better system
                break

        else:
            if self._timeout_half >= dt.now():
                self._backoff = max(self._backoff - 1, 0)
            # _logger_send(_LOGGER.debug, "SUCCEEDED")


def create_pkt_stack(
    gwy, msg_handler, protocol_factory=None, serial_port=None, packet_log=None
) -> Tuple[asyncio.Protocol, asyncio.Transport]:
    """Utility function to provide a transport to the internal protocol.

    The architecture is: app (client) -> msg -> pkt -> ser (HW interface).

    The msg/pkt interface is via:
     - PktProtocol.data_received           to (msg_handler)  MsgTransport._pkt_receiver
     - MsgTransport.write (pkt_dispatcher) to (pkt_protocol) PktProtocol.send_data
    """

    def _protocol_factory():
        if packet_log:
            return create_protocol_factory(PacketProtocolFile, gwy, msg_handler)()
        elif gwy.config[DISABLE_SENDING]:
            return create_protocol_factory(PacketProtocol, gwy, msg_handler)()
        else:
            return create_protocol_factory(PacketProtocolQos, gwy, msg_handler)()

    assert (serial_port is not None and packet_log is None) or (
        serial_port is None and packet_log is not None
    ), "port / file are not mutually exclusive"

    pkt_protocol = protocol_factory() if protocol_factory else _protocol_factory()

    if packet_log:
        pkt_transport = SerTransportFile(gwy._loop, pkt_protocol, packet_log)
        return (pkt_protocol, pkt_transport)

    ser_instance = serial_for_url(serial_port, **SERIAL_CONFIG)
    if os.name == "posix":
        try:
            ser_instance.set_low_latency_mode(True)  # only for FTDI?
        except ValueError:
            pass

    if os.name == "nt":
        pkt_transport = SerTransportPoller(gwy._loop, pkt_protocol, ser_instance)
    else:
        pkt_transport = SerialTransportAsync(gwy._loop, pkt_protocol, ser_instance)

    return (pkt_protocol, pkt_transport)
