#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatble Packet processor.

Operates at the pkt layer of: app - msg - pkt - h/w
"""

import asyncio
import logging
import os
import re
import sys
from datetime import datetime as dt
from datetime import timedelta as td
from multiprocessing import Process
from queue import Queue
from string import printable  # ascii_letters, digits
from threading import Lock, Thread
from types import SimpleNamespace
from typing import ByteString, Callable, Generator, Optional, Tuple

from serial import SerialException, serial_for_url
from serial_asyncio import SerialTransport as SerTransportAsync

from .command import (
    ARGS,
    DEAMON,
    FUNC,
    QOS_RX_TIMEOUT,
    QOS_TX_RETRIES,
    QOS_TX_TIMEOUT,
    Command,
)
from .const import HGI_DEVICE_ID, NON_DEVICE_ID, NUL_DEVICE_ID, __dev_mode__
from .exceptions import InvalidPacketError
from .helpers import dt_now
from .packet import Packet
from .protocol import create_protocol_factory
from .schema import SERIAL_CONFIG_SCHEMA
from .version import VERSION

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)  # INFO may have too much detail
if DEV_MODE:  # or True:
    _LOGGER.setLevel(logging.DEBUG)  # should be INFO

BLOCK_LIST = "block_list"
KNOWN_LIST = "known_list"

IS_INITIALIZED = "IS_INITIALIZED"
IS_EVOFW3 = "is_evofw3"
DEVICE_ID = "device_id"

DEFAULT_SERIAL_CONFIG = SERIAL_CONFIG_SCHEMA({})

ERR_MSG_REGEX = re.compile(r"^([0-9A-F]{2}\.)+$")

POLLER_TASK = "poller_task"

_QOS_POLL_INTERVAL = 0.005
_QOS_MAX_BACKOFF = 3

Pause = SimpleNamespace(
    NONE=td(seconds=0),
    MINIMUM=td(seconds=0.01),
    SHORT=td(seconds=0.05),
    DEFAULT=td(seconds=0.15),
    LONG=td(seconds=0.5),
)

VALID_CHARACTERS = printable  # "".join((ascii_letters, digits, ":-<*# "))

# evofw3 commands (as of 0.7.0) include (from cmd.c):
# case 'V':  validCmd = cmd_version( cmd );       break;
# case 'T':  validCmd = cmd_trace( cmd );         break;
# case 'B':  validCmd = cmd_boot( cmd );          break;
# case 'C':  validCmd = cmd_cc1101( cmd );        break;
# case 'F':  validCmd = cmd_cc_tune( cmd );       break;
# case 'E':  validCmd = cmd_eeprom( cmd );        break;
# !F  - indicate autotune status
# !FT - start autotune
# !FS - save autotune


def _str(value: ByteString) -> str:
    try:
        result = "".join(
            c
            for c in value.decode("ascii", errors="strict").strip()
            if c in VALID_CHARACTERS
        )
    except UnicodeDecodeError:
        _LOGGER.warning("%s < Cant decode bytestream (ignoring)", value)
        return ""
    return result


def _normalise(pkt_line: str) -> str:
    """Perform any (transparent) frame-level hacks, as required at (near-)RF layer.

    Goals:
    - ensure an evofw3 provides the exact same output as a HGI80
    - handle 'strange' packets (e.g. I/08:/0008)
    """

    # psuedo-RAMSES-II packets...
    if pkt_line[10:14] in (" 08:", " 31:") and pkt_line[-16:] == "* Checksum error":
        pkt_line = pkt_line[:-17] + " # Checksum error (ignored)"
        _LOGGER.warning("Packet line has been normalised (0x01)")

    return pkt_line.strip()


def _regex_hack(pkt_line: str, regex_filters) -> str:
    """Perform any packet hacks, as configured."""

    for k, v in regex_filters.items():
        try:
            pkt_line = re.sub(k, v, pkt_line)
        except re.error as exc:
            _LOGGER.warning(f"{pkt_line} < issue with regex ({k}, {v}): {exc}")

    return pkt_line


class SerTransportRead(asyncio.ReadTransport):
    """Interface for a packet transport via a dict (saved state) or a file (pkt log)."""

    def __init__(self, loop, protocol, packet_source, extra=None):
        self._loop = loop
        self._protocol = protocol
        self._packets = packet_source
        self._extra = {} if extra is None else extra

        self._protocol.pause_writing()

        self._start()

    def _start(self):
        self._extra[POLLER_TASK] = self._loop.create_task(self._polling_loop())

    async def _polling_loop(self):  # TODO: harden with try
        self._protocol.connection_made(self)

        # hint = "777" if isinstance(self._packets, dict) else "888"
        # dtm_str = dt.fromtimestamp(0).isoformat(sep="T", timespec="microseconds")
        # pkt_line = Command._puzzle(message="loading packets")
        # self._protocol.data_received(f"{dtm_str} {hint} {pkt_line}")  # HACK: 01, below

        if isinstance(self._packets, dict):  # can assume dtm_str is OK
            for dtm_str, pkt_line in self._packets.items():
                self._protocol.data_received(f"{dtm_str} {pkt_line}")
                await asyncio.sleep(0)
        else:
            for dtm_pkt_line in self._packets:  # need to check dtm_str is OK
                self._protocol.data_received(dtm_pkt_line)  # .rstrip())
                await asyncio.sleep(0)

        self._protocol.connection_lost(exc=None)  # EOF


class SerTransportPoll(asyncio.Transport):
    """Interface for a packet transport using polling."""

    MAX_BUFFER_SIZE = 500

    def __init__(self, loop, protocol, ser_instance, extra=None):
        self._loop = loop
        self._protocol = protocol
        self.serial = ser_instance
        self._extra = {} if extra is None else extra

        self._is_closing = None
        self._write_queue = None

        self._start()

    def _start(self):
        self._write_queue = Queue(maxsize=self.MAX_BUFFER_SIZE)
        self._extra[POLLER_TASK] = self._loop.create_task(self._polling_loop())

    async def _polling_loop(self):
        self._protocol.connection_made(self)

        while self.serial.is_open:
            await asyncio.sleep(0.001)

            if self.serial.in_waiting:
                # NOTE: cant use readline(), as it blocks until a newline is received
                self._protocol.data_received(self.serial.read(self.serial.in_waiting))
                continue

            if getattr(self.serial, "out_waiting", False):
                # NOTE: rfc2217 ports have no out_waiting attr!
                continue

            if not self._write_queue.empty():
                self.serial.write(self._write_queue.get())
                self._write_queue.task_done()

        self._protocol.connection_lost(exc=None)

    def write(self, cmd):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it to be sent out
        asynchronously.
        """

        self._write_queue.put_nowait(cmd)


class _SerTransportProc(Process):  # TODO: WIP
    """Interface for a packet transport using a process - WIP."""

    def __init__(self, loop, protocol, ser_port, extra=None):
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

        if DEV_MODE:
            _LOGGER.debug("SerTransProc._start() STARTING loop")
        self._write_queue = Queue(maxsize=200)

        self.serial = serial_for_url(self._ser_port[0], **self._ser_port[1])
        self.serial.timeout = 0

        self._poller = Thread(target=self._polling_loop, daemon=True)
        self._poller.start()

        self._protocol.connection_made(self)

    def _polling_loop(self):
        # asyncio.set_event_loop(self._loop)
        # asyncio.get_running_loop()  # TODO: this fails

        self._protocol.connection_made(self)

        while self.serial.is_open:
            # time.sleep(0.001)

            if self.serial.in_waiting:
                # NOTE: cant use readline(), as it blocks until a newline is received
                self._protocol.data_received(self.serial.read(self.serial.in_waiting))
                continue

            if self.serial and getattr(self.serial, "out_waiting", False):
                # NOTE: rfc2217 ports have no out_waiting attr!
                continue

            if not self._write_queue.empty():
                self.serial.write(self._write_queue.get())
                self._write_queue.task_done()

        self._protocol.connection_lost(exc=None)

    def write(self, cmd):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it to be sent out
        asynchronously.
        """
        # _LOGGER.debug("SerTransProc.write(%s)", cmd)

        self._write_queue.put_nowait(cmd)


class PacketProtocolBase(asyncio.Protocol):
    """Interface for a packet protocol (no Qos).

    ex transport: self.data_received(bytes) -> self._callback(pkt)
    to transport: self.send_data(cmd)       -> self._transport.write(bytes)
    """

    @staticmethod
    def _dt_now():
        return dt_now() if sys.platform == "win32" else dt.now()

    def __init__(self, gwy, pkt_handler: Callable) -> None:
        self._gwy = gwy
        self._loop = gwy._loop
        self._callback = pkt_handler  # Could be None

        self._transport = None
        self._pause_writing = True
        self._recv_buffer = bytes()

        self._prev_pkt = None
        self._this_pkt = None

        self._disable_sending = gwy.config.disable_sending
        self._evofw_flag = gwy.config.evofw_flag

        if gwy.config.enforce_known_list:
            self._exclude = []
            self._include = list(gwy._include.keys())
        else:
            self._exclude = list(gwy._exclude.keys())
            self._include = []
        self._unwanted = []  # not: [NON_DEVICE_ID, NUL_DEVICE_ID]

        self._hgi80 = {
            IS_INITIALIZED: None,
            IS_EVOFW3: None,
            DEVICE_ID: None,
        }

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Called when a connection is made."""
        # _LOGGER.debug("PktProtocol.connection_made(%s)", transport)

        self._transport = transport

        if self._include:  # TODO: here, or in init?
            _LOGGER.info(
                f"Enforcing the {KNOWN_LIST} (as a whitelist): %s", self._include
            )
        elif self._exclude:
            _LOGGER.info(
                f"Enforcing the {BLOCK_LIST} (as a blacklist): %s", self._exclude
            )
        else:
            _LOGGER.warning(
                f"Not using any device filter: using a {KNOWN_LIST} (as a whitelist) "
                "is strongly recommended)"
            )

    # @functools.lru_cache(maxsize=128)  # this will no longer work
    def _is_wanted(self, src_id, dst_id) -> Optional[bool]:
        """Parse the packet, return True if the packet is not to be filtered out.

        An unwanted device_id will 'trump' a whitelited device_id in the same packet
        because there is a significant chance the packet is simply corrupt.
        """

        for dev_id in [d for d in dict.fromkeys((src_id, dst_id))]:
            if dev_id in self._unwanted:
                return

            if dev_id in self._exclude:
                _LOGGER.info(
                    f"Blocking packets with device_id: {dev_id} (is blacklisted), "
                    f"if required, remove it from the {BLOCK_LIST})"
                )
                self._unwanted.append(dev_id)
                return

            if dev_id in self._include or dev_id in (NON_DEVICE_ID, NUL_DEVICE_ID):
                continue

            if dev_id[:2] == "18" and self._hgi80[DEVICE_ID] is None:
                continue

            if dev_id == self._hgi80[DEVICE_ID]:
                if self._include:
                    _LOGGER.warning(
                        f"Allowing packets with device_id: {dev_id} (is gateway), "
                        f"configure the {KNOWN_LIST}/{BLOCK_LIST} as required"
                    )
                    self._include.append(dev_id)  # only time include list is modified
                continue

            if dev_id[:2] == "18" and self._gwy.serial_port:  # dex
                _LOGGER.warning(
                    f"Blocking packets with device_id: {dev_id} (is foreign gateway), "
                    f"configure the {KNOWN_LIST}/{BLOCK_LIST} as required"
                )
                self._unwanted.append(dev_id)
                return

            if self._include:
                _LOGGER.warning(
                    f"Blocking packets with device_id: {dev_id} (is not whitelisted), "
                    f"if required, add it to the {KNOWN_LIST}"
                )
                self._unwanted.append(dev_id)
                return

        return True

    def _pkt_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted packets to the callback."""

        self._this_pkt, self._prev_pkt = pkt, self._this_pkt

        if self._callback and self._is_wanted(pkt.src.id, pkt.dst.id):
            try:
                self._callback(pkt)  # only wanted PKTs to the MSG transport's handler
            except InvalidPacketError as exc:
                _LOGGER.error("%s < %s", pkt, exc)
            # except Exception as exc:  # noqa: E722, broad-except
            except (
                ArithmeticError,  # incl. ZeroDivisionError,
                AssertionError,
                AttributeError,
                IndexError,
                LookupError,  # incl. IndexError, KeyError
                NameError,  # incl. UnboundLocalError
                RuntimeError,  # incl. RecursionError
                TypeError,
                ValueError,
            ) as exc:
                _LOGGER.exception("%s < exception from msg layer: %s", pkt, exc)

    def _line_received(self, dtm: dt, line: str, raw_line: ByteString) -> None:
        if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
            _LOGGER.info("RF Rx: %s", raw_line)

        self._hgi80[IS_INITIALIZED], was_initialized = True, self._hgi80[IS_INITIALIZED]

        try:
            pkt = Packet.from_port(
                self._gwy,
                dtm,
                _regex_hack(line, self._gwy.config.use_regex.get("inbound", {})),
                raw_line=raw_line,
            )

        except InvalidPacketError as exc:
            if "# evofw" in line and self._hgi80[IS_EVOFW3] is None:
                self._hgi80[IS_EVOFW3] = line
                if self._evofw_flag not in (None, "!V"):
                    self._transport.write(
                        bytes(f"{self._evofw_flag}\r\n".encode("ascii"))
                    )
            elif was_initialized and line and line[:1] != "#" and "*" not in line:
                _LOGGER.error("%s < Cant create packet (ignoring): %s", line, exc)
            return

        if pkt.src.type == "18":  # dex: should use HGI, but how?
            if self._hgi80[DEVICE_ID] is None:
                self._hgi80[DEVICE_ID] = pkt.src.id

            elif self._hgi80[DEVICE_ID] != pkt.src.id:
                (_LOGGER.debug if pkt.src.id in self._unwanted else _LOGGER.warning)(
                    f"{pkt} < There appears to be more than one HGI80-compatible device"
                    f" (active gateway: {self._hgi80[DEVICE_ID]}), this is unsupported"
                )

        self._pkt_received(pkt)

    def data_received(self, data: ByteString) -> None:
        """Called when some data (packet fragments) is received (from RF)."""
        # _LOGGER.debug("PacketProtocolBase.data_received(%s)", data.rstrip())

        def _bytes_received(
            data: ByteString,
        ) -> Generator[ByteString, ByteString, None]:
            self._recv_buffer += data
            if b"\r\n" in self._recv_buffer:
                lines = self._recv_buffer.split(b"\r\n")
                self._recv_buffer = lines[-1]
                for line in lines[:-1]:
                    yield self._dt_now(), line

        for dtm, raw_line in _bytes_received(data):
            self._line_received(dtm, _normalise(_str(raw_line)), raw_line)

    async def _send_data(self, data: str) -> None:
        """Send a bytearray to the transport (serial) interface."""

        while self._pause_writing:
            await asyncio.sleep(0.005)

        # while (
        #     self._transport is None
        #     # or self._transport.serial is None  # Shouldn't be required, but is!
        #     or getattr(self._transport.serial, "out_waiting", False)
        # ):
        #     await asyncio.sleep(0.005)

        data = bytes(
            _regex_hack(
                data,
                self._gwy.config.use_regex.get("outbound", {}),
            ).encode("ascii")
        )

        if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
            _LOGGER.info("RF Tx:     %s", data)
        self._transport.write(data + b"\r\n")

        # 0.2: can still exceed RF duty cycle limit with back-to-back restarts
        # await asyncio.sleep(0.2)  # TODO: RF Duty cycle, make configurable?

    async def send_data(self, cmd: Command) -> None:
        """Called when some data is to be sent (not a callback)."""
        # _LOGGER.debug("PktProtocol.send_data(%s)", cmd)

        if self._disable_sending:
            raise RuntimeError("Sending is disabled")

        # if not self._is_wanted(cmd.src, cmd.dst):
        #     _LOGGER.warning(
        #     return

        if cmd.src.id != HGI_DEVICE_ID:
            if self._hgi80[IS_EVOFW3]:
                _LOGGER.info(
                    "Impersonating device: %s, for pkt: %s", cmd.src.id, cmd.tx_header
                )
            else:
                _LOGGER.warning(
                    "Impersonating device: %s, for pkt: %s"
                    ", NB: standard HGI80s dont support this feature, it needs evofw3!",
                    cmd.src.id,
                    cmd.tx_header,
                )
            await self.send_data(Command._puzzle(msg_type="11", message=cmd.tx_header))

        await self._send_data(str(cmd))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""
        _LOGGER.debug("PktProtocol.connection_lost(%s)", exc)
        # serial.serialutil.SerialException: device reports error (poll)

        if exc is not None:
            raise exc

    def pause_writing(self) -> None:
        """Called when the transport's buffer goes over the high-water mark."""
        _LOGGER.debug("PktProtocol.pause_writing()")
        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called when the transport's buffer drains below the low-water mark."""
        _LOGGER.debug("PktProtocol.resume_writing()")
        self._pause_writing = False


class PacketProtocolPort(PacketProtocolBase):
    """Interface for a packet protocol (without QoS)."""

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Called when a connection is made."""
        _LOGGER.info(f"RAMSES_RF protocol library v{VERSION} (serial port)")

        super().connection_made(transport)  # self._transport = transport
        # self._transport.serial.rts = False

        # determine if using a evofw3 rather than a HGI80
        self._transport.write(bytes("!V\r\n".encode("ascii")))

        # add this to start of the pkt log, if any
        if not self._disable_sending:  # TODO: use a callback
            self._loop.create_task(self.send_data(Command._puzzle()))

        self.resume_writing()


class PacketProtocol(PacketProtocolPort):
    """Interface for a packet protocol (without QoS)."""

    def __init__(self, gwy, pkt_handler: Callable) -> None:
        _LOGGER.debug(
            "PktProtocol.__init__(gwy, %s) *** Std version ***",
            pkt_handler.__name__ if pkt_handler else None,
        )
        super().__init__(gwy, pkt_handler)


class PacketProtocolRead(PacketProtocolBase):
    """Interface for a packet protocol (for packet log)."""

    def __init__(self, gwy, pkt_handler: Callable) -> None:
        _LOGGER.debug(
            "PacketProtocolRead.__init__(gwy, %s) *** R/O version ***",
            pkt_handler.__name__ if pkt_handler else None,
        )
        super().__init__(gwy, pkt_handler)

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Called when a connection is made."""
        _LOGGER.info(f"RAMSES_RF protocol library v{VERSION} (packet log)")

        super().connection_made(transport)  # self._transport = transport

    def _line_received(self, dtm: str, line: str, raw_line: str) -> None:

        try:
            pkt = Packet.from_file(
                self._gwy,
                dtm,
                _regex_hack(line, self._gwy.config.use_regex.get("inbound", {})),
            )

        except (InvalidPacketError, ValueError):  # VE from dt.fromisoformat()
            return

        if pkt.src.type == "18" and pkt.src.id != HGI_DEVICE_ID:  # HACK 01: dex
            if self._hgi80[DEVICE_ID] is None:
                self._hgi80[DEVICE_ID] = pkt.src.id

            elif self._hgi80[DEVICE_ID] != pkt.src.id:
                (_LOGGER.debug if pkt.src.id in self._unwanted else _LOGGER.warning)(
                    f"{pkt} < There appears to be more than one HGI80-compatible device"
                    f" (active gateway: {self._hgi80[DEVICE_ID]}), this is unsupported"
                )

        self._pkt_received(pkt)

    def data_received(self, data: str) -> None:
        """Called when a packet line is received (from a log file)."""
        # _LOGGER.debug("PacketProtocolRead.data_received(%s)", data.rstrip())
        self._line_received(data[:26], data[27:].strip(), data)

    def _dt_now(self) -> dt:
        try:
            return self._this_pkt.dtm
        except AttributeError:
            return dt(1970, 1, 1, 1, 0)


class PacketProtocolQos(PacketProtocolPort):
    """Interface for a packet protocol (includes QoS)."""

    def __init__(self, gwy, pkt_handler: Callable) -> None:
        _LOGGER.debug(
            "PktProtocol.__init__(gwy, %s) *** Qos version ***",
            pkt_handler.__name__ if pkt_handler else None,
        )
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

    def _qos_set_cmd(self, cmd) -> None:
        """Set the QoS command for sending, or clear it when sent OK/timed out."""

        self._qos_lock.acquire()
        if cmd and self._qos_cmd:
            raise RuntimeError
        self._qos_cmd = cmd
        self._qos_lock.release()

        self._tx_hdr = cmd.tx_header if cmd else None
        self._rx_hdr = cmd.rx_header if cmd else None  # Could be None, even if cmd

        if cmd:
            self._tx_retries = 0
            self._tx_retry_limit = cmd.qos.get("retries", QOS_TX_RETRIES)

    def _qos_expire_cmd(self, cmd) -> None:
        """Handle an expired cmd, such as invoking its callbacks."""

        if cmd._source_entity:  # HACK - should be using a callback
            cmd._source_entity._qos_function(cmd)

        hdr, callback = cmd.tx_header, cmd.callback
        if callback and not callback.get("expired"):
            # see also: MsgTransport._pkt_receiver()
            _LOGGER.error("PktProtocolQos.send_data(%s): Expired callback", hdr)
            callback[FUNC](False, *callback.get(ARGS, tuple()))
            callback["expired"] = not callback.get(DEAMON, False)  # HACK:

    def _qos_update_timeouts(self) -> None:
        """Update QoS self._timeout_full, self._timeout_half attrs."""

        if not self._qos_cmd:
            raise RuntimeError

        dtm = self._dt_now()

        if self._tx_hdr:
            timeout = QOS_TX_TIMEOUT
        else:
            timeout = self._qos_cmd.qos.get("timeout", QOS_RX_TIMEOUT)
        timeout = min(timeout * 4 ** self._backoff, td(seconds=1))

        self._timeout_full = dtm + timeout * 2
        self._timeout_half = dtm + timeout

    def _pkt_received(self, pkt: Packet) -> None:
        """Called when packets are received (a callback).

        Wraps the relevant function with QoS code.
        """

        self._qos_received(pkt)

        super()._pkt_received(pkt)

    def _qos_received(self, pkt: Packet) -> None:
        """Perform any QoS functions on packets received from the transport."""

        def logger_rcvd(message: str, wanted: Packet = None) -> None:
            # Reserve the use of _LOGGER.info() for RF Tx/Rx logging
            if wanted:
                logger = _LOGGER.warning if DEV_MODE else _LOGGER.debug
            elif message:
                logger = _LOGGER.error if DEV_MODE else _LOGGER.warning
            else:
                logger = _LOGGER.debug if DEV_MODE else _LOGGER.debug
                message = "not wanting any pkt"

            logger(
                "PktProtocolQos.data_rcvd(rcvd=%s): boff=%s, want=%s, tout=%s: %s",
                pkt._hdr or str(pkt),
                self._backoff,
                wanted,
                self._timeout_full.isoformat(timespec="milliseconds"),
                f"QoS: {message}",
            )

        if self._qos_cmd is None:
            wanted, msg = None, None  # = None, "not looking for any pkt"

        elif self._tx_hdr:  # expected an echo of the Tx'd pkt
            wanted, msg = self._tx_hdr, "wanting Tx (RQ) pkt: "

            if pkt._hdr != self._tx_hdr:
                msg += "NOT MATCHED (still waiting for the Tx (RQ) pkt)"
            elif self._rx_hdr:  # is the Tx pkt, and a response *is* expected
                msg += "was MATCHED (now waiting for the corresponding Rx (RP) pkt)"
                self._tx_hdr = None
            else:  # is the Tx pkt, and a response *is not* expected
                msg += "was MATCHED (not wanting a corresponding Rx (RP) pkt, now done)"
                self._qos_set_cmd(None)

        elif self._rx_hdr:  # expecting a Rx to the Tx'd pkt
            wanted, msg = self._rx_hdr, "wanting Rx (RP) pkt: "

            if pkt._hdr == self._rx_hdr:  # is the Rx pkt, is (expected) response
                msg += "was MATCHED (now done)"
                if entity := self._qos_cmd._source_entity:
                    entity._qos_function(self._qos_cmd, reset=True)
                self._qos_set_cmd(None)
            elif pkt._hdr == self._tx_hdr:  # is the Tx pkt, so increase backoff?
                msg += "was MATCHED duplicate Tx (RQ) pkt (now backing off)"
            else:
                msg += "NOT MATCHED (still waiting for the Rx (RP) pkt)"

        else:  # we shouldn't ever reach here!
            wanted, msg = None, f"Woops! cmd = {self._qos_cmd}"
            raise RuntimeError(f"QoS: {msg}")

        logger_rcvd(msg, wanted=wanted)

    async def send_data(self, cmd: Command) -> None:
        """Called when packets are to be sent (not a callback).

        Wraps the relevant function with QoS code.
        """
        # _LOGGER.debug("PktProtocolQos.send_data(%s)", cmd)

        while self._qos_cmd is not None:
            await asyncio.sleep(_QOS_POLL_INTERVAL)

        await super().send_data(cmd)

        return await self._qos_send_data(cmd)

    async def _qos_send_data(self, cmd: Command) -> None:
        """Perform any QoS functions on packets sent to the transport."""

        def logger_send(logger, message: str, wanted: Packet = None) -> None:
            # Reserve the use of _LOGGER.info() for RF Tx/Rx logging
            logger(
                "PktProtocolQos.send_data(sent=%s): boff=%s, want=%s, tout=%s: %s",
                cmd.tx_header,
                self._backoff,
                self._tx_hdr or self._rx_hdr,
                self._timeout_full.isoformat(timespec="milliseconds"),
                f"QoS: {message} ({self._tx_retries}/{self._tx_retry_limit})",
            )

        self._qos_set_cmd(cmd)
        self._qos_update_timeouts()

        while self._qos_cmd is not None:  # until sent (may need re-transmit) or expired
            if self._timeout_full > self._dt_now():
                await asyncio.sleep(_QOS_POLL_INTERVAL)
                continue
            elif not self._qos_cmd.qos.get("disable_backoff", False):
                self._backoff = min(self._backoff + 1, _QOS_MAX_BACKOFF)

            if self._tx_retries < self._tx_retry_limit:
                logger_send(_LOGGER.debug, "TIMED_OUT_ (will retry)")

                self._tx_retries += 1
                self._qos_update_timeouts()

                await self._send_data(str(cmd))

            else:  # if self._tx_retries >= self._tx_retry_limit:
                logger_send(_LOGGER.warning, "IS_EXPIRED (giving up)")

                self._qos_expire_cmd(cmd)
                self._qos_set_cmd(None)
                break

        else:
            logger_send(_LOGGER.debug, "IS_SENT_OK (done)")

            if self._timeout_half >= self._dt_now():
                self._backoff = max(self._backoff - 1, 0)


def create_pkt_stack(
    gwy,
    pkt_callback,
    protocol_factory=None,
    ser_port=None,
    packet_log=None,
    packet_dict=None,
) -> Tuple[asyncio.Protocol, asyncio.Transport]:
    """Utility function to provide a transport to the internal protocol.

    The architecture is: app (client) -> msg -> pkt -> ser (HW interface).

    The msg/pkt interface is via:
     - PktProtocol.data_received           to (pkt_callback) MsgTransport._pkt_receiver
     - MsgTransport.write (pkt_dispatcher) to (pkt_protocol) PktProtocol.send_data
    """

    def _protocol_factory():
        if packet_log or packet_dict is not None:
            return create_protocol_factory(PacketProtocolRead, gwy, pkt_callback)()
        elif gwy.config.disable_sending:  # TODO: assumes we wont change our mind
            return create_protocol_factory(PacketProtocol, gwy, pkt_callback)()
        else:
            return create_protocol_factory(PacketProtocolQos, gwy, pkt_callback)()

    if len([x for x in (packet_dict, packet_log, ser_port) if x is not None]) != 1:
        raise TypeError("port / file / dict should be mutually exclusive")

    pkt_protocol = (protocol_factory or _protocol_factory)()

    if packet_log or packet_dict is not None:  # {} is a processable packet_dict
        pkt_transport = SerTransportRead(
            gwy._loop, pkt_protocol, packet_log or packet_dict
        )
        return (pkt_protocol, pkt_transport)

    ser_config = DEFAULT_SERIAL_CONFIG
    ser_config.update(gwy.config.serial_config)

    # python client.py monitor 'alt:///dev/ttyUSB0?class=PosixPollSerial'
    try:
        ser_instance = serial_for_url(ser_port, **ser_config)
    except SerialException as exc:
        _LOGGER.error("Failed to open %s (config: %s): %s", ser_port, ser_config, exc)
        raise

    try:  # FTDI on Posix/Linux would be a common environment for this library...
        ser_instance.set_low_latency_mode(True)
    except (AttributeError, NotImplementedError, ValueError):  # Wrong OS/Platform/FTDI
        pass

    if any(
        (
            ser_port.startswith("rfc2217:"),
            ser_port.startswith("socket:"),
            os.name == "nt",
        )
    ):
        pkt_transport = SerTransportPoll(gwy._loop, pkt_protocol, ser_instance)
    else:
        pkt_transport = SerTransportAsync(gwy._loop, pkt_protocol, ser_instance)

    return (pkt_protocol, pkt_transport)
