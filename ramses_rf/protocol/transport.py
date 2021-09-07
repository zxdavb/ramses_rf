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
    QOS_MAX_BACKOFF,
    QOS_RX_TIMEOUT,
    QOS_TX_RETRIES,
    QOS_TX_TIMEOUT,
    Command,
    Priority,
)
from .const import _PUZZ, HGI_DEVICE_ID, NON_DEVICE_ID, NUL_DEVICE_ID, __dev_mode__
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

Pause = SimpleNamespace(
    NONE=td(seconds=0),
    MINIMUM=td(seconds=0.01),
    SHORT=td(seconds=0.05),
    DEFAULT=td(seconds=0.15),
    LONG=td(seconds=0.5),
)

VALID_CHARACTERS = printable  # "".join((ascii_letters, digits, ":-<*# "))

INIT_QOS = {"priority": Priority.HIGHEST, "retries": 24, "disable_backoff": True}
INIT_CMD = Command._puzzle(message=f"v{VERSION}", **INIT_QOS)

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


def _normalise(pkt_line: str, log_file: bool = False) -> str:
    """Perform any packet line hacks, as required.

    Goals:
     - ensure an evofw3 provides the exact same output as a HGI80
     - handle 'strange' packets (e.g. I/08:/0008)
     - correct any historical design failures (e.g. puzzle packets with an index)
    """

    # bug fixed in evofw3 v0.6.x...
    # 095  I --- 18:013393 18:000730 --:------ 0001 005 00FFFF0200 # HGI80
    # 000  I --- 18:140805 18:140805 --:------ 0001 005 00FFFF0200 # evofw3
    if pkt_line[10:14] == " 18:" and pkt_line[11:20] == pkt_line[21:30]:
        pkt_line = pkt_line[:21] + HGI_DEVICE_ID + pkt_line[30:]
        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)(
            "evofw3 packet line has been normalised (0x00)"
        )

    # psuedo-RAMSES-II packets...
    elif pkt_line[10:14] in (" 08:", " 31:") and pkt_line[-16:] == "* Checksum error":
        pkt_line = pkt_line[:-17] + " # Checksum error (ignored)"
        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)(
            "Packet line has been normalised (0x01)"
        )

    # bug fixed in evofw3 v0.6.x...
    elif pkt_line[:2] == "!C":
        pkt_line = "# " + pkt_line
        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)(
            "Packet line has been normalised (0x02)"
        )

    # # TODO: very old evofw3 - taken out because expensive
    # elif ERR_MSG_REGEX.match(pkt_line):
    #     pkt_line = "# " + pkt_line
    #     (_LOGGER.warning if DEV_MODE else _LOGGER.debug)(
    #         "Packet line has been normalised (0x03)"
    #     )

    if not log_file:
        return pkt_line

    pkt_line = pkt_line.strip()

    # HACK for v0.11.x and earlier - puzzle packets should have no index
    if pkt_line[41:45] == _PUZZ and (pkt_line[:2] != "00" or pkt_line[:4] != "0000"):
        payload = f"00{pkt_line[50:]}"[:96]
        pkt_line = pkt_line[:46] + f"{int(len(payload)/2):03} " + payload
        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)(
            "Packet line has been normalised (0x04)"
        )

    return pkt_line


def _str(value: ByteString) -> str:
    try:
        result = "".join(
            c
            for c in value.decode("ascii", errors="strict").strip()
            if c in VALID_CHARACTERS
        )
    except UnicodeDecodeError:
        _LOGGER.warning("%s << Cant decode bytestream (ignoring)", value)
        return ""
    return result


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

    async def _polling_loop(self):
        self._protocol.connection_made(self)

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

            # if hasattr(self.serial, "out_waiting") and self.serial.out_waiting:
            # if getattr(self.serial, "out_waiting", False):
            if self.serial and self.serial.out_waiting:
                continue

            if not self._write_queue.empty():
                self.serial.write(self._write_queue.get())
                self._write_queue.task_done()

        self._protocol.connection_lost()

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

            # time.sleep(0.005)

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

    _dt_now = dt_now if sys.platform == "win32" else dt.now

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
        self._unwanted = []

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

    # @functools.lru_cache(maxsize=128)
    def _is_wanted(self, src_id, dst_id) -> bool:
        """Parse the packet, return True if the packet is not to be filtered out."""
        # pkt_addrs = {src_id, dst_id}
        # if any(d[:2] == "18" for d in pkt_addrs):  # TODO: use HGI's full addr
        #     return True
        # wanted = not self._include or any(d in self._include for d in pkt_addrs)
        # return wanted and all(d not in self._exclude for d in pkt_addrs)

        result = True
        for dev_id in [
            d for d in {src_id, dst_id} if d not in (NON_DEVICE_ID, NUL_DEVICE_ID)
        ]:
            if dev_id in self._unwanted:
                result = False
            elif dev_id[:2] != "18" and self._include and dev_id not in self._include:
                _LOGGER.warning(
                    f"Ignoring a non-allowed device_id: {dev_id}, "
                    f"if required, add it to the {KNOWN_LIST}"
                )
                self._unwanted.append(dev_id)
                result = False
            elif dev_id in self._exclude:
                _LOGGER.warning(
                    f"Ignoring a blocked device_id: {dev_id}, "
                    f"if required, remove it from the {BLOCK_LIST})"
                )
                self._unwanted.append(dev_id)
                result = False
        return result

    def _pkt_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted packets to the callback."""

        # if process_pkt(pkt) is False:
        #     return

        self._this_pkt, self._prev_pkt = pkt, self._this_pkt
        if self._callback and self._is_wanted(pkt.src.id, pkt.dst.id):
            self._callback(pkt)  # only wanted PKTs up to the MSG transport's handler

    def _line_received(self, dtm: dt, line: str, raw_line: ByteString) -> None:
        if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
            _LOGGER.info("RF Rx: %s", raw_line)

        self._hgi80[IS_INITIALIZED], was_initialized = True, self._hgi80[IS_INITIALIZED]

        try:
            pkt = Packet.from_port(self._gwy, dtm, line, raw_line=raw_line)

        except (AssertionError, LookupError, TypeError, ValueError) as exc:
            if DEV_MODE and line and line[:1] != "#" and "*" not in line:
                _LOGGER.exception("%s < Cant create packet (ignoring 1): %s", line, exc)
            return

        except InvalidPacketError as exc:
            if "# evofw" in line and self._hgi80[IS_EVOFW3] is None:
                self._hgi80[IS_EVOFW3] = True
                if self._evofw_flag not in (None, "!V"):
                    self._transport.write(
                        bytes(f"{self._evofw_flag}\r\n".encode("ascii"))
                    )
            elif was_initialized:
                _LOGGER.exception("%s < Cant create packet (ignoring 2): %s", line, exc)
            return

        if pkt.src.type == "18":
            if not self._hgi80[DEVICE_ID]:
                self._hgi80[DEVICE_ID] = pkt.src.id
            elif self._hgi80[DEVICE_ID] != pkt.src.id:
                _LOGGER.error(
                    f"{pkt} < seems to be more than one HGI80-compatible device"
                    f" (another is: {self._hgi80[DEVICE_ID]}), this is unsupported"
                )

        try:
            self._pkt_received(pkt)
        except:  # noqa: E722  # TODO: remove broad-except
            pass

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

    async def _send_data(self, data: str, ignore_pause=False) -> None:
        """Send a bytearray to the transport (serial) interface.

        The _pause_writing flag can be ignored, is useful for sending traceflags.
        """

        if not ignore_pause:
            while self._pause_writing:
                await asyncio.sleep(0.005)
        while (
            self._transport is None
            or self._transport.serial is None  # Shouldn't be required, but is!
            or getattr(self._transport.serial, "out_waiting", False)
        ):
            await asyncio.sleep(0.005)

        data = bytes(data.encode("ascii"))

        if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
            _LOGGER.info("RF Tx:     %s", data)
        self._transport.write(data + b"\r\n")

        # 0.2: can still exceed with back-to-back restarts
        # await asyncio.sleep(0.2)  # TODO: RF Duty cycle, make configurable?

    async def send_data(self, cmd: Command) -> None:
        """Called when some data is to be sent (not a callback)."""
        _LOGGER.debug("PktProtocol.send_data(%s)", cmd)

        if self._disable_sending:
            raise RuntimeError("Sending is disabled")

        if not cmd.is_valid:
            _LOGGER.warning(
                "PktProtocol.send_data(%s): invalid command: %s", cmd.tx_header, cmd
            )
            return

        # if not self._is_wanted(cmd.src, cmd.dst):
        #     # _LOGGER.warning(
        #     return

        if cmd.src.type != "18":
            _LOGGER.info("PktProtocol.send_data(%s): IMPERSONATING!", cmd.tx_header)
            await self._send_data(str(Command._puzzle("02", cmd.tx_header)))

        # self._loop.create_task(self._send_data(str(cmd)))
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

    def __init__(self, gwy, pkt_handler: Callable) -> None:
        super().__init__(gwy, pkt_handler)

        # this needs to be here, and not in connection_made, so that it is 1st
        if not self._disable_sending:
            self._loop.create_task(self.send_data(INIT_CMD))  # HACK: port wakeup

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Called when a connection is made."""
        _LOGGER.info(f"RAMSES_RF protocol library v{VERSION} (serial port)")

        super().connection_made(transport)  # self._transport = transport
        # self._transport.serial.rts = False

        # Used to see if using a evofw3 rather than a HGI80
        self._transport.write(bytes("!V\r\n".encode("ascii")))
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

        self._hgi80[IS_INITIALIZED] = True

        try:
            pkt = Packet.from_file(self._gwy, dtm, line)

        except (AssertionError, LookupError, TypeError, ValueError) as exc:
            if (
                line
                and line[:1] != "#"
                and "*" not in line
                and (dtm and dtm.lstrip()[:1] != "#")
            ):
                _LOGGER.error("%s < Cant create packet (ignoring): %s", line, exc)
            return

        except InvalidPacketError:
            return

        try:
            self._pkt_received(pkt)
        except:  # noqa: E722  # TODO: remove broad-except
            pass

    def data_received(self, data: str) -> None:
        """Called when a packet line is received (from a log file)."""
        # _LOGGER.debug("PacketProtocolRead.data_received(%s)", data.rstrip())
        self._line_received(data[:26], _normalise(data[27:], log_file=True), data)

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

    def _timeouts(self, dtm: dt) -> Tuple[dt, dt]:
        """Update self._timeout_full, self._timeout_half"""
        if self._qos_cmd:
            if self._tx_hdr:
                timeout = QOS_TX_TIMEOUT
            else:
                timeout = self._qos_cmd.qos.get("timeout", QOS_RX_TIMEOUT)
            self._timeout_full = dtm + timeout * 2 ** self._backoff
            self._timeout_half = dtm + timeout * 2 ** (self._backoff - 1)

            # _LOGGER.debug(
            #     "backoff=%s, timeout=%s, timeout_full=%s",
            #     self._backoff,
            #     timeout,
            #     self._timeout_full.isoformat(timespec="milliseconds"),
            # )

        # if self._timeout_half >= dtm:
        #     self._backoff = max(self._backoff - 1, 0)
        # if self._timeout_full >= dtm:
        #     self._backoff = min(self._backoff + 1, QOS_MAX_BACKOFF)

    def _pkt_received(self, pkt: Packet) -> None:
        """Perform any QoS functions before processing valid/wanted packets."""

        def _logger_rcvd(logger, message: str) -> None:
            if self._qos_cmd is None:
                wanted = None
            elif self._tx_hdr:
                wanted = self._tx_hdr
            else:
                wanted = self._rx_hdr

            logger(
                "PktProtocolQos.data_rcvd(rcvd=%s): boff=%s, want=%s, tout=%s: %s",
                pkt._hdr or str(pkt),
                self._backoff,
                wanted,
                self._timeout_full.isoformat(timespec="milliseconds"),
                message,
            )

        if self._qos_cmd:
            _logger_rcvd(_LOGGER.debug, "CHECKING")

            # NOTE: is the Tx pkt, and no response is expected
            if pkt._hdr == self._tx_hdr and self._rx_hdr is None:
                log_msg = "matched the Tx pkt (not wanting a Rx pkt) - now done"
                self._qos_lock.acquire()
                self._qos_cmd = None
                self._qos_lock.release()

            # NOTE: is the Tx pkt, and a response *is* expected
            elif pkt._hdr == self._tx_hdr:
                # assert str(pkt)[4:] == str(self._qos_cmd), "Packets dont match"
                log_msg = "matched the Tx pkt (now wanting a Rx pkt)"
                self._tx_hdr = None

            # NOTE: is the Tx pkt, but is a *duplicate* - we've already seen it!
            elif pkt._hdr == self._qos_cmd.tx_header:
                # assert str(pkt) == str(self._qos_cmd), "Packets dont match"
                log_msg = "duplicated Tx pkt (still wanting the Rx pkt)"
                self._timeouts(dt.now())  # TODO: increase backoff?

            # NOTE: is the Rx pkt, and is a non-Null (expected) response
            elif pkt._hdr == self._rx_hdr:
                log_msg = "matched the Rx pkt - now done"
                self._qos_lock.acquire()
                self._qos_cmd = None
                self._qos_lock.release()

            # TODO: is the Rx pkt, but is a Null response
            # elif pkt._hdr == self._qos_cmd.null_header:
            #     log_msg = "matched a NULL Rx pkt - now done"
            #     self._qos_lock.acquire()
            #     self._qos_cmd = None
            #     self._qos_lock.release()

            # NOTE: is not the expected pkt, but another pkt
            else:
                log_msg = (
                    "unmatched pkt (still wanting a "
                    + ("Tx" if self._tx_hdr else "Rx")
                    + " pkt)"
                )

            self._timeouts(dt.now())
            _logger_rcvd(_LOGGER.debug, f"CHECKED - {log_msg}")

        else:  # TODO: no outstanding cmd - ?throttle down the backoff
            # self._timeouts(dt.now())
            _logger_rcvd(_LOGGER.debug, "XXXXXXX - ")

        super()._pkt_received(pkt)

    async def send_data(self, cmd: Command) -> None:
        """Called when some data is to be sent (not a callback)."""
        _LOGGER.debug("PktProtocolQos.send_data(%s)", cmd)

        def _logger_send(logger, message: str) -> None:
            logger(
                "PktProtocolQos.send_data(%s): boff=%s, want=%s, tout=%s: %s",
                cmd.tx_header,
                self._backoff,
                self._tx_hdr or self._rx_hdr,
                self._timeout_full.isoformat(timespec="milliseconds"),
                message,
            )

        def _expired_cmd(cmd):
            hdr, callback = cmd.tx_header, cmd.callback
            if callback and not callback.get("expired"):
                # see also: MsgTransport._pkt_receiver()
                _LOGGER.error("PktProtocolQos.send_data(%s): Expired callback", hdr)
                callback[FUNC](False, *callback.get(ARGS, tuple()))
                callback["expired"] = not callback.get(DEAMON, False)  # HACK:

        if self._disable_sending:
            raise RuntimeError("Sending is disabled")

        if not cmd.is_valid:
            _LOGGER.warning(
                "PktProtocolQos.send_data(%s): invalid command: %s", cmd.tx_header, cmd
            )
            return

        # if not self._is_wanted(cmd.src, cmd.dst):
        #     # _LOGGER.warning(
        #     return

        while self._qos_cmd is not None:
            await asyncio.sleep(0.005)

        self._qos_lock.acquire()
        self._qos_cmd = cmd
        self._qos_lock.release()
        self._tx_hdr = cmd.tx_header
        self._rx_hdr = cmd.rx_header  # Could be None
        self._tx_retries = 0
        self._tx_retry_limit = cmd.qos.get("retries", QOS_TX_RETRIES)

        if cmd.src.type != "18":
            _LOGGER.info(
                "PacketProtocolQos.send_data(%s): IMPERSONATING!", cmd.tx_header
            )
            await self._send_data(str(Command._puzzle("02", cmd.tx_header)))

        self._timeouts(dt.now())
        await self._send_data(str(cmd))

        while self._qos_cmd is not None:  # until sent (may need re-transmit) or expired
            await asyncio.sleep(0.005)
            if self._timeout_full > dt.now():
                await asyncio.sleep(0.02)
                # await self._send_data("")

            elif self._qos_cmd is None:  # can be set to None by data_received
                continue

            elif self._tx_retries < self._tx_retry_limit:
                self._tx_hdr = cmd.tx_header
                self._tx_retries += 1
                if not self._qos_cmd.qos.get("disable_backoff", False):
                    self._backoff = min(self._backoff + 1, QOS_MAX_BACKOFF)
                self._timeouts(dt.now())
                await self._send_data(str(cmd))
                _logger_send(
                    (_LOGGER.warning if DEV_MODE else _LOGGER.debug),
                    f"RE-SENT ({self._tx_retries}/{self._tx_retry_limit})",
                )  # TODO: should be debug

            else:
                if self._qos_cmd.code != _PUZZ:  # HACK: why expired when shouldn't
                    _logger_send(
                        _LOGGER.warning,
                        f"EXPIRED ({self._tx_retries}/{self._tx_retry_limit})",
                    )
                    _expired_cmd(self._qos_cmd)

                self._qos_lock.acquire()
                self._qos_cmd = None
                self._qos_lock.release()
                self._backoff = 0  # TODO: need a better system
                break

        else:
            if self._timeout_half >= self._dt_now():
                self._backoff = max(self._backoff - 1, 0)
            _logger_send(_LOGGER.debug, "SENT OK")


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
        if packet_dict or packet_log:
            return create_protocol_factory(PacketProtocolRead, gwy, pkt_callback)()
        elif gwy.config.disable_sending:
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
    except SerialException as err:
        _LOGGER.error("Failed to open %s (config: %s): %s", ser_port, ser_config, err)
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
