#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible Packet processor.

Operates at the pkt layer of: app - msg - pkt - h/w

For ser2net, use the following YAML file with: ser2net -c hgi80.yaml

connection: &con00
  accepter: telnet(rfc2217),tcp,5001
  timeout: 0
  connector: serialdev,/dev/ttyUSB0,115200n81,local
  options:
    max-connections: 3

For socat, see:
  socat -dd pty,raw,echo=0 pty,raw,echo=0
  python client.py monitor /dev/pts/0
  cat packet.log | cut -d ' ' -f 2- | unix2dos > /dev/pts/1
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from collections import deque
from datetime import datetime as dt
from datetime import timedelta as td
from functools import wraps
from io import TextIOWrapper
from queue import Queue
from string import printable  # ascii_letters, digits
from time import perf_counter
from types import SimpleNamespace
from typing import Awaitable, Callable, Iterable, Optional, TextIO, TypeVar

from serial import SerialBase, SerialException, serial_for_url  # type: ignore[import]
from serial_asyncio import SerialTransport as SerTransportAsync  # type: ignore[import]

from .address import HGI_DEV_ADDR, NON_DEV_ADDR, NUL_DEV_ADDR
from .command import Command, Qos

# skipcq: PY-W2000
from .const import DEV_TYPE, DEV_TYPE_MAP, SZ_DEVICE_ID, __dev_mode__
from .exceptions import InvalidPacketError
from .helpers import dt_now
from .packet import Packet
from .protocol import create_protocol_factory
from .schemas import (
    SCH_SERIAL_PORT_CONFIG,
    SZ_BLOCK_LIST,
    SZ_CLASS,
    SZ_INBOUND,
    SZ_KNOWN_LIST,
    SZ_OUTBOUND,
    SZ_USE_REGEX,
)
from .version import VERSION

# TODO: switch dtm from naive to aware
# TODO: https://evohome-hackers.slack.com/archives/C02SYCLATSL/p1646997554178989
# TODO: https://evohome-hackers.slack.com/archives/C02SYCLATSL/p1646998253052939


# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)


DEV_MODE = __dev_mode__ and False  # debug is_wanted, or qos_fx
DEV_HACK_REGEX = False


_LOGGER = logging.getLogger(__name__)
if DEV_MODE:  # or True:
    _LOGGER.setLevel(logging.DEBUG)  # should be INFO


_DEFAULT_USE_REGEX = {
    SZ_INBOUND: {"( 03:.* 03:.* (1060|2389|30C9) 003) ..": "\\1 00"},
    SZ_OUTBOUND: {},
}

TIP = f", configure the {SZ_KNOWN_LIST}/{SZ_BLOCK_LIST} as required"

SZ_FINGERPRINT = "fingerprint"
SZ_IS_EVOFW3 = "is_evofw3"
SZ_KNOWN_HGI = "known_hgi"

ERR_MSG_REGEX = re.compile(r"^([0-9A-F]{2}\.)+$")

SZ_POLLER_TASK = "poller_task"

_MIN_GAP_BETWEEN_WRITES = 0.2  # seconds
_MIN_GAP_BETWEEN_RETRYS = td(seconds=2.0)  # seconds

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


_PacketProtocolT = TypeVar("_PacketProtocolT", bound=asyncio.BaseProtocol)
_PacketTransportT = TypeVar("_PacketTransportT", bound=asyncio.BaseTransport)


def _str(value: bytes) -> str:
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


def _regex_hack(pkt_line: str, regex_filters: dict) -> str:
    """Perform any packet hacks, as configured."""

    if not regex_filters:
        return pkt_line

    result = pkt_line

    for k, v in regex_filters.items():
        try:
            result = re.sub(k, v, result)
        except re.error as exc:
            _LOGGER.warning(f"{pkt_line} < issue with regex ({k}, {v}): {exc}")

    if result != pkt_line and not DEV_HACK_REGEX:
        (_LOGGER.debug if DEV_MODE else _LOGGER.warning)(
            f"{pkt_line} < Changed by use_regex to: {result}"
        )

    return result


sync_cycles: deque = deque()  # used by @avoid_system_syncs / @track_system_syncs


def avoid_system_syncs(fnc: Callable[..., Awaitable]):
    """Take measures to avoid Tx when any controller is doing a sync cycle."""

    DURATION_PKT_GAP = 0.020  # 0.0200 for evohome, or 0.0127 for DTS92
    DURATION_LONG_PKT = 0.022  # time to tx I|2309|048 (or 30C9, or 000A)
    DURATION_SYNC_PKT = 0.010  # time to tx I|1F09|003

    SYNC_WAIT_LONG = (DURATION_PKT_GAP + DURATION_LONG_PKT) * 2
    SYNC_WAIT_SHORT = DURATION_SYNC_PKT
    SYNC_WINDOW_LOWER = td(seconds=SYNC_WAIT_SHORT * 0.8)  # could be * 0
    SYNC_WINDOW_UPPER = SYNC_WINDOW_LOWER + td(seconds=SYNC_WAIT_LONG * 1.2)  #

    times_0 = []  # FIXME: remove

    async def wrapper(*args, **kwargs):
        global sync_cycles  # skipcq: PYL-W0602

        def is_imminent(p):
            """Return True if a sync cycle is imminent."""
            return (
                SYNC_WINDOW_LOWER
                < (p.dtm + td(seconds=int(p.payload[2:6], 16) / 10) - dt_now())
                < SYNC_WINDOW_UPPER
            )

        start = perf_counter()

        # wait for the start of the sync cycle (I|1F09|003, Tx time ~0.009)
        while any(is_imminent(p) for p in sync_cycles):
            await asyncio.sleep(SYNC_WAIT_SHORT)

        # wait for the remainder of sync cycle (I|2309/30C9) to complete
        if (x := perf_counter() - start) > SYNC_WAIT_SHORT:
            await asyncio.sleep(SYNC_WAIT_LONG)
            # FIXME: remove this block
            times_0.append(x)
            _LOGGER.warning(
                f"*** sync cycle stats: {x:.3f}, "
                f"avg: {sum(times_0) / len(times_0):.3f}, "
                f"lower: {min(times_0):.3f}, "
                f"upper: {max(times_0):.3f}, "
                f"times: {[f'{t:.3f}' for t in times_0]}"
            )

        await fnc(*args, **kwargs)

    return wrapper


def track_system_syncs(fnc: Callable):
    """Track/remember the most recent sync cycle for a controller."""

    MAX_SYNCS_TRACKED = 3

    def wrapper(self, pkt: Packet, *args, **kwargs) -> None:
        global sync_cycles

        def is_pending(p):
            """Return True if a sync cycle is still pending (ignores drift)."""
            return p.dtm + td(seconds=int(p.payload[2:6], 16) / 10) > dt_now()

        if pkt.code != Code._1F09 or pkt.verb != I_ or pkt._len != 3:
            return fnc(self, pkt, *args, **kwargs)

        sync_cycles = deque(
            p for p in sync_cycles if p.src != pkt.src and is_pending(p)
        )
        sync_cycles.append(pkt)

        if len(sync_cycles) > MAX_SYNCS_TRACKED:
            sync_cycles.popleft()

        fnc(self, pkt, *args, **kwargs)

    return wrapper


def limit_duty_cycle(max_duty_cycle: float, time_window: int = 60):
    """Limit the Tx rate to the RF duty cycle regulations (e.g. 1% per hour).

    max_duty_cycle: bandwidth available per observation window (%)
    time_window: duration of the sliding observation window (default 60 seconds)
    """

    TX_RATE_AVAIL: int = 38400  # bits per second (deemed)
    FILL_RATE: float = TX_RATE_AVAIL * max_duty_cycle  # bits per second
    BUCKET_CAPACITY: float = FILL_RATE * time_window

    def decorator(fnc: Callable[..., Awaitable]):
        # start with a full bit bucket
        bits_in_bucket: float = BUCKET_CAPACITY
        last_time_bit_added = perf_counter()

        @wraps(fnc)
        async def wrapper(self, packet: str, *args, **kwargs):
            nonlocal bits_in_bucket
            nonlocal last_time_bit_added

            rf_frame_size = 330 + len(packet[46:]) * 10

            # top-up the bit bucket
            elapsed_time = perf_counter() - last_time_bit_added
            bits_in_bucket = min(
                bits_in_bucket + elapsed_time * FILL_RATE, BUCKET_CAPACITY
            )
            last_time_bit_added = perf_counter()

            # if required, wait for the bit bucket to refill (not for SETs/PUTs)
            if bits_in_bucket < rf_frame_size:
                await asyncio.sleep((rf_frame_size - bits_in_bucket) / FILL_RATE)

            # consume the bits from the bit bucket
            try:
                await fnc(self, packet, *args, **kwargs)  # was return ...
            finally:
                bits_in_bucket -= rf_frame_size

        return wrapper

    return decorator


def limit_transmit_rate(max_tokens: float, time_window: int = 60):
    """Limit the Tx rate as # packets per period of time.

    Rate-limits the decorated function locally, for one process (Token Bucket).

    max_tokens: maximum number of calls of function in time_window
    time_window: duration of the sliding observation window (default 60 seconds)
    """
    # thanks, kudos to: Thomas Meschede, license: MIT
    # see: https://gist.github.com/yeus/dff02dce88c6da9073425b5309f524dd

    token_fill_rate: float = max_tokens / time_window

    def decorator(fnc: Callable):
        token_bucket: float = max_tokens  # initialize with max tokens
        last_time_token_added = perf_counter()

        @wraps(fnc)
        async def wrapper(*args, **kwargs):
            nonlocal token_bucket
            nonlocal last_time_token_added

            # top-up the bit bucket
            elapsed = perf_counter() - last_time_token_added
            token_bucket = min(token_bucket + elapsed * token_fill_rate, max_tokens)
            last_time_token_added = perf_counter()

            # if required, wait for a token (not for SETs/PUTs)
            if token_bucket < 1.0:
                await asyncio.sleep((1 - token_bucket) / token_fill_rate)

            # consume one token for every call
            try:
                await fnc(*args, **kwargs)
            finally:
                token_bucket -= 1.0

        return wrapper

    return decorator


class SerTransportBase(asyncio.ReadTransport):
    """Interface for a packet transport."""

    _extra: dict

    def __init__(self, loop, extra=None):
        super().__init__(extra=extra)

        self._loop = loop
        self._extra[SZ_POLLER_TASK] = self._loop.create_task(self._polling_loop())

        # for sig in (signal.SIGINT, signal.SIGTERM):
        #     self._loop.add_signal_handler(sig, self.abort)

        self._is_closing = False

    async def _polling_loop(self):  # TODO: make into a thread, as doing I/O
        # self._protocol.connection_made(self)

        raise NotImplementedError

    def close(self):
        """Close the transport."""

        if self._is_closing:
            return
        self._is_closing = True

        self._protocol.pause_writing()
        if task := self._extra.get(SZ_POLLER_TASK):
            task.cancel()

        self._loop.call_soon(self._protocol.connection_lost, None)

    def is_closing(self) -> bool:
        """Return True if the transport is closing or closed."""
        return self._is_closing


class SerTransportRead(SerTransportBase):
    """Interface for a packet transport via a dict (saved state) or a file (pkt log)."""

    def __init__(self, loop, protocol: PacketProtocolBase, packet_source, extra=None):
        super().__init__(loop, extra=extra)

        self._protocol = protocol
        self._packets = packet_source

        self._protocol.pause_writing()

    async def _polling_loop(self):  # TODO: harden with try
        self._protocol.connection_made(self)

        if isinstance(self._packets, dict):  # can assume dtm_str is OK
            for dtm_str, pkt_line in self._packets.items():
                self._protocol.data_received(f"{dtm_str} {pkt_line}")
                await asyncio.sleep(0)

        elif isinstance(self._packets, TextIOWrapper):
            for dtm_pkt_line in self._packets:  # should check dtm_str is OK
                self._protocol.data_received(dtm_pkt_line)  # .rstrip())
                await asyncio.sleep(0)

        else:
            raise TypeError(f"Wrong type of packet source: {type(self._packets)}")

        self._protocol.connection_lost(None)

    def write(self, *args, **kwargs) -> None:
        raise NotImplementedError


class SerTransportPoll(SerTransportBase):
    """Interface for a packet transport using polling."""

    MAX_BUFFER_SIZE = 500

    def __init__(self, loop, protocol: PacketProtocolBase, ser_instance, extra=None):
        super().__init__(loop, extra=extra)

        self._protocol = protocol
        self.serial = ser_instance

        self._is_closing = None
        self._write_queue: Queue = Queue(maxsize=self.MAX_BUFFER_SIZE)

    async def _polling_loop(self):
        self._protocol.connection_made(self)

        while self.serial.is_open:
            await asyncio.sleep(0.001)

            if self.serial.in_waiting:
                # NOTE: cant use readline(), as it blocks until a newline is received
                self._protocol.data_received(self.serial.read_all())
                continue

            if getattr(self.serial, "out_waiting", 0):
                # NOTE: rfc2217 ports have no out_waiting attr!
                continue

            if not self._write_queue.empty():
                self.serial.write(self._write_queue.get())
                self._write_queue.task_done()

        self._protocol.connection_lost(None)

    def write(self, cmd):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it to be sent out
        asynchronously.
        """

        self._write_queue.put_nowait(cmd)


class PacketProtocolBase(asyncio.Protocol):
    """Interface for a packet protocol (no Qos).

    ex transport: self.data_received(bytes) -> self._callback(pkt)
    to transport: self.send_data(cmd)       -> self._transport.write(bytes)
    """

    def __init__(self, gwy, pkt_handler: Callable) -> None:

        _LOGGER.info(f"RAMSES_RF protocol library v{VERSION}, using {self}")

        self._gwy = gwy
        self._loop = gwy._loop
        self._callback: None | Callable = pkt_handler

        self._transport: asyncio.Transport = None  # type: ignore[assignment]
        self._pause_writing = True
        self._recv_buffer = bytes()

        self._prev_pkt: Packet = None  # type: ignore[assignment]
        self._this_pkt: Packet = None  # type: ignore[assignment]

        self._disable_sending = gwy.config.disable_sending
        self._evofw_flag = getattr(gwy.config, "evofw_flag", None)

        self.enforce_include = gwy.config.enforce_known_list
        self._exclude = list(gwy._exclude.keys())
        self._include = list(gwy._include.keys()) + [NON_DEV_ADDR.id, NUL_DEV_ADDR.id]
        self._unwanted: list = []  # not: [NON_DEV_ADDR.id, NUL_DEV_ADDR.id]

        self._hgi80 = {
            SZ_DEVICE_ID: None,
            SZ_FINGERPRINT: None,
            SZ_IS_EVOFW3: None,
            SZ_KNOWN_HGI: None,
        }  # also: "evofw3_ver"

        if known_hgis := [
            k for k, v in gwy._include.items() if v.get(SZ_CLASS) == DEV_TYPE.HGI
        ]:
            self._hgi80[SZ_KNOWN_HGI] = known_hgis[0]

        self._use_regex = getattr(self._gwy.config, SZ_USE_REGEX, {})

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(enforce_include={self.enforce_include})"

    def __str__(self) -> str:
        return self.__class__.__name__

    def _dt_now(self) -> dt:
        """Return a precise datetime, using the curent dtm."""
        return dt_now()

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        """Called when a connection is made."""
        _LOGGER.debug(f"{self}.connection_made({transport})")

        self._transport = transport

        # self.resume_writing()  # executed in selected sub-classes

        if self.enforce_include:  # TODO: here, or in init?
            _LOGGER.info(
                f"Enforcing the {SZ_KNOWN_LIST} (as a whitelist): %s", self._include
            )
        elif self._exclude:
            _LOGGER.info(
                f"Enforcing the {SZ_BLOCK_LIST} (as a blacklist): %s", self._exclude
            )
        else:
            _LOGGER.warning(
                f"Not using any device filter: using a {SZ_KNOWN_LIST} (as a whitelist) "
                "is strongly recommended)"
            )

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""
        _LOGGER.debug(f"{self}.connection_lost(exc)")
        # serial.serialutil.SerialException: device reports error (poll)

        self.pause_writing()

        if exc is not None:
            raise exc

    def pause_writing(self) -> None:
        """Called when the transport's buffer goes over the high-water mark."""
        _LOGGER.debug(f"{self}.pause_writing()")

        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called when the transport's buffer drains below the low-water mark."""
        _LOGGER.debug(f"{self}.resume_writing()")

        self._pause_writing = False

    def data_received(self, data: bytes) -> None:
        """Called by the transport when some data (packet fragments) is received."""

        def bytes_received(data: bytes) -> Iterable[tuple[dt, bytes]]:
            self._recv_buffer += data
            if b"\r\n" in self._recv_buffer:
                lines = self._recv_buffer.split(b"\r\n")
                self._recv_buffer = lines[-1]
                for line in lines[:-1]:
                    yield self._dt_now(), line

        for dtm, raw_line in bytes_received(data):
            self._line_received(dtm, _normalise(_str(raw_line)), raw_line)

    def _check_set_hgi80(self, pkt: Packet):
        """Check/set (a pkt with) src.type == 18: - is it the HGI, or a foreign HGI?"""

        if pkt.src.id == self._hgi80[SZ_DEVICE_ID]:
            return

        if self._hgi80[SZ_DEVICE_ID]:
            if pkt.verb != RQ:  # HACK: to reduce logspam
                return

            _LOGGER.warning(  # more than one GWY
                f"{pkt} < Appears to be a Foreign gateway: {pkt.src.id} (Active gateway: "
                f"{self._hgi80[SZ_DEVICE_ID]}): this is unsupported{TIP}"
            )

            if pkt.src.id not in self._include and self.enforce_include:
                _LOGGER.info(f"Blacklisting {pkt.src.id} (is Foreign gateway?){TIP}")
                self._unwanted.append(pkt.src.id)
            return

        if pkt.payload == self._hgi80[SZ_FINGERPRINT]:
            self._hgi80[SZ_DEVICE_ID] = pkt.src.id
            _LOGGER.warning(f"{pkt} < Active gateway set to: {pkt.src.id}")

            if pkt.src.id not in self._include:
                _LOGGER.info(f"Whitelisting {pkt.src.id} (is Active gateway){TIP}")
                self._include.append(pkt.src.id)  # NOTE: only time _include is modified
            return

        if pkt.src.id == self._hgi80[SZ_KNOWN_HGI]:
            self._hgi80[SZ_DEVICE_ID] = pkt.src.id
            _LOGGER.warning(f"{pkt} < Active gateway set to: {pkt.src.id}")

    def _line_received(self, dtm: dt, line: str, raw_line: bytes) -> None:

        if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
            _LOGGER.info("RF Rx: %s", raw_line)

        try:
            pkt = Packet.from_port(
                self._gwy,
                dtm,
                _regex_hack(line, self._use_regex.get(SZ_INBOUND, {})),
                raw_line=raw_line,
            )  # should log all? invalid pkts appropriately

        except InvalidPacketError as exc:
            if "# evofw" in line and self._hgi80[SZ_IS_EVOFW3] is None:
                self._hgi80[SZ_IS_EVOFW3] = True
                self._hgi80["evofw3_ver"] = line
                if self._evofw_flag not in (None, "!V"):
                    self._transport.write(
                        bytes(f"{self._evofw_flag}\r\n".encode("ascii"))
                    )
            _LOGGER.debug("%s < Cant create packet (ignoring): %s", line, exc)
            return

        self._pkt_received(pkt)

    def _pkt_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted packets to the callback.

        Called by data_received(bytes) -> line_received(frame) -> pkt_received(pkt).
        """

        self._this_pkt, self._prev_pkt = pkt, self._this_pkt

        if self._callback and self._is_wanted(pkt.src.id, pkt.dst.id):

            if pkt.src.type == DEV_TYPE_MAP.HGI:
                self._check_set_hgi80(pkt)

            try:  # why not call soon?
                self._callback(pkt)  # only wanted PKTs to the MSG transport's handler

            except AssertionError as exc:  # protect from upper-layer callbacks
                _LOGGER.exception("%s < exception from msg layer: %s", pkt, exc)

    def _is_wanted(self, src_id: str, dst_id: str) -> bool:
        """Parse the packet, return True if the packet is not to be filtered out.

        An unwanted device_id will 'trump' a whitelisted device_id in the same packet
        because there is a significant chance that the packet is simply corrupt.
        """

        for dev_id in dict.fromkeys((src_id, dst_id)):
            if dev_id in self._unwanted:  # TODO: remove entries older than (say) 1w/1d
                return False

            if dev_id in self._exclude:
                self._unwanted.append(dev_id)
                return False

            if dev_id in self._include:
                continue  # TODO: or break if not self.enforce_include?

            if not self._hgi80[SZ_KNOWN_HGI] and dev_id[:2] == DEV_TYPE_MAP.HGI:
                continue

            if self.enforce_include:  # TODO: omit if using break?
                return False

        return True

    async def send_data(self, cmd: Command) -> None:
        raise NotImplementedError


class PacketProtocolFile(PacketProtocolBase):
    """Interface for a packet protocol (for packet log)."""

    def __init__(self, gwy, pkt_handler: Callable) -> None:
        super().__init__(gwy, pkt_handler)

        self._dt_str_: str = None  # type: ignore[assignment]

    def _dt_now(self) -> dt:
        """Return a precise datetime, using a packet's dtm field."""

        try:
            return dt.fromisoformat(self._dt_str_)  # always current pkt's dtm
        except (TypeError, ValueError):
            pass

        try:
            return self._this_pkt.dtm  # if above fails, will be previous pkt's dtm
        except AttributeError:
            return dt(1970, 1, 1, 1, 0)

    def data_received(self, data: str) -> None:  # type: ignore[override]
        """Called when a packet line is received (from a log file)."""

        self._dt_str_ = data[:26]  # used for self._dt_now

        self._line_received(data[:26], data[27:].strip(), data)

    def _line_received(self, dtm: str, line: str, raw_line: str) -> None:  # type: ignore[override]

        try:
            pkt = Packet.from_file(
                self._gwy,
                dtm,
                _regex_hack(line, self._use_regex.get(SZ_INBOUND, {})),
            )  # should log all invalid pkts appropriately

        except (InvalidPacketError, ValueError):  # VE from dt.fromisoformat()
            return

        self._pkt_received(pkt)


class PacketProtocolPort(PacketProtocolBase):
    """Interface for a packet protocol (without QoS)."""

    def __init__(self, gwy, pkt_handler: Callable) -> None:
        super().__init__(gwy, pkt_handler)

        self._sem = asyncio.BoundedSemaphore()
        self._leaker = None

    async def _leak_sem(self):
        """Used to enforce a minimum time between calls to `self._transport.write()`."""
        while True:
            await asyncio.sleep(_MIN_GAP_BETWEEN_WRITES)
            try:
                self._sem.release()
            except ValueError:
                pass

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""

        if self._leaker:
            self._leaker.cancel()

        super().connection_lost(exc)

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        """Called when a connection is made."""

        if not self._leaker:
            self._leaker = self._loop.create_task(self._leak_sem())

        super().connection_made(transport)  # self._transport = transport
        # self._transport.serial.rts = False

        self._transport.write(bytes("!V\r\n".encode("ascii")))  # is evofw3 or HGI80?

        # add this to start of the pkt log, if any
        if not self._disable_sending:
            cmd = Command._puzzle()
            self._hgi80[SZ_FINGERPRINT] = cmd.payload
            self._transport.write(bytes(str(cmd), "ascii") + b"\r\n")

        self.resume_writing()

    @track_system_syncs
    def _pkt_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted packets to the callback.

        Called by data_received(bytes) -> line_received(frame) -> pkt_received(pkt).
        """
        super()._pkt_received(pkt)

    async def send_data(self, cmd: Command) -> None:
        """Called when some data is to be sent (not a callback)."""

        if self._disable_sending:
            raise RuntimeError("Sending is disabled")

        if cmd.src.id != HGI_DEV_ADDR.id:
            await self._alert_is_impersonating(cmd)

        await self._send_data(str(cmd))

    async def _alert_is_impersonating(self, cmd: Command) -> None:
        msg = f"Impersonating device: {cmd.src}, for pkt: {cmd.tx_header}"
        if self._hgi80[SZ_IS_EVOFW3]:
            _LOGGER.info(msg)
        else:
            _LOGGER.warning(
                "%s, NB: HGI80s dont support impersonation, it requires evofw3!", msg
            )
        await self.send_data(Command._puzzle(msg_type="11", message=cmd.tx_header))

    @avoid_system_syncs
    @limit_duty_cycle(0.01)  # @limit_transmit_rate(45)
    async def _send_data(self, data: str) -> None:  # NOTE: is also throttled internally
        """Send a bytearray to the transport (serial) interface."""

        while self._pause_writing:
            await asyncio.sleep(0.005)

        # while (
        #     self._transport is None
        #     # or self._transport.serial is None  # Shouldn't be required, but is!
        #     or getattr(self._transport.serial, "out_waiting", False)
        # ):
        #     await asyncio.sleep(0.005)

        data_bytes = bytes(
            _regex_hack(
                data,
                self._use_regex.get(SZ_OUTBOUND, {}),
            ).encode("ascii")
        )

        await self._sem.acquire()  # minimum time between Tx

        if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
            _LOGGER.info("RF Tx:     %s", data_bytes)
        self._transport.write(data_bytes + b"\r\n")


class PacketProtocolQos(PacketProtocolPort):
    """Interface for a packet protocol (includes QoS)."""

    def __init__(self, gwy, pkt_handler: Callable) -> None:
        super().__init__(gwy, pkt_handler)

        # self._qos_lock = Lock()
        self._qos_cmd: None | Command = None
        self._tx_rcvd: None | Packet = None
        self._rx_rcvd: None | Packet = None

    def _pkt_received(self, pkt: Packet) -> None:
        """Called when packets are received (a callback).

        Perform any QoS functions on packets received from the transport.
        """

        if self._qos_cmd:
            if pkt._hdr == self._qos_cmd.tx_header:
                if self._tx_rcvd:
                    err = f"have seen tx_rcvd({self._tx_rcvd}), rx_rcvd={self._rx_rcvd}"
                    (_LOGGER.error if DEV_MODE else _LOGGER.debug)(err)
                self._tx_rcvd = pkt
            elif pkt._hdr == self._qos_cmd.rx_header:
                if self._rx_rcvd:
                    err = f"have seen rx_rcvd({self._rx_rcvd}), tx_rcvd={self._tx_rcvd}"
                    (_LOGGER.error if DEV_MODE else _LOGGER.debug)(err)
                self._rx_rcvd = pkt

        super()._pkt_received(pkt)

    async def send_data(self, cmd: Command) -> Optional[Packet]:  # type: ignore[override]
        """Called when packets are to be sent (not a callback)."""

        if self._disable_sending:
            raise RuntimeError("Sending is disabled")

        if cmd.src.id != HGI_DEV_ADDR.id:
            await self._alert_is_impersonating(cmd)

        def expires(timeout, disable_backoff, retry_count):
            """Return a dtm for expiring the Tx (or Rx), with an optional backoff."""
            if disable_backoff:
                return dt.now() + timeout
            return dt.now() + timeout * 2 ** min(retry_count, Qos.MAX_BACKOFF_FACTOR)

        # self._qos_lock.acquire()
        if self._qos_cmd:
            raise RuntimeError
        self._qos_cmd = cmd
        # self._qos_lock.release()
        self._tx_rcvd = None

        retry_count = 0
        while retry_count <= min(cmd._qos.retry_limit, Qos.RETRY_LIMIT_MAX):  # 5

            self._rx_rcvd = None
            await super()._send_data(str(cmd))

            tx_expires = expires(
                cmd._qos.tx_timeout, cmd._qos.disable_backoff, retry_count
            )
            while tx_expires > dt.now():  # Step 1: wait for Tx to echo
                await asyncio.sleep(Qos.POLL_INTERVAL)
                if self._tx_rcvd or self._rx_rcvd:
                    break
            else:
                retry_count += 1
                continue

            if not cmd._qos.rx_timeout or self._rx_rcvd:  # not expected an Rx
                break

            rx_expires = dt.now() + cmd._qos.rx_timeout
            while rx_expires > dt.now():  # Step 2: wait for Rx to arrive
                await asyncio.sleep(0.001)
                if self._rx_rcvd:
                    break
            else:
                retry_count += 1
                continue

            if self._rx_rcvd:
                break

        else:
            _LOGGER.debug(
                f"PacketProtocolQos.send_data({cmd}) timed out"
                f": tx_rcvd={bool(self._tx_rcvd)} (retry_count={retry_count - 1})"
                f", rx_rcvd={bool(self._rx_rcvd)} (timeout={cmd._qos.rx_timeout})"
            )

        self._qos_cmd = None
        return self._rx_rcvd


def create_pkt_stack(
    gwy,
    pkt_callback: Callable,
    /,
    *,
    protocol_factory: Callable = None,
    port_name: str = None,
    port_config: dict = None,
    packet_log: TextIO = None,
    packet_dict: dict = None,
) -> tuple[_PacketProtocolT, _PacketTransportT]:
    """Utility function to provide a transport to the internal protocol.

    The architecture is: app (client) -> msg -> pkt -> ser (HW interface) / log (file).

    The msg/pkt interface is via:
    - PktProtocol.data_received           to (pkt_callback) MsgTransport._pkt_receiver
    - MsgTransport.write (pkt_dispatcher) to (pkt_protocol) PktProtocol.send_data
    """

    def get_serial_instance(ser_name: str, ser_config: dict) -> SerialBase:

        # For example:
        # - python client.py monitor 'rfc2217://localhost:5001'
        # - python client.py monitor 'alt:///dev/ttyUSB0?class=PosixPollSerial'

        ser_config = SCH_SERIAL_PORT_CONFIG(ser_config or {})

        try:
            ser_obj = serial_for_url(ser_name, **ser_config)
        except SerialException as exc:
            _LOGGER.exception(
                "Failed to open %s (config: %s): %s", ser_name, ser_config, exc
            )
            raise

        try:  # FTDI on Posix/Linux would be a common environment for this library...
            ser_obj.set_low_latency_mode(True)
        except (
            AttributeError,
            NotImplementedError,
            ValueError,
        ):  # Wrong OS/Platform/not FTDI
            pass

        return ser_obj

    def issue_warning() -> None:
        _LOGGER.warning(
            f"{'Windows' if os.name == 'nt' else 'This type of serial interface'} "
            "is not fully supported by this library: "
            "please don't report any Transport/Protocol errors/warnings, "
            "unless they are reproducable with a standard configuration "
            "(e.g. linux with a local serial port)"
        )

    def protocol_factory_() -> type[_PacketProtocolT]:
        if packet_log or packet_dict is not None:
            return create_protocol_factory(PacketProtocolFile, gwy, pkt_callback)()
        elif gwy.config.disable_sending:  # NOTE: assumes we wont change our mind
            return create_protocol_factory(PacketProtocolPort, gwy, pkt_callback)()
        else:
            return create_protocol_factory(
                PacketProtocolQos, gwy, pkt_callback
            )()  # NOTE: should be: PacketProtocolQos, not PacketProtocolPort

    if len([x for x in (packet_dict, packet_log, port_name) if x is not None]) != 1:
        raise TypeError("must have exactly one of: serial port, pkt log or pkt dict")

    pkt_protocol = (protocol_factory or protocol_factory_)()

    if (pkt_source := packet_log or packet_dict) is not None:  # {} is a processable log
        return pkt_protocol, SerTransportRead(gwy._loop, pkt_protocol, pkt_source)

    ser_instance = get_serial_instance(port_name, port_config)

    if os.name == "nt" or ser_instance.portstr[:7] in ("rfc2217", "socket:"):
        issue_warning()
        return pkt_protocol, SerTransportPoll(gwy._loop, pkt_protocol, ser_instance)

    return pkt_protocol, SerTransportAsync(gwy._loop, pkt_protocol, ser_instance)
