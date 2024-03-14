#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible packet transport.

Operates at the pkt layer of: app - msg - pkt - h/w

For ser2net, use the following YAML with: ser2net -c misc/ser2net.yaml
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

For re-flashing evofw3 via Arduino IDE on *my* atmega328p (YMMV):
 - Board:      atmega328p (SW UART)
 - Bootloader: Old Bootloader
 - Processor:  atmega328p (5V, 16 MHz)
 - Host:       57600 (or 115200, YMMV)
 - Pinout:     Nano

For re-flashing evofw3 via Arduino IDE on *my* atmega32u4 (YMMV):
 - Board:      atmega32u4 (HW UART)
 - Processor:  atmega32u4 (5V, 16 MHz)
 - Pinout:     Pro Micro
"""

# TODO:
# - add auto-detection of evofw3/HGI80
# - chase down gwy.config.disable_discovery
# - chase down / check deprecation

from __future__ import annotations

import asyncio
import functools
import glob
import json
import logging
import os
import re
import sys
from collections import deque
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime as dt, timedelta as td
from functools import wraps
from io import TextIOWrapper
from string import printable
from time import perf_counter
from typing import TYPE_CHECKING, Any, Final, TypeAlias
from urllib.parse import parse_qs, unquote, urlparse

import serial_asyncio  # type: ignore[import-untyped]
from paho.mqtt import MQTTException, client as mqtt
from serial import (  # type: ignore[import-untyped]
    Serial,
    SerialException,
    serial_for_url,
)

from . import exceptions as exc
from .command import Command
from .const import MINIMUM_GAP_DURATION, SZ_ACTIVE_HGI, SZ_IS_EVOFW3, SZ_SIGNATURE
from .helpers import dt_now
from .packet import Packet
from .schemas import SCH_SERIAL_PORT_CONFIG, SZ_EVOFW_FLAG, SZ_INBOUND, SZ_OUTBOUND
from .typing import ExceptionT, SerPortNameT

from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:
    from .protocol import RamsesProtocolT


_SIGNATURE_MAX_TRYS = 24
_SIGNATURE_GAP_SECS = 0.05


DEV_MODE = False

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

# All debug flags (used for dev/test) should be False for published code
_DBG_DISABLE_DUTY_CYCLE_LIMIT: Final[bool] = False
_DBG_DISABLE_REGEX_WARNINGS = False
_DBG_FORCE_LOG_FRAMES = False

# other constants
_MAX_DUTY_CYCLE = 0.01  # % bandwidth used per cycle (default 60 secs)
_MAX_TOKENS = 45  # #     number of Tx per cycle (default 60 secs)
_CYCLE_DURATION = 60  # # seconds

_GAP_BETWEEN_WRITES: Final[float] = MINIMUM_GAP_DURATION


# For linux, use a modified version of comports() to include /dev/serial/by-id/* links
if os.name == "nt":  # sys.platform == 'win32':
    from serial.tools.list_ports_windows import comports  # type: ignore[import-untyped]

elif os.name != "posix":  # is unsupported
    raise ImportError(
        f"Sorry: no implementation for your platform ('{os.name}') available"
    )

elif sys.platform.lower()[:5] != "linux":  # e.g. osx
    from serial.tools.list_ports_posix import comports  # type: ignore[import-untyped]

else:  # is linux
    # - see: https://github.com/pyserial/pyserial/pull/700
    # - see: https://github.com/pyserial/pyserial/pull/709

    from serial.tools.list_ports_linux import SysFS  # type: ignore[import-untyped]

    def list_links(devices):
        """Search for symlinks to ports already listed in devices."""

        links = []
        for device in glob.glob("/dev/*") + glob.glob("/dev/serial/by-id/*"):
            if os.path.islink(device) and os.path.realpath(device) in devices:
                links.append(device)
        return links

    def comports(
        include_links: bool = False, _hide_subsystems: list[str] | None = None
    ) -> list[SysFS]:
        """Return a list of Serial objects for all known serial ports."""

        if _hide_subsystems is None:
            _hide_subsystems = ["platform"]

        devices = set()
        drivers = open("/proc/tty/drivers").readlines()
        for driver in drivers:
            items = driver.strip().split()
            if items[4] == "serial":
                devices.update(glob.glob(items[1] + "*"))

        if include_links:
            devices.update(list_links(devices))

        return [d for d in map(SysFS, devices) if d.subsystem not in _hide_subsystems]


def is_hgi80(serial_port: SerPortNameT) -> bool | None:
    """Return True/False if the device attached to the port has the attrs of an HGI80.

    Return None if it's not possible to tell (falsy should assume is evofw3).
    Raise TransportSerialError if the port is not found at all.
    """

    if serial_port[:7] == "mqtt://":
        return False  # ramses_esp

    # TODO: add tests for different serial ports, incl./excl/ by-id

    # See: https://github.com/pyserial/pyserial-asyncio/issues/46
    if "://" in serial_port:  # e.g. "rfc2217://localhost:5001"
        try:
            serial_for_url(serial_port, do_not_open=True)
        except (SerialException, ValueError) as err:
            raise exc.TransportSerialError(
                f"Unable to find {serial_port}: {err}"
            ) from err
        return None

    if not os.path.exists(serial_port):
        raise exc.TransportSerialError(f"Unable to find {serial_port}")

    # first, try the easy win...
    if "by-id" not in serial_port:
        pass
    elif "TUSB3410" in serial_port:
        return True
    elif "evofw3" in serial_port or "FT232R" in serial_port or "NANO" in serial_port:
        return False

    # otherwise, we can look at device attrs via comports()...
    try:
        komports = comports(include_links=True)
    except ImportError as err:
        raise exc.TransportSerialError(f"Unable to find {serial_port}: {err}") from err

    # TODO: remove get(): not monkeypatching comports() correctly for /dev/pts/...
    vid = {x.device: x.vid for x in komports}.get(serial_port)

    # this works, but we may not have all valid VIDs
    if not vid:
        pass
    elif vid == 0x10AC:  # Honeywell
        return True
    elif vid in (0x0403, 0x1B4F):  # FTDI, SparkFun
        return False

    # TODO: remove get(): not monkeypatching comports() correctly for /dev/pts/...
    product = {x.device: getattr(x, "product", None) for x in komports}.get(serial_port)

    if not product:  # is None - VM, or not member of plugdev group?
        pass
    elif "TUSB3410" in product:  # ?needed
        return True
    elif "evofw3" in product or "FT232R" in product or "NANO" in product:
        return False

    # could try sending an "!V", expect "# evofw3 0.7.1", but that needs I/O

    _LOGGER.warning(
        f"{serial_port}: the gateway type is not determinable, will assume evofw3"
        + (
            ", TIP: specify the serial port by-id (i.e. /dev/serial/by-id/usb-...)"
            if "by-id" not in serial_port
            else ""
        )
    )
    return None


def _normalise(pkt_line: str) -> str:
    """Perform any (transparent) frame-level hacks, as required at (near-)RF layer.

    Goals:
    - ensure an evofw3 provides the same output as a HGI80 (none, presently)
    - handle 'strange' packets (e.g. I|08:|0008)
    """

    # ramses-esp bugs, see: https://github.com/IndaloTech/ramses_esp/issues/1
    pkt_line = re.sub("\r\r", "\r", pkt_line)
    for s in (I_, RQ, RP, W_, "000", "\r\n"):
        pkt_line = re.sub(f"^ {s}", s, pkt_line)

    # psuedo-RAMSES-II packets (encrypted payload?)...
    if pkt_line[10:14] in (" 08:", " 31:") and pkt_line[-16:] == "* Checksum error":
        pkt_line = pkt_line[:-17] + " # Checksum error (ignored)"

    return pkt_line


def _str(value: bytes) -> str:
    try:
        result = "".join(
            c
            for c in value.decode("ascii", errors="strict")  # was: .strip()
            if c in printable
        )
    except UnicodeDecodeError:
        _LOGGER.warning("%s < Cant decode bytestream (ignoring)", value)
        return ""
    return result


def limit_duty_cycle(max_duty_cycle: float, time_window: int = _CYCLE_DURATION):
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
        async def wrapper(self, frame: str, *args, **kwargs) -> None:
            nonlocal bits_in_bucket
            nonlocal last_time_bit_added

            rf_frame_size = 330 + len(frame[46:]) * 10

            # top-up the bit bucket
            elapsed_time = perf_counter() - last_time_bit_added
            bits_in_bucket = min(
                bits_in_bucket + elapsed_time * FILL_RATE, BUCKET_CAPACITY
            )
            last_time_bit_added = perf_counter()

            if _DBG_DISABLE_DUTY_CYCLE_LIMIT:
                bits_in_bucket = BUCKET_CAPACITY

            # if required, wait for the bit bucket to refill (not for SETs/PUTs)
            if bits_in_bucket < rf_frame_size:
                await asyncio.sleep((rf_frame_size - bits_in_bucket) / FILL_RATE)

            # consume the bits from the bit bucket
            try:
                await fnc(self, frame, *args, **kwargs)
            finally:
                bits_in_bucket -= rf_frame_size

        @wraps(fnc)
        async def null_wrapper(self, frame: str, *args, **kwargs) -> None:
            await fnc(self, frame, *args, **kwargs)

        if 0 < max_duty_cycle <= 1:
            return wrapper

        return null_wrapper

    return decorator


def limit_transmit_rate(max_tokens: float, time_window: int = _CYCLE_DURATION):
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

        @wraps(fnc)  # type: ignore[unreachable]
        async def null_wrapper(*args, **kwargs) -> Any:
            return await fnc(*args, **kwargs)

        if max_tokens <= 0:
            return null_wrapper

    return decorator


_global_sync_cycles: deque = deque()  # used by @avoid_system_syncs/@track_system_syncs


def avoid_system_syncs(fnc: Callable[..., Awaitable]):
    """Take measures to avoid Tx when any controller is doing a sync cycle."""

    DURATION_PKT_GAP = 0.020  # 0.0200 for evohome, or 0.0127 for DTS92
    DURATION_LONG_PKT = 0.022  # time to tx I|2309|048 (or 30C9, or 000A)
    DURATION_SYNC_PKT = 0.010  # time to tx I|1F09|003

    SYNC_WAIT_LONG = (DURATION_PKT_GAP + DURATION_LONG_PKT) * 2
    SYNC_WAIT_SHORT = DURATION_SYNC_PKT
    SYNC_WINDOW_LOWER = td(seconds=SYNC_WAIT_SHORT * 0.8)  # could be * 0
    SYNC_WINDOW_UPPER = SYNC_WINDOW_LOWER + td(seconds=SYNC_WAIT_LONG * 1.2)  #

    times_0 = []  # TODO: remove

    async def wrapper(*args, **kwargs) -> None:
        global _global_sync_cycles

        def is_imminent(p):
            """Return True if a sync cycle is imminent."""
            return (
                SYNC_WINDOW_LOWER
                < (p.dtm + td(seconds=int(p.payload[2:6], 16) / 10) - dt_now())
                < SYNC_WINDOW_UPPER
            )

        start = perf_counter()  # TODO: remove

        # wait for the start of the sync cycle (I|1F09|003, Tx time ~0.009)
        while any(is_imminent(p) for p in _global_sync_cycles):
            await asyncio.sleep(SYNC_WAIT_SHORT)

        # wait for the remainder of sync cycle (I|2309/30C9) to complete
        if (x := perf_counter() - start) > SYNC_WAIT_SHORT:
            await asyncio.sleep(SYNC_WAIT_LONG)
            # FIXME: remove this block, and merge both ifs
            times_0.append(x)
            _LOGGER.warning(
                f"*** sync cycle stats: {x:.3f}, "
                f"avg: {sum(times_0) / len(times_0):.3f}, "
                f"lower: {min(times_0):.3f}, "
                f"upper: {max(times_0):.3f}, "
                f"times: {[f'{t:.3f}' for t in times_0]}"
            )  # TODO: wrap with if effectiveloglevel

        await fnc(*args, **kwargs)
        return None

    return wrapper


def track_system_syncs(fnc: Callable[[Any, Packet], None]):
    """Track/remember the any new/outstanding TCS sync cycle."""

    MAX_SYNCS_TRACKED = 3

    def wrapper(self, pkt: Packet) -> None:
        global _global_sync_cycles

        def is_pending(p: Packet) -> bool:
            """Return True if a sync cycle is still pending (ignores drift)."""
            return bool(p.dtm + td(seconds=int(p.payload[2:6], 16) / 10) > dt_now())

        if pkt.code != Code._1F09 or pkt.verb != I_ or pkt._len != 3:
            fnc(self, pkt)
            return None

        _global_sync_cycles = deque(
            p for p in _global_sync_cycles if p.src != pkt.src and is_pending(p)
        )
        _global_sync_cycles.append(pkt)  # TODO: sort

        if (
            len(_global_sync_cycles) > MAX_SYNCS_TRACKED
        ):  # safety net for corrupted payloads
            _global_sync_cycles.popleft()

        fnc(self, pkt)
        return None

    return wrapper


class _BaseTransport:  # NOTE: active gwy detection in here
    """Filter out any unwanted (but otherwise valid) packets via device ids."""

    _protocol: RamsesProtocolT
    _extra: dict[str, Any]  # mypy

    def __init__(self, *args, **kwargs) -> None:
        self._evofw_flag = kwargs.pop(SZ_EVOFW_FLAG, None)  # gwy.config.evofw_flag

        super().__init__(*args, **kwargs)

        self._this_pkt: Packet | None = None
        self._prev_pkt: Packet | None = None

        for key in (SZ_ACTIVE_HGI, SZ_SIGNATURE):
            self._extra[key] = None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._protocol})"

    def _pkt_read(self, pkt: Packet) -> None:
        """Pass any valid Packets to the protocol's callback.

        Also maintain _prev_pkt, _this_pkt attrs.
        """

        self._this_pkt, self._prev_pkt = pkt, self._this_pkt

        # NOTE: No need to use call_soon() here, and they may break Qos/Callbacks
        # NOTE: Thus, excepts need checking
        try:  # below could be a call_soon?
            self._protocol.pkt_received(pkt)
        except (AssertionError, exc.ProtocolError) as err:  # protect from upper layers
            _LOGGER.exception("%s < exception from msg layer: %s", pkt, err)


class _RegHackMixin:
    def __init__(self, *args, use_regex: dict | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        use_regex = use_regex or {}

        self.__inbound_rule = use_regex.get(SZ_INBOUND, {})
        self.__outbound_rule = use_regex.get(SZ_OUTBOUND, {})

    @staticmethod
    def __regex_hack(pkt_line: str, regex_rules: dict) -> str:
        if not regex_rules:
            return pkt_line

        result = pkt_line
        for k, v in regex_rules.items():
            try:
                result = re.sub(k, v, result)
            except re.error as err:
                _LOGGER.warning(f"{pkt_line} < issue with regex ({k}, {v}): {err}")

        if result != pkt_line and not _DBG_DISABLE_REGEX_WARNINGS:
            (_LOGGER.debug if DEV_MODE else _LOGGER.warning)(
                f"{pkt_line} < Changed by use_regex to: {result}"
            )
        return result

    def _frame_read(self, dtm: str, frame: str) -> None:
        super()._frame_read(dtm, self.__regex_hack(frame, self.__inbound_rule))  # type: ignore[misc]

    async def _write_frame(self, frame: str) -> None:
        await super()._write_frame(self.__regex_hack(frame, self.__outbound_rule))  # type: ignore[misc]


class _FileTransport(asyncio.ReadTransport):
    """Parse a file (or a dict) for packets, and never send."""

    READER_TASK = "reader_task"
    _protocol: RamsesProtocolT

    _dtm_str: str = None  # type: ignore[assignment]  # FIXME: remove this somehow

    def __init__(
        self,
        protocol: RamsesProtocolT,
        pkt_source: dict | TextIOWrapper,
        loop: asyncio.AbstractEventLoop | None = None,
        extra: dict | None = None,
    ) -> None:
        super().__init__(extra=extra)

        self._pkt_source = pkt_source
        self._protocol = protocol
        self._loop: asyncio.AbstractEventLoop = loop or asyncio.get_running_loop()

        self._closing: bool = False
        self._reading: bool = False

        self._reader_task = self._loop.create_task(self._start_reader())

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        """The asyncio event loop as used by SerialTransport."""
        return self._loop

    def get_extra_info(self, name, default=None) -> Any:
        if name == self.READER_TASK:
            return self._reader_task
        return super().get_extra_info(name, default)

    def is_closing(self) -> bool:
        """Return True if the transport is closing or closed."""
        return self._closing

    def is_reading(self) -> bool:
        """Return True if the transport is receiving."""
        return self._reading

    def pause_reading(self) -> None:
        """Pause the receiving end (no data to protocol.pkt_received())."""
        self._reading = False

    def resume_reading(self) -> None:
        """Resume the receiving end."""
        self._reading = True

    async def _start_reader(self) -> None:  # TODO
        self._reading = True
        try:
            await self._reader()
        except Exception as err:
            self._protocol.connection_lost(err)  # type: ignore[arg-type]
        else:
            self._protocol.connection_lost(None)

    async def _reader(self) -> None:  # TODO
        """Loop through the packet source for Frames and process them."""

        if isinstance(self._pkt_source, dict):
            for dtm_str, pkt_line in self._pkt_source.items():  # assume dtm_str is OK
                while not self._reading:
                    await asyncio.sleep(0.001)
                self._frame_read(dtm_str, pkt_line)
                await asyncio.sleep(0)  # NOTE: big performance penalty if delay >0

        elif isinstance(self._pkt_source, TextIOWrapper):
            for dtm_pkt_line in self._pkt_source:  # should check dtm_str is OK
                while not self._reading:
                    await asyncio.sleep(0.001)
                # can be blank lines in annotated log files
                if (dtm_pkt_line := dtm_pkt_line.strip()) and dtm_pkt_line[:1] != "#":
                    self._frame_read(dtm_pkt_line[:26], dtm_pkt_line[27:])
                await asyncio.sleep(0)  # NOTE: big performance penalty if delay >0

        else:
            raise exc.TransportSourceInvalid(
                f"Packet source is not dict or TextIOWrapper: {self._pkt_source:!r}"
            )

    def _frame_read(self, dtm_str: str, frame: str) -> None:
        """Make a Packet from the Frame and process it."""
        self._dtm_str = dtm_str  # HACK: FIXME: remove need for this, somehow

        try:
            pkt = Packet.from_file(dtm_str, frame)  # is OK for when src is dict
        except ValueError as err:  # VE from dt.fromisoformat() or falsey packet
            _LOGGER.debug("%s < PacketInvalid(%s)", frame, err)
            return
        except exc.PacketInvalid as err:  # VE from dt.fromisoformat()
            _LOGGER.warning("%s < PacketInvalid(%s)", frame, err)
            return
        self._pkt_read(pkt)

    def _pkt_read(self, pkt: Packet) -> None:
        raise NotImplementedError

    async def write_frame(self, frame: str) -> None:  # NotImplementedError
        raise NotImplementedError(f"{self}: This Protocol is Read-Only")

    def write(self, data: bytes) -> None:  # NotImplementedError
        raise NotImplementedError(f"{self}: This Protocol is Read-Only")

    def _abort(self, exc: ExceptionT | None = None) -> None:  # NotImplementedError
        raise NotImplementedError(f"{self}: Not implemented")

    def _close(self, exc: ExceptionT | None = None) -> None:
        if self._closing:
            return
        self._closing = True

        if self._reader_task:
            self._reader_task.cancel()

        self._loop.call_soon(self._protocol.connection_lost, exc)

    def close(self) -> None:
        """Close the transport gracefully (calls `self._protocol.connection_lost()`)."""
        self._close()


class _PortTransport(serial_asyncio.SerialTransport):  # type: ignore[misc]
    """Poll a serial port for packets, and send (without QoS)."""

    loop: asyncio.AbstractEventLoop
    serial: Serial

    _init_fut: asyncio.Future
    _init_task: asyncio.Task

    _recv_buffer: bytes = b""

    _extra: dict[str, Any]  # mypy
    _protocol: RamsesProtocolT  # mypy

    def __init__(
        self,
        protocol: RamsesProtocolT,
        pkt_source: Serial,
        loop: asyncio.AbstractEventLoop | None = None,
        extra: dict | None = None,
    ) -> None:
        super().__init__(loop or asyncio.get_running_loop(), protocol, pkt_source)

        self._extra: dict = {} if extra is None else extra

        self._leaker_sem = asyncio.BoundedSemaphore()
        self._leaker_task = self.loop.create_task(self._leak_sem())

    async def _leak_sem(self) -> None:
        """Used to enforce a minimum time between calls to self.write()."""
        while True:
            await asyncio.sleep(_GAP_BETWEEN_WRITES)
            try:
                self._leaker_sem.release()
            except ValueError:
                pass

    def _dt_now(self) -> dt:
        """Return a precise datetime, using the curent dtm."""
        return dt_now()

    def _read_ready(self) -> None:
        # data to self._bytes_read() instead of self._protocol.data_received()
        try:
            data: bytes = self._serial.read(self._max_read_size)
        except SerialException as e:
            if not self._closing:
                self._close(exc=e)
            return

        if data:
            self._bytes_read(data)  # was: self._protocol.pkt_received(data)

    def is_reading(self) -> bool:
        """Return True if the transport is receiving."""
        return bool(self._has_reader)

    def _bytes_read(self, data: bytes) -> None:  # logs: RCVD(bytes)
        """Make a Frame from the data and process it."""

        def bytes_read(data: bytes) -> Iterable[tuple[dt, bytes]]:
            self._recv_buffer += data
            if b"\r\n" in self._recv_buffer:
                lines = self._recv_buffer.split(b"\r\n")
                self._recv_buffer = lines[-1]
                for line in lines[:-1]:
                    yield self._dt_now(), line + b"\r\n"

        for dtm, raw_line in bytes_read(data):
            if _DBG_FORCE_LOG_FRAMES:
                _LOGGER.warning("Rx: %s", raw_line)
            elif _LOGGER.getEffectiveLevel() == logging.INFO:  # log for INFO not DEBUG
                _LOGGER.info("Rx: %s", raw_line)
            self._frame_read(dtm, _normalise(_str(raw_line)))

    def _frame_read(self, dtm: dt, frame: str) -> None:
        """Make a Packet from the Frame and process it."""

        try:
            pkt = Packet.from_port(dtm, frame)
        except (exc.PacketInvalid, ValueError) as err:  # VE from dt.fromisoformat()
            _LOGGER.warning("%s < PacketInvalid(%s)", frame, err)
            return

        # NOTE: a signature can override an existing active gateway
        if (
            not self._init_fut.done()
            and pkt.code == Code._PUZZ
            and pkt.payload == self._extra[SZ_SIGNATURE]
        ):
            self._extra[SZ_ACTIVE_HGI] = pkt.src.id  # , by_signature=True)
            self._init_fut.set_result(pkt)

        self._pkt_read(pkt)  # TODO: remove raw_line attr from Packet()

    async def write_frame(
        self, frame: str
    ) -> None:  # Protocol usu. calls this, not write()
        await self._leaker_sem.acquire()  # asyncio.sleep(_GAP_BETWEEN_WRITES)
        await self._write_frame(frame)

    # NOTE: The order should be: minimum gap between writes, duty cycle limits, and
    # then the code that avoids the controller sync cycles

    async def _write_frame(self, frame: str) -> None:
        self.write(bytes(frame, "ascii") + b"\r\n")

    def write(self, data: bytes) -> None:  # logs: SENT(bytes)
        if self._closing:
            return

        if _DBG_FORCE_LOG_FRAMES:
            _LOGGER.warning("Tx:     %s", data)
        elif _LOGGER.getEffectiveLevel() == logging.INFO:  # log for INFO not DEBUG
            _LOGGER.info("Tx:     %s", data)

        try:
            super().write(data)
        except SerialException as exc:
            self._abort(exc)
            return

    def _abort(self, exc: ExceptionT) -> None:
        super()._abort(exc)

        if self._init_task:
            self._init_task.cancel()
        if self._leaker_task:
            self._leaker_task.cancel()

    def _close(self, exc: ExceptionT | None = None) -> None:
        super()._close(exc=exc)

        if self._init_task:
            self._init_task.cancel()
        if self._leaker_task:
            self._leaker_task.cancel()

    def close(self) -> None:
        """Close the transport gracefully (calls `self._protocol.connection_lost()`)."""
        if not self._closing:
            self._close()


# ### Read-Only Transports for dict / log file ########################################
class FileTransport(_BaseTransport, _FileTransport):
    """Parse a file (or a dict) for packets, and never send."""

    def __init__(self, *args, disable_sending: bool = True, **kwargs) -> None:
        if disable_sending is False:
            raise exc.TransportSourceInvalid("This Transport cannot send packets")
        super().__init__(*args, **kwargs)
        self.loop.call_soon(self._protocol.connection_made, self)

    def _dt_now(self) -> dt:
        """Return a precise datetime, using a packet's dtm field."""

        try:
            return dt.fromisoformat(self._dtm_str)  # always current pkt's dtm
        except (TypeError, ValueError):
            pass

        try:
            return self._this_pkt.dtm  # type: ignore[union-attr]
        except AttributeError:
            return dt(1970, 1, 1, 1, 0)


# ### Read-Write Transport for serial port ############################################
class PortTransport(_RegHackMixin, _BaseTransport, _PortTransport):  # type: ignore[misc]
    """Poll a serial port for packets, and send (without QoS)."""

    _init_fut: asyncio.Future
    _init_task: asyncio.Task

    def __init__(self, *args, disable_sending: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._is_hgi80 = is_hgi80(self.serial.name)
        self._make_connection(disable_sending)

    def _make_connection(self, sending_disabled: bool) -> None:
        """Call connection_made() after housekeeping functions are completed."""

        # HGI80s (and also VMs) take longer to send signature packets as they have long
        # initialisation times, so we must wait until they send OK

        # signature also serves to discover the HGI's device_id (& for pkt log, if any)

        def call_make_connection(pkt: Packet | None = None) -> None:
            """Invoke the Protocol.connection_made() callback."""
            # if self._is_hgi80 is not True:  # TODO: !V doesn't work, why?
            #     await self._write_frame("!V")  # or self.write()???

            self.loop.call_soon_threadsafe(
                functools.partial(self._protocol.connection_made, self, ramses=True)
            )  # was: self._protocol.connection_made(self, ramses=True)

        async def connect_without_signature() -> None:
            """Call connection_made() without sending/waiting for a signature."""
            self._init_fut.set_result(None)
            call_make_connection()

        async def connect_after_signature() -> None:
            """Poll port with signatures, call connection_made() after first echo."""
            sig = Command._puzzle()
            self._extra[SZ_SIGNATURE] = sig.payload

            num_sends = 0
            while num_sends < _SIGNATURE_MAX_TRYS:
                num_sends += 1

                await self._write_frame(str(sig))
                await asyncio.sleep(_SIGNATURE_GAP_SECS)

                if self._init_fut.done():
                    call_make_connection(pkt=self._init_fut.result())
                    return

            self._init_fut.set_exception(
                exc.TransportSerialError("Never received an echo signature")
            )

        self._init_fut = asyncio.Future()
        if sending_disabled:
            self._init_task = asyncio.create_task(connect_without_signature())
        else:  # incl. disable_qos
            self._init_task = asyncio.create_task(connect_after_signature())

    def get_extra_info(self, name: str, default: Any = None):
        if name == SZ_IS_EVOFW3:
            return not self._is_hgi80  # NOTE: None (unknown) as False (is_evofw3)
        return self._extra.get(name, default)

    @track_system_syncs
    def _pkt_read(self, pkt: Packet) -> None:
        super()._pkt_read(pkt)

    @limit_duty_cycle(_MAX_DUTY_CYCLE)  # type: ignore[misc]  # @limit_transmit_rate(_MAX_TOKENS)
    @avoid_system_syncs
    async def _write_frame(self, frame: str) -> None:
        await super()._write_frame(frame)


# ### Read-Write Transport *with QoS* for serial port #################################
class QosTransport(PortTransport):
    """Poll a serial port for packets, and send with QoS."""

    pass


# ### Read-Write Transport for MQTT ###################################################
class MqttTransport(_BaseTransport, asyncio.Transport):
    READER_TASK = "reader_task"  # only for mypy

    def __init__(
        self,
        protocol: RamsesProtocolT,
        broker_url: str,
        loop: asyncio.AbstractEventLoop | None = None,
        extra: dict | None = None,
        **kwargs,
    ) -> None:
        super().__init__()

        self._protocol = protocol
        self.loop = loop or asyncio.get_event_loop()
        self._extra: dict = {} if extra is None else extra

        self.broker_url = urlparse(broker_url)

        # TODO: check this GWY exists, and is online
        self._extra[SZ_ACTIVE_HGI] = self.broker_url.path[-9:]  # "18:017804"  # HACK
        self._username = unquote(self.broker_url.username or "")
        self._password = unquote(self.broker_url.password or "")

        self._TOPIC_PUB: Final = f"{self.broker_url.path}/tx"[1:]
        self._TOPIC_SUB: Final = f"{self.broker_url.path}/rx"[1:]
        self._qos: Final = int(parse_qs(self.broker_url.query).get("qos", ["0"])[0])

        self._closing = False
        self._reading = True

        self.client = mqtt.Client()
        self.loop.call_soon(self._connect)

    def _dt_now(self) -> dt:
        """Return a precise datetime, using the curent dtm."""
        return dt_now()

    def is_closing(self) -> bool:
        """Return True if the transport is closing or closed."""
        return self._closing

    def is_reading(self) -> bool:
        """Return True if the transport is receiving."""
        return self._reading

    def pause_reading(self) -> None:
        """Pause the receiving end (no data to protocol.pkt_received())."""
        self._reading = False

    def resume_reading(self) -> None:
        """Resume the receiving end."""
        self._reading = True

    def _connect(self):
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.username_pw_set(self._username, self._password)
        self.client.connect_async(
            self.broker_url.hostname,  # type: ignore[arg-type]
            self.broker_url.port or 1883,
            60,
        )

        self.client.loop_start()

    def _on_connect(
        self, client: mqtt.Client, userdata: Any | None, flags: dict[str, Any], rc: int
    ):
        # print(f"Connected with result code {rc}")

        self.loop.call_soon_threadsafe(
            functools.partial(self._protocol.connection_made, self, ramses=True)
        )  # was: self._protocol.connection_made(self, ramses=True)

        client.subscribe(self._TOPIC_SUB, qos=self._qos)

    def _on_message(
        self, client: mqtt.Client, userdata: Any | None, msg: mqtt.MQTTMessage
    ):
        if _DBG_FORCE_LOG_FRAMES:
            _LOGGER.warning("Rx: %s", msg.payload)
        elif _LOGGER.getEffectiveLevel() == logging.INFO:  # log for INFO not DEBUG
            _LOGGER.info("Rx: %s", msg.payload)

        payload = json.loads(msg.payload)

        try:
            pkt = Packet.from_dict(payload["ts"], _normalise(payload["msg"]))
        except (exc.PacketInvalid, ValueError) as err:  # VE from dt.fromisoformat()
            _LOGGER.warning("%s < PacketInvalid(%s)", _normalise(payload["msg"]), err)
            return

        # TODO: dtermine active gateway

        self._pkt_read(pkt)  # TODO: remove raw_line attr from Packet()

    def _publish(self, message: str) -> None:
        info: mqtt.MQTTMessageInfo = self.client.publish(
            self._TOPIC_PUB, payload=message, qos=self._qos
        )
        assert info

    async def write_frame(
        self, frame: str
    ) -> None:  # Protocol usu. calls this, not write()
        if self._closing:
            return

        if _DBG_FORCE_LOG_FRAMES:
            _LOGGER.warning("Tx: %s", frame)
        elif _LOGGER.getEffectiveLevel() == logging.INFO:  # log for INFO not DEBUG
            _LOGGER.info("Tx: %s", frame)

        try:
            self._publish(frame)
        except MQTTException as exc:
            self._close(exc)
            return

    def _close(self, exc: ExceptionT | MQTTException | None = None) -> None:
        """Disconnect from the broker and stop the poller"""
        self._closing = True
        self.client.disconnect()
        self.client.loop_stop()

    def close(self) -> None:
        """Close the transport gracefully."""
        if not self._closing:
            self._close()


RamsesTransportT: TypeAlias = (
    QosTransport | PortTransport | FileTransport | MqttTransport
)


async def transport_factory(
    protocol: RamsesProtocolT,
    /,
    *,
    port_name: SerPortNameT | None = None,
    port_config: dict | None = None,
    packet_log: TextIOWrapper | None = None,
    packet_dict: dict | None = None,
    disable_qos: bool | None = False,
    disable_sending: bool | None = False,
    extra: dict | None = None,
    loop: asyncio.AbstractEventLoop | None = None,
    **kwargs,
) -> RamsesTransportT:
    """Create and return a Ramses-specific async packet Transport."""

    # kwargs are specific to a transport. The above transports have:
    # evofw3_flag, use_regex

    async def poll_until_connection_made(protocol: RamsesProtocolT) -> None:
        """Poll until the Transport is bound to the Protocol."""
        while protocol._transport is None:
            await asyncio.sleep(0.005)  # type: ignore[unreachable]

    def get_serial_instance(ser_name: SerPortNameT, ser_config: dict) -> Serial:
        # For example:
        # - python client.py monitor 'rfc2217://localhost:5001'
        # - python client.py monitor 'alt:///dev/ttyUSB0?class=PosixPollSerial'

        ser_config = SCH_SERIAL_PORT_CONFIG(ser_config or {})

        try:
            ser_obj = serial_for_url(ser_name, **ser_config)
        except SerialException as err:
            _LOGGER.error(
                "Failed to open %s (config: %s): %s", ser_name, ser_config, err
            )
            raise exc.TransportSerialError(
                f"Unable to open the serial port: {ser_name}"
            ) from err

        # FTDI on Posix/Linux would be a common environment for this library...
        try:
            ser_obj.set_low_latency_mode(True)
        except (AttributeError, NotImplementedError, ValueError):
            pass  # Wrong OS/Platform/not FTDI

        return ser_obj

    def issue_warning() -> None:
        """Warn of the perils of semi-supported configurations."""
        _LOGGER.warning(
            f"{'Windows' if os.name == 'nt' else 'This type of serial interface'} "
            "is not fully supported by this library: "
            "please don't report any Transport/Protocol errors/warnings, "
            "unless they are reproducable with a standard configuration "
            "(e.g. linux with a local serial port)"
        )

    if len([x for x in (packet_dict, packet_log, port_name) if x is not None]) != 1:
        raise exc.TransportSourceInvalid(
            "Packet source must be exactly one of: packet_dict, packet_log, port_name"
        )

    if (pkt_source := packet_log or packet_dict) is not None:
        return FileTransport(protocol, pkt_source, extra=extra, loop=loop, **kwargs)

    assert port_name is not None  # mypy check
    assert port_config is not None  # mypy check

    if port_name[:4] == "mqtt":
        return MqttTransport(protocol, port_name, extra=extra, loop=loop, **kwargs)

    # may: raise TransportSerialError("Unable to open serial port...")
    ser_instance = get_serial_instance(port_name, port_config)

    # TODO: test these...
    if os.name == "nt" or ser_instance.portstr[:7] in ("rfc2217", "socket:"):
        issue_warning()
        # return PortTransport(protocol, ser_instance, **kwargs)

    if disable_sending or disable_qos:
        transport = PortTransport(
            protocol,
            ser_instance,
            disable_sending=bool(disable_sending),
            extra=extra,
            loop=loop,
            **kwargs,
        )
    else:  # disable_qos could  be False, None
        transport = QosTransport(
            protocol, ser_instance, extra=extra, loop=loop, **kwargs
        )

    # wait to get (first) signature echo from evofw3/HGI80 (even if disable_sending)
    try:
        await asyncio.wait_for(transport._init_fut, timeout=3)  # signature echo
    except TimeoutError as err:
        raise exc.TransportSerialError(
            "Transport did not initialise successfully"
        ) from err

    # wait for protocol to receive connection_made(transport) (i.e. is quiesced)
    try:
        await asyncio.wait_for(poll_until_connection_made(protocol), timeout=3)
    except TimeoutError as err:
        raise exc.TransportSerialError("Transport did not bind to Protocol") from err

    return transport
