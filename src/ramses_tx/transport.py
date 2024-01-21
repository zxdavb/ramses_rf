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
import logging
import os
import re
import sys
from collections.abc import Iterable
from datetime import datetime as dt
from io import TextIOWrapper
from string import printable
from typing import TYPE_CHECKING, Any, TypeAlias

import serial_asyncio  # type: ignore[import-untyped]
from serial import (  # type: ignore[import-untyped]
    Serial,
    SerialException,
    serial_for_url,
)

from . import exceptions as exc
from .address import ALL_DEV_ADDR, HGI_DEV_ADDR, NON_DEV_ADDR, pkt_addrs
from .command import Command
from .const import (
    DEV_TYPE_MAP,
    SZ_ACTIVE_HGI,
    SZ_IS_EVOFW3,
    SZ_KNOWN_HGI,
    SZ_SIGNATURE,
    DevType,
)
from .helpers import dt_now
from .packet import Packet
from .schemas import (
    SCH_SERIAL_PORT_CONFIG,
    SZ_BLOCK_LIST,
    SZ_CLASS,
    SZ_EVOFW_FLAG,
    SZ_INBOUND,
    SZ_KNOWN_LIST,
    SZ_OUTBOUND,
)
from .typing import ExceptionT, SerPortNameT

from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:
    from .address import DeviceIdT
    from .protocol import RamsesProtocolT


_SIGNATURE_MAX_TRYS = 24
_SIGNATURE_GAP_SECS = 0.05

TIP = f", configure the {SZ_KNOWN_LIST}/{SZ_BLOCK_LIST} as required"


DEV_MODE = False

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

# All debug flags (used for dev/test) should be False for end-users
_DBG_DISABLE_REGEX_WARNINGS = False
_DBG_FORCE_LOG_FRAMES = False


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
        f"{serial_port}: the gateway type is not determinable, will assume evofw3, "
        "TIP: specify the serial port by-id (i.e. /dev/serial/by-id/usb-...)"
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


class _DeviceIdFilterMixin:  # NOTE: active gwy detection in here
    """Filter out any unwanted (but otherwise valid) packets via device ids."""

    _protocol: RamsesProtocolT
    _extra: dict[str, Any]  # mypy

    def __init__(
        self,
        *args,
        enforce_include_list: bool = False,
        exclude_list: dict[DeviceIdT, str] | None = None,
        include_list: dict[DeviceIdT, str] | None = None,
        **kwargs,
    ) -> None:
        exclude_list = exclude_list or {}
        include_list = include_list or {}

        self._evofw_flag = kwargs.pop(SZ_EVOFW_FLAG, None)  # gwy.config.evofw_flag

        super().__init__(*args, **kwargs)

        self._this_pkt: Packet | None = None
        self._prev_pkt: Packet | None = None

        self.enforce_include = enforce_include_list
        self._exclude = list(exclude_list.keys())
        self._include = list(include_list.keys()) + [ALL_DEV_ADDR.id, NON_DEV_ADDR.id]

        self._foreign_gwys_lst: list[DeviceIdT] = []
        self._foreign_last_run = dt.now().date()

        for key in (SZ_ACTIVE_HGI, SZ_SIGNATURE, SZ_KNOWN_HGI):
            self._extra[key] = None

        # TODO: maybe this shouldn't be called for read-only transports?
        self._extra[SZ_KNOWN_HGI] = self._get_known_hgi(include_list)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._protocol})"

    def _get_known_hgi(self, include_list: dict[DeviceIdT, Any]) -> DeviceIdT | None:
        """Return the device_id of the gateway specified in the include_list, if any.

        The 'Known' gateway is the predicted Active gateway, given the known_list.
        The 'Active' gateway is the USB device that is Tx/Rx frames.

        The Known gateway ID should be the Active gateway ID, but does not have to
        match.

        Send a warning if the include_list is configured incorrectly.
        """

        known_hgis = [
            k for k, v in include_list.items() if v.get(SZ_CLASS) == DevType.HGI
        ]
        known_hgis = known_hgis or [
            k for k, v in include_list.items() if k[:2] == "18" and not v.get(SZ_CLASS)
        ]

        if not known_hgis:
            _LOGGER.info(
                f"The {SZ_KNOWN_LIST} should include exactly one gateway (HGI), "
                f"but does not (make sure you specify class: HGI)"
            )
            return None

        known_hgi = known_hgis[0]

        if include_list[known_hgi].get(SZ_CLASS) != DevType.HGI:
            _LOGGER.info(
                f"The {SZ_KNOWN_LIST} should include a well-configured gateway (HGI), "
                f"{known_hgi} should specify class: HGI (18: is also used for HVAC)"
            )

        elif len(known_hgis) > 1:
            _LOGGER.info(
                f"The {SZ_KNOWN_LIST} should include exactly one gateway (HGI), "
                f"{known_hgi} is the assumed device id (is it/are the others HVAC?)"
            )

        else:
            _LOGGER.debug(
                f"The {SZ_KNOWN_LIST} specifies {known_hgi} as the gateway (HGI)"
            )

        return known_hgis[0]

    def _set_active_hgi(self, dev_id: DeviceIdT, by_signature: bool = False) -> None:
        """Set the Active Gateway (HGI) device_if.

        Send a warning if the include list is configured incorrectly.
        """

        assert self._extra[SZ_ACTIVE_HGI] is None  # should only be called once

        msg = f"The active gateway {dev_id}: {{ class: HGI }} "
        msg += "(by signature)" if by_signature else "(by filter)"

        if dev_id not in self._exclude:
            self._extra[SZ_ACTIVE_HGI] = dev_id
            # else: setting self._extra[SZ_ACTIVE_HGI] will not help

        if dev_id in self._exclude:
            _LOGGER.error(f"{msg} MUST NOT be in the {SZ_BLOCK_LIST}{TIP}")
        elif dev_id in self._include:
            pass
        elif self.enforce_include:
            _LOGGER.warning(f"{msg} SHOULD be in the (enforced) {SZ_KNOWN_LIST}")
            # self._include.append(dev_id)  # a good idea?
        else:
            _LOGGER.warning(f"{msg} SHOULD be in the {SZ_KNOWN_LIST}")

    def _is_wanted_addrs(
        self, src_id: DeviceIdT, dst_id: DeviceIdT, sending: bool = False
    ) -> bool:
        """Return True if the packet is not to be filtered out.

        In any one packet, an excluded device_id 'trumps' an included device_id.

        There are two ways to set the Active Gateway (HGI80/evofw3):
        - by signature (evofw3 only), when frame -> packet
        - by known_list (HGI80/evofw3), when filtering packets
        """

        def warn_foreign_hgi(dev_id: DeviceIdT) -> None:
            current_date = dt.now().date()

            if self._foreign_last_run != current_date:
                self._foreign_last_run = current_date
                self._foreign_gwys_lst = []  # reset the list every 24h

            if dev_id in self._foreign_gwys_lst:
                return

            _LOGGER.warning(
                f"Device {dev_id} is potentially a Foreign gateway, "
                f"the Active gateway is {self._extra[SZ_ACTIVE_HGI]}, "
                f"alternatively, is it a HVAC device?{TIP}"
            )
            self._foreign_gwys_lst.append(dev_id)

        for dev_id in dict.fromkeys((src_id, dst_id)):  # removes duplicates
            if dev_id in self._exclude:  # problems if incl. active gateway
                return False

            if dev_id == self._extra[SZ_ACTIVE_HGI]:  # is active gwy
                continue  # consider: return True

            if dev_id in self._include:  # incl. 63:262142 & --:------
                continue

            if sending and dev_id == HGI_DEV_ADDR.id:
                continue

            if self.enforce_include:
                return False

            if dev_id[:2] != DEV_TYPE_MAP.HGI:
                continue

            if self._extra[SZ_ACTIVE_HGI]:  # this 18: is not in known_list
                warn_foreign_hgi(dev_id)

        return True

    def _pkt_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted Packets to the protocol's callback.

        Also maintain _prev_pkt, _this_pkt attrs.
        """

        if not self._is_wanted_addrs(pkt.src.id, pkt.dst.id):
            return

        self._this_pkt, self._prev_pkt = pkt, self._this_pkt

        # NOTE: No need to use call_soon() here, and they may break Qos/Callbacks
        # NOTE: Thus, excepts need checking
        try:  # below could be a call_soon?
            self._protocol.pkt_received(pkt)
        except AssertionError as err:  # protect from upper-layer callbacks
            _LOGGER.exception("%s < exception from msg layer: %s", pkt, err)

    def _send_frame(self, frame: str) -> None:
        src, dst, *_ = pkt_addrs(frame[7:36])
        if not self._is_wanted_addrs(src.id, dst.id, sending=True):
            raise exc.TransportError(f"Packet excluded by device_id filter: {frame}")
        super()._send_frame(frame)  # type: ignore[misc]


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

    def _frame_received(self, dtm: str, frame: str) -> None:
        super()._frame_received(dtm, self.__regex_hack(frame, self.__inbound_rule))  # type: ignore[misc]

    def _send_frame(self, frame: str) -> None:
        super()._send_frame(self.__regex_hack(frame, self.__outbound_rule))  # type: ignore[misc]


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

        self._is_closing: bool = False
        self._is_reading: bool = False

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
        return self._is_closing

    def is_reading(self) -> bool:
        """Return True if the transport is receiving."""
        return self._is_reading

    def pause_reading(self) -> None:
        """Pause the receiving end (no data to protocol.pkt_received())."""
        self._is_reading = False

    def resume_reading(self) -> None:
        """Resume the receiving end."""
        self._is_reading = True

    async def _start_reader(self) -> None:  # TODO
        self._is_reading = True
        try:
            await self._reader()
        except KeyboardInterrupt as err:
            self._protocol.connection_lost(err)  # type: ignore[arg-type]
        else:
            self._protocol.connection_lost(None)

    async def _reader(self) -> None:  # TODO
        """Loop through the packet source for Frames and process them."""

        if isinstance(self._pkt_source, dict):
            for dtm_str, pkt_line in self._pkt_source.items():  # assume dtm_str is OK
                while not self._is_reading:
                    await asyncio.sleep(0.001)
                self._frame_received(dtm_str, pkt_line)
                await asyncio.sleep(0)  # NOTE: big performance penalty if delay >0

        elif isinstance(self._pkt_source, TextIOWrapper):
            for dtm_pkt_line in self._pkt_source:  # should check dtm_str is OK
                while not self._is_reading:
                    await asyncio.sleep(0.001)
                self._frame_received(dtm_pkt_line[:26], dtm_pkt_line[27:])
                await asyncio.sleep(0)  # NOTE: big performance penalty if delay >0

        else:
            raise exc.TransportSourceInvalid(
                f"Packet source is not dict or TextIOWrapper: {self._pkt_source:!r}"
            )

    def _frame_received(self, dtm_str: str, frame: str) -> None:
        """Make a Packet from the Frame and process it."""
        self._dtm_str = dtm_str  # HACK: FIXME: remove need for this, somehow

        try:
            pkt = Packet.from_file(dtm_str, frame)  # is OK for when src is dict
        except (exc.PacketInvalid, ValueError):  # VE from dt.fromisoformat()
            return
        self._pkt_received(pkt)

    def _pkt_received(self, pkt: Packet) -> None:
        raise NotImplementedError

    def send_frame(self, frame: str) -> None:  # NotImplementedError
        raise NotImplementedError(f"{self}: This Protocol is Read-Only")

    def write(self, data: bytes) -> None:  # NotImplementedError
        raise NotImplementedError(f"{self}: This Protocol is Read-Only")

    def _abort(self, exc: ExceptionT | None = None) -> None:  # NotImplementedError
        raise NotImplementedError(f"{self}: Not implemented")

    def _close(self, exc: ExceptionT | None = None) -> None:
        if self._is_closing:
            return
        self._is_closing = True

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

    def __init__(
        self,
        protocol: RamsesProtocolT,
        pkt_source: Serial,
        loop: asyncio.AbstractEventLoop | None = None,
        extra: dict | None = None,
    ) -> None:
        super().__init__(loop or asyncio.get_running_loop(), protocol, pkt_source)

        self._extra: dict = {} if extra is None else extra

    def _dt_now(self) -> dt:
        """Return a precise datetime, using the curent dtm."""
        return dt_now()

    def _read_ready(self) -> None:
        # data to self._bytes_received() instead of self._protocol.data_received()
        try:
            data: bytes = self._serial.read(self._max_read_size)
        except SerialException as e:
            if not self._closing:
                self._close(exc=e)
            return

        if data:
            self._bytes_received(data)  # was: self._protocol.pkt_received(data)

    def is_reading(self) -> bool:
        """Return True if the transport is receiving."""
        return bool(self._has_reader)

    def _bytes_received(self, data: bytes) -> None:  # logs: RCVD(bytes)
        """Make a Frame from the data and process it."""

        def bytes_received(data: bytes) -> Iterable[tuple[dt, bytes]]:
            self._recv_buffer += data
            if b"\r\n" in self._recv_buffer:
                lines = self._recv_buffer.split(b"\r\n")
                self._recv_buffer = lines[-1]
                for line in lines[:-1]:
                    yield self._dt_now(), line + b"\r\n"

        for dtm, raw_line in bytes_received(data):
            if _DBG_FORCE_LOG_FRAMES:
                _LOGGER.warning("Rx: %s", raw_line)
            elif _LOGGER.getEffectiveLevel() == logging.INFO:  # log for INFO not DEBUG
                _LOGGER.info("Rx: %s", raw_line)
            self._frame_received(dtm, _normalise(_str(raw_line)))

    def _frame_received(self, dtm: dt, frame: str) -> None:
        """Make a Packet from the Frame and process it."""

        try:
            pkt = Packet.from_port(dtm, frame)
        except (exc.PacketInvalid, ValueError):  # VE from dt.fromisoformat()
            return

        # NOTE: a signature can override an existing active gateway
        if (
            not self._init_fut.done()
            and pkt.code == Code._PUZZ
            and pkt.payload == self._extra[SZ_SIGNATURE]
        ):
            self._set_active_hgi(pkt.src.id, by_signature=True)
            self._init_fut.set_result(pkt)

        elif not self._extra[SZ_ACTIVE_HGI] and pkt.src.id == self._extra[SZ_KNOWN_HGI]:
            self._set_active_hgi(pkt.src.id)

        self._pkt_received(pkt)  # TODO: remove raw_line attr from Packet()

    def send_frame(self, frame: str) -> None:  # Protocol usu. calls this, not write()
        self._send_frame(frame)

    def _send_frame(self, frame: str) -> None:
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

    def _close(self, exc: ExceptionT | None = None) -> None:
        super()._close(exc=exc)

        if self._init_task:
            self._init_task.cancel()

    def close(self) -> None:
        """Close the transport gracefully (calls `self._protocol.connection_lost()`)."""
        if not self._closing:
            self._close()


# ### Read-Only Transports for dict / log file ########################################
class FileTransport(_DeviceIdFilterMixin, _FileTransport):
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
class PortTransport(_RegHackMixin, _DeviceIdFilterMixin, _PortTransport):  # type: ignore[misc]
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

        # Could instead have: connection_made(self, pkt=pkt) *if* pkt is sig. echo, but
        # would require a re-write or portions of both Transport & Protocol

        def call_make_connection() -> None:
            """Invoke the Protocol.connection_made() callback."""
            # if self._is_hgi80 is not True:  # TODO: !V doesn't work, why?
            #     self._send_frame("!V")

            self.loop.call_soon(
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

                self._send_frame(str(sig))
                await asyncio.sleep(_SIGNATURE_GAP_SECS)

                if self._init_fut.done():
                    call_make_connection()
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


# ### Read-Write Transport *with QoS* for serial port #################################
class QosTransport(PortTransport):
    """Poll a serial port for packets, and send with QoS."""

    # NOTE: Might normally include code to the limit duty cycle, etc., but see
    # the note in Protocol layer

    pass


RamsesTransportT: TypeAlias = QosTransport | PortTransport | FileTransport


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
    # enforce_include_list, exclude_list, include_list, use_regex

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
    except asyncio.TimeoutError as err:
        raise exc.TransportSerialError(
            "Transport did not initialise successfully"
        ) from err

    # wait for protocol to receive connection_made(transport) (i.e. is quiesced)
    try:
        await asyncio.wait_for(poll_until_connection_made(protocol), timeout=3)
    except asyncio.TimeoutError as err:
        raise exc.TransportSerialError("Transport did not bind to Protocol") from err

    return transport
