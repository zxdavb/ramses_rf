#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible packet transport.

Operates at the pkt layer of: app - msg - pkt - h/w

For ser2net, use the following YAML with: ser2net -c hgi80.yaml
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
import logging
import os
import re
from collections.abc import Callable, Iterable
from datetime import datetime as dt
from io import TextIOWrapper
from string import printable
from typing import TYPE_CHECKING, Any

import serial_asyncio  # type: ignore[import-untyped]
from serial import (  # type: ignore[import-untyped]
    Serial,
    SerialException,
    serial_for_url,
)
from serial.tools.list_ports import comports  # type: ignore[import-untyped]

from .address import NON_DEV_ADDR, NUL_DEV_ADDR
from .command import Command
from .const import (
    DEV_TYPE_MAP,
    SZ_ACTIVE_HGI,
    SZ_IS_EVOFW3,
    SZ_KNOWN_HGI,
    SZ_SIGNATURE,
    DevType,
    __dev_mode__,
)
from .exceptions import PacketInvalid, TransportSerialError, TransportSourceInvalid
from .helpers import dt_now
from .packet import Packet
from .schemas import (
    SCH_SERIAL_PORT_CONFIG,
    SZ_BLOCK_LIST,
    SZ_CLASS,
    SZ_DISABLE_QOS,
    SZ_DISABLE_SENDING,
    SZ_EVOFW_FLAG,
    SZ_INBOUND,
    SZ_KNOWN_LIST,
    SZ_OUTBOUND,
)

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:  # mypy TypeVars and similar (e.g. Index, Verb)
    # skipcq: PY-W2000
    from .address import DeviceId
    from .const import Index, Verb  # noqa: F401, pylint: disable=unused-import


if TYPE_CHECKING:
    from . import QosProtocol as _ProtocolT

_SIGNATURE_MAX_TRYS = 24
_SIGNATURE_GAP_SECS = 0.05

TIP = f", configure the {SZ_KNOWN_LIST}/{SZ_BLOCK_LIST} as required"


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

# All debug flags should be False for end-users
_DEBUG_DISABLE_REGEX_WARNINGS = True  # useful for dev/test
_DEBUG_FORCE_LOG_FRAMES = False  # useful for dev/test


def _normalise(pkt_line: str) -> str:
    """Perform any (transparent) frame-level hacks, as required at (near-)RF layer.

    Goals:
    - ensure an evofw3 provides the same output as a HGI80 (none, presently)
    - handle 'strange' packets (e.g. I/08:/0008)
    """

    # psuedo-RAMSES-II packets...
    if pkt_line[10:14] in (" 08:", " 31:") and pkt_line[-16:] == "* Checksum error":
        pkt_line = pkt_line[:-17] + " # Checksum error (ignored)"

    return pkt_line.strip()


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


class _PktMixin:
    """Base class for RAMSES II transports."""

    _this_pkt: None | Packet
    _prev_pkt: None | Packet
    _protocol: _ProtocolT

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._this_pkt: Packet = None
        self._prev_pkt: Packet = None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._protocol})"

    def _pkt_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted Packets to the protocol's callback.

        Also maintain _prev_pkt, _this_pkt attrs.
        """

        self._this_pkt, self._prev_pkt = pkt, self._this_pkt

        # NOTE: No need to use call_soon() here, and they may break Qos/Callbacks
        # NOTE: Thus, excepts need checking
        try:  # below could be a call_soon?
            self._protocol.pkt_received(pkt)
        except AssertionError as exc:  # protect from upper-layer callbacks
            _LOGGER.exception("%s < exception from msg layer: %s", pkt, exc)


class _DeviceIdFilterMixin:  # NOTE: active gwy detection in here too
    """Filter out any unwanted (but otherwise valid) packets via device ids."""

    _extra: dict[str, Any]  # mypy

    def __init__(
        self,
        *args,
        enforce_include_list: bool = False,
        exclude_list: None | dict = None,
        include_list: None | dict = None,
        **kwargs,
    ) -> None:
        exclude_list = exclude_list or {}
        include_list = include_list or {}

        self._evofw_flag = kwargs.pop(SZ_EVOFW_FLAG, None)  # gwy.config.evofw_flag

        super().__init__(*args, **kwargs)

        self.enforce_include = enforce_include_list
        self._exclude = list(exclude_list.keys())
        self._include = list(include_list.keys()) + [NON_DEV_ADDR.id, NUL_DEV_ADDR.id]

        self._unwanted: list = []  # not: [NON_DEV_ADDR.id, NUL_DEV_ADDR.id]

        for key in (SZ_ACTIVE_HGI, SZ_SIGNATURE, SZ_KNOWN_HGI):
            self._extra[key] = None

        known_hgis = [
            k for k, v in include_list.items() if v.get(SZ_CLASS) == DevType.HGI
        ]
        if not known_hgis:
            _LOGGER.warning(
                f"The {SZ_KNOWN_LIST} should include the gateway (HGI) but doesn't{TIP}"
            )
        else:
            self._extra[SZ_KNOWN_HGI] = known_hgis[0]
        if len(known_hgis) > 1:
            _LOGGER.warning(
                f"The {SZ_KNOWN_LIST} should have only 1 gateway (HGI) but has more"
                f" (the selected Known gateway is: {self._extra[SZ_KNOWN_HGI]}){TIP}"
            )

    def _set_active_hgi(self, dev_id: DeviceId, by_signature: bool = False) -> None:
        """Set the Active Gateway device (HGI), warn if it is filtered incorrectly."""
        msg = "Active gateway " + "(by signature)" if by_signature else "(by filter)"

        if dev_id in self._exclude:
            _LOGGER.error(f"{msg} is in {SZ_BLOCK_LIST}: {dev_id}{TIP}")
        elif dev_id in self._include:
            _LOGGER.info(f"{msg}: {dev_id}")
        else:
            _LOGGER.warning(f"{msg} not in {SZ_KNOWN_LIST}: {dev_id}{TIP}")
        self._extra[SZ_ACTIVE_HGI] = dev_id

    def _is_wanted_addrs(
        self, src_id: DeviceId, dst_id: DeviceId, payload: None | str = None
    ) -> bool:
        """Return True if the packet is not to be filtered out.

        In any one packet, an excluded device_id 'trumps' an included device_id.
        """

        def deprecate_foreign_hgi(dev_id: DeviceId) -> None:
            self._unwanted.append(dev_id)
            _LOGGER.warning(
                f"Blacklisted a Foreign gateway (is it a HVAC device?): {dev_id}"
                f" (Active gateway is: {self._extra[SZ_ACTIVE_HGI]}){TIP}"
            )

        for dev_id in dict.fromkeys((src_id, dst_id)):  # removes duplicates
            # TODO: _unwanted exists since (in future) stale entries need to be removed

            if dev_id in self._exclude or dev_id in self._unwanted:
                return False

            if dev_id == self._extra[SZ_ACTIVE_HGI]:  # is active gwy
                continue

            if dev_id in self._include:  # incl. 63:262142 & --:------
                continue

            if self.enforce_include:
                return False

            if dev_id[:2] != DEV_TYPE_MAP.HGI:
                continue

            if self._extra[SZ_ACTIVE_HGI]:
                deprecate_foreign_hgi(dev_id)  # self._unwanted.append(dev_id)
                return False

            if dev_id == src_id and payload == self._extra[SZ_SIGNATURE]:
                self._set_active_hgi(dev_id)
                continue

            if dev_id == self._extra[SZ_KNOWN_HGI]:
                self._set_active_hgi(dev_id)

        return True

    def _pkt_received(self, pkt: Packet) -> None:
        """Validate a Packet and dispatch it to the protocol's callback."""
        if self._is_wanted_addrs(pkt.src.id, pkt.dst.id, pkt.payload):
            super()._pkt_received(pkt)  # type: ignore[misc]


class _RegHackMixin:
    def __init__(self, *args, use_regex: None | dict = None, **kwargs) -> None:
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
            except re.error as exc:
                _LOGGER.warning(f"{pkt_line} < issue with regex ({k}, {v}): {exc}")

        if result != pkt_line and not _DEBUG_DISABLE_REGEX_WARNINGS:
            (_LOGGER.debug if DEV_MODE else _LOGGER.warning)(
                f"{pkt_line} < Changed by use_regex to: {result}"
            )
        return result

    def _frame_received(self, dtm: str, frame: str) -> None:
        super()._frame_received(dtm, self.__regex_hack(frame, self.__inbound_rule))  # type: ignore[misc]

    def _send_frame(self, frame: str) -> None:
        super()._send_frame(self.__regex_hack(frame, self.__outbound_rule))  # type: ignore[misc]


class _FileTransport(_PktMixin, asyncio.ReadTransport):
    """Parse a file (or a dict) for packets, and never send."""

    READER_TASK = "reader_task"
    _protocol: _ProtocolT

    _dtm_str: str = None  # type: ignore[assignment]  # FIXME: remove this somehow

    def __init__(
        self,
        protocol: _ProtocolT,
        pkt_source: dict | TextIOWrapper,
        loop: None | asyncio.AbstractEventLoop = None,
        extra: None | dict = None,
    ) -> None:
        super().__init__(extra=extra)

        self._pkt_source = pkt_source
        self._protocol = protocol
        self._loop: asyncio.AbstractEventLoop = loop or asyncio.get_running_loop()

        self._is_closing: bool = False
        self._is_reading: bool = False

        self._reader_task = self._loop.create_task(self._start_reader())

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

    def is_reading(self):
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
        except KeyboardInterrupt as exc:
            self._protocol.connection_lost(exc)
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
            raise TransportSourceInvalid(
                f"Packet source is not dict or TextIOWrapper: {self._pkt_source:!r}"
            )

    def _frame_received(self, dtm_str: str, frame: str) -> None:
        """Make a Packet from the Frame and process it."""
        self._dtm_str = dtm_str  # HACK: FIXME: remove need for this, somehow

        try:
            pkt = Packet.from_file(dtm_str, frame)  # is OK for when src is dict
        except (PacketInvalid, ValueError):  # VE from dt.fromisoformat()
            return
        self._pkt_received(pkt)

    def close(self, exc: None | Exception = None) -> None:
        """Close the transport (calls self._protocol.connection_lost())."""
        if self._is_closing:
            return
        self._is_closing = True

        if self._reader_task:
            self._reader_task.cancel()

        self._loop.call_soon(self._protocol.connection_lost, exc)


class _PortTransport(_PktMixin, serial_asyncio.SerialTransport):
    """Poll a serial port for packets, and send (without QoS)."""

    loop: asyncio.AbstractEventLoop
    serial: Serial

    _init_fut: asyncio.Future
    _init_task: None | asyncio.Task = None

    _recv_buffer: bytes = b""

    def __init__(
        self,
        protocol: _ProtocolT,
        pkt_source: Serial,
        loop: None | asyncio.AbstractEventLoop = None,
        extra: None | dict = None,
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
            self._close(exc=e)
            return

        if data:
            self._bytes_received(data)  # was: self._protocol.pkt_received(data)

    def is_reading(self) -> None:
        """Return True if the transport is receiving."""
        return self._has_reader

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
            if _DEBUG_FORCE_LOG_FRAMES:
                _LOGGER.warning("Rx: %s", raw_line)
            elif _LOGGER.getEffectiveLevel() == logging.INFO:  # log for INFO not DEBUG
                _LOGGER.info("Rx: %s", raw_line)
            self._frame_received(dtm, _normalise(_str(raw_line)))

    def _frame_received(self, dtm: dt, frame: str) -> None:
        """Make a Packet from the Frame and process it."""

        try:
            pkt = Packet.from_port(dtm, frame)
        except (PacketInvalid, ValueError):  # VE from dt.fromisoformat()
            return

        if (
            not self._init_fut.done()
            and pkt.code == Code._PUZZ
            and pkt.payload == self._extra[SZ_SIGNATURE]
        ):
            self._set_active_hgi(pkt.src.id, by_signature=True)
            self._init_fut.set_result(pkt)

        self._pkt_received(pkt)  # TODO: remove raw_line attr from Packet()

    def send_frame(self, frame: str) -> None:  # Protocol usu. calls this, not write()
        self._send_frame(frame)

    def _send_frame(self, frame: str) -> None:
        self.write(bytes(frame, "ascii") + b"\r\n")

    def write(self, data: bytes) -> None:  # logs: SENT(bytes)
        if _DEBUG_FORCE_LOG_FRAMES:
            _LOGGER.warning("Tx:     %s", data)
        elif _LOGGER.getEffectiveLevel() == logging.INFO:  # log for INFO not DEBUG
            _LOGGER.info("Tx:     %s", data)
        super().write(data)

    def close(self, exc: None | Exception = None) -> None:
        """Close the transport (calls self._protocol.connection_lost())."""
        super().close()
        if self._init_task:
            self._init_task.cancel()


# ### Read-Only Transports for dict / log file ########################################
class FileTransport(_DeviceIdFilterMixin, _FileTransport):
    """Parse a file (or a dict) for packets, and never send."""

    def __init__(self, *args, disable_sending: bool = True, **kwargs) -> None:
        if disable_sending is False:
            raise TransportSourceInvalid("This Transport cannot send packets")
        super().__init__(*args, **kwargs)
        self.loop.call_soon(self._protocol.connection_made, self)


# ### Read-Write Transport for serial port ############################################
class PortTransport(_RegHackMixin, _DeviceIdFilterMixin, _PortTransport):
    """Poll a serial port for packets, and send (without QoS)."""

    _init_fut: asyncio.Future
    _init_task: asyncio.Task

    def __init__(self, *args, disable_sending: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._is_hgi80 = self.is_hgi80(self.serial.name)
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
                TransportSerialError("Never received an echo signature")
            )

        self._init_fut = asyncio.Future()
        if sending_disabled:
            self._init_task = asyncio.create_task(connect_without_signature())
        else:  # incl. disable_qos
            self._init_task = asyncio.create_task(connect_after_signature())

    @staticmethod
    def is_hgi80(serial_port: SerPortName) -> None | bool:
        """Return True/False if the device attached to the port is/isn't an HGI80.

        Return None if it's not possible to tell (effectively assume is evofw3).
        """

        vid = {x.device: x.vid for x in comports()}.get(serial_port)

        if vid and vid == 0x10AC:  # aka Honeywell, Inc.
            _LOGGER.debug(f"{serial_port}: is HGI80-compatible (by VID)")
            return True

        product: None | str = {
            x.device: getattr(x, "product", None) for x in comports()
        }.get(serial_port)

        if not product:  # is None - not member of plugdev group?
            pass
        # elif "TUSB3410" in product:  # ?needed
        #     _LOGGER.info("The gateway is HGI80-compatible (by USB attrs)")
        #     return True
        elif "evofw3" in product or "FT232R" in product:
            _LOGGER.debug(f"{serial_port}: appears evofw3-compatible (by USB attrs)")
            return False

        _LOGGER.warning(
            f"{serial_port}: the gateway type is not determinable, will assume evofw3 "
            "(check you have the rights to enumerate USB attrs?)"
        )
        return None  # try sending an "!V", expect "# evofw3 0.7.1"

    def get_extra_info(self, name, default=None):
        if name == SZ_IS_EVOFW3:
            return not self._is_hgi80  # NOTE: None (unknown) as False (is_evofw3)
        return self._extra.get(name, default)


# ### Read-Write Transport *with QoS* for serial port #################################
class QosTransport(PortTransport):
    """Poll a serial port for packets, and send with QoS."""

    # NOTE: Might normally include code to the limit duty cycle, etc., but see
    # the note in Protocol layer

    pass


def find_gateway_device() -> None | SerPortName:
    """Find the gateway device and return its port name (assumes exactly one)."""
    port_names = [
        p.device for p in comports() if PortTransport.is_hgi80(p.device) is not None
    ]
    try:
        return port_names[0]
    except IndexError:
        return None


async def transport_factory(
    protocol: Callable[[], _ProtocolT],
    /,
    *,
    port_name: None | SerPortName = None,
    port_config: None | dict = None,
    packet_log: None | TextIOWrapper = None,
    packet_dict: None | dict = None,
    **kwargs,
) -> RamsesTransportT:
    """Create and return a Ramses-specific async packet Transport."""

    # The kwargs must be a subset of: loop, extra, and...
    # disable_sending, enforce_include_list, exclude_list, include_list, use_regex

    async def poll_until_connection_made(protocol: _ProtocolT):
        """Poll until the Transport is bound to the Protocol."""
        while protocol._transport is None:
            await asyncio.sleep(0.005)

    def get_serial_instance(ser_name: SerPortName, ser_config: dict) -> Serial:
        # For example:
        # - python client.py monitor 'rfc2217://localhost:5001'
        # - python client.py monitor 'alt:///dev/ttyUSB0?class=PosixPollSerial'

        ser_config = SCH_SERIAL_PORT_CONFIG(ser_config or {})

        try:
            ser_obj = serial_for_url(ser_name, **ser_config)
        except SerialException as exc:
            _LOGGER.error(
                "Failed to open %s (config: %s): %s", ser_name, ser_config, exc
            )
            raise TransportSerialError(
                f"Unable to open the serial port: {ser_name}"
            ) from exc

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
        raise TransportSourceInvalid(
            "Packet source must be exactly one of: packet_dict, packet_log, port_name"
        )

    if (pkt_source := packet_log or packet_dict) is not None:
        return FileTransport(protocol, pkt_source, **kwargs)

    assert port_name is not None  # mypy
    assert port_config is not None  # mypy

    # may: raise TransportSerialError("Unable to open serial port...")
    ser_instance = get_serial_instance(port_name, port_config)

    # TODO: test these...
    if os.name == "nt" or ser_instance.portstr[:7] in ("rfc2217", "socket:"):
        issue_warning()
        # return PortTransport(protocol, ser_instance, **kwargs)

    if kwargs.get(SZ_DISABLE_SENDING) or kwargs.get(SZ_DISABLE_QOS):  # no need for QoS
        transport = PortTransport(protocol, ser_instance, **kwargs)
    else:
        transport = QosTransport(protocol, ser_instance, **kwargs)

    # wait to get (first) signature echo from evofw3/HGI80 (even if disable_sending)
    try:
        await asyncio.wait_for(transport._init_fut, timeout=3)  # signature echo
    except asyncio.TimeoutError as exc:
        raise TransportSerialError("Transport did not initialise successfully") from exc

    # wait for protocol to receive connection_made(transport) (i.e. is quiesced)
    try:
        await asyncio.wait_for(poll_until_connection_made(protocol), timeout=3)
    except asyncio.TimeoutError as exc:
        raise TransportSerialError("Transport did not bind to Protocol") from exc

    return transport


RamsesTransportT = FileTransport | PortTransport | QosTransport
SerPortName = str
