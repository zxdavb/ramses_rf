#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#


# TODO:
# - make use_regex work again
# - chase down gwy.config.disable_discovery
# - chase down / check deprecation
# - check: READER/POLLER & WRITER tasks


"""RAMSES RF - RAMSES-II compatible packet transport."""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime as dt
from io import TextIOWrapper
from string import printable
from typing import Any, Callable, Iterable, TypeVar

import serial_asyncio
from serial import Serial, SerialException, serial_for_url  # type: ignore[import]
from serial.tools.list_ports import comports  # type: ignore[import]

from .address import NON_DEV_ADDR, NUL_DEV_ADDR
from .command import Command
from .const import DEV_TYPE, DEV_TYPE_MAP, SZ_DEVICE_ID, __dev_mode__
from .exceptions import InvalidPacketError
from .helpers import dt_now
from .packet import Packet
from .schemas import (  # TODO: SZ_INBOUND, SZ_OUTBOUND
    SCH_SERIAL_PORT_CONFIG,
    SZ_BLOCK_LIST,
    SZ_CLASS,
    SZ_KNOWN_LIST,
    SZ_USE_REGEX,
)

# from .version import VERSION

# if TYPE_CHECKING:
#     from io import TextIOWrapper


_MsgProtocolT = TypeVar("_MsgProtocolT", bound="asyncio.Protocol")
PktTransportT = TypeVar("PktTransportT", bound="_TranFilter")
_SerPortName = str


DONT_CREATE_MESSAGES = 3  # duplicate

SZ_POLLER_TASK = "poller_task"
SZ_WRITER_TASK = "writer_task"
SZ_READER_TASK = "reader_task"

SZ_FINGERPRINT = "fingerprint"
SZ_KNOWN_HGI = "known_hgi"
SZ_IS_EVOFW3 = "is_evofw3"
SZ_EVOFW3_FLAG = "evo_flag"  # FIXME: is kwarg from upper layer: beware changing value

TIP = f", configure the {SZ_KNOWN_LIST}/{SZ_BLOCK_LIST} as required"

MIN_GAP_BETWEEN_WRITES = 0.2  # seconds


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class TransportError(Exception):
    """Base class for exceptions in this module."""

    pass


class InvalidSourceError(TransportError):
    """The packet source is not valid type."""

    pass


def _normalise(pkt_line: str) -> str:
    """Perform any (transparent) frame-level hacks, as required at (near-)RF layer.

    Goals:
    - ensure an evofw3 provides the exact same output as a HGI80
    - handle 'strange' packets (e.g. I/08:/0008)
    """

    # psuedo-RAMSES-II packets...
    if pkt_line[10:14] in (" 08:", " 31:") and pkt_line[-16:] == "* Checksum error":
        pkt_line = pkt_line[:-17] + " # Checksum error (ignored)"
    else:
        return pkt_line.strip()

    # _LOGGER.warning("%s < Packet line has been normalised", pkt_line)
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


class _FileTransportWrapper(asyncio.ReadTransport):  # Read-only
    """Homogonise the two types of Transport (serial and file/dict)."""

    _extra: dict  # mypy hint

    def __init__(
        self,
        pkt_source: dict | TextIOWrapper,
        protocol: None | _MsgProtocolT = None,
        extra: None | dict = None,
        loop: None | asyncio.AbstractEventLoop = None,
        **kwargs,
    ) -> None:
        super().__init__(extra={} if extra is None else extra)

        self._protocol = protocol
        self._loop: asyncio.AbstractEventLoop = loop or asyncio.get_running_loop()

        self._closing: bool = False
        self._reading: bool = False

        self._loop.call_soon(self._protocol.connection_made, self)

    @property
    def loop(self):
        """The asyncio event loop as used by SerialTransport."""
        return self._loop

    def get_extra_info(self, name, default=None):
        """Get optional transport information."""
        return self._extra.get(name, default)

    def is_closing(self) -> bool:
        """Return True if the transport is closing or closed."""
        return self._closing

    def is_reading(self):
        """Return True if the transport is receiving."""
        return self._reading

    def pause_reading(self) -> None:
        """Pause the receiving end (No data to protocol.data_received())."""
        self._is_reading = False

    def resume_reading(self) -> None:
        """Resume the receiving end."""
        self._is_reading = True


class _PortTransportWrapper(serial_asyncio.SerialTransport):  # Read-write
    """Homogonise the two types of Transport (serial and file/dict)."""

    def __init__(
        self,
        pkt_source: Serial,
        protocol: None | _MsgProtocolT = None,
        extra: None | dict = None,
        loop: None | asyncio.AbstractEventLoop = None,
    ) -> None:
        super().__init__(loop or asyncio.get_running_loop(), protocol, pkt_source)

        self._extra: dict = {} if extra is None else extra

    def get_extra_info(self, name, default=None):
        """Get optional transport information."""
        if name == "serial":
            return super().get_extra_info(name, default=default)
        return self._extra.get(name, default)

    def _read_ready(self) -> None:  # redirect data to self._bytes_received()
        try:
            data: bytes = self._serial.read(self._max_read_size)
        except SerialException as e:
            self._close(exc=e)
            return

        if data:
            self._bytes_received(data)  # was: self._protocol.data_received(data)

    def _bytes_received(data: bytes) -> None:  # raise NotImplementedError
        raise NotImplementedError

    def is_reading(self) -> None:
        """Return True if the transport is receiving."""
        return self._has_reader


class _BaseTransport(asyncio.Transport):
    """Base class for transports."""

    _extra: dict
    _loop: asyncio.AbstractEventLoop
    _protocol: _MsgProtocolT

    def __init__(self, pkt_source: dict | TextIOWrapper, *args, **kwargs) -> None:
        super().__init__(pkt_source, *args, **kwargs)

        self._pkt_source = pkt_source  # aka: super()._serial

        self._this_pkt: Packet = None
        self._prev_pkt: Packet = None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._protocol}, {self._pkt_source})"

    def _dt_now(self) -> dt:  # raise NotImplementedError
        raise NotImplementedError

    def get_extra_info(self, name: str, default=None) -> Any:
        """Get optional transport information."""
        if name == "dt_now":
            return self._dt_now()
        return super().get_extra_info(name, default=default)

    # def set_protocol(self, protocol: _MsgProtocolT) -> None:
    #     """Set a new protocol."""
    #     self._protocol = protocol

    # def get_protocol(self) -> None:
    #     """Return the current protocol."""
    #     return self._protocol

    # TODO: call_soon(self._protocol.data_received, pkt)
    def _pkt_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted Packets to the protocol's callback.

        Also maintain _prev_pkt, _this_pkt attrs.
        """

        try:
            if self._protocol:
                self._protocol.data_received(pkt)  # TODO: should be a call_soon?
        except AssertionError as exc:  # protect from upper-layer callbacks
            _LOGGER.exception("%s < exception from msg layer: %s", pkt, exc)


class _TranFilter(_BaseTransport):  # mixin
    """"""

    def __init__(
        self,
        *args,
        enforce_include_list: bool = False,
        exclude_list: None | dict = None,
        include_list: None | dict = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)

        self.enforce_include = enforce_include_list
        self._exclude = list(exclude_list.keys())
        self._include = list(include_list.keys()) + [NON_DEV_ADDR.id, NUL_DEV_ADDR.id]
        self._unwanted: list = []  # not: [NON_DEV_ADDR.id, NUL_DEV_ADDR.id]

        for key in (SZ_DEVICE_ID, SZ_FINGERPRINT, SZ_KNOWN_HGI):
            self._extra[key] = None

        known_hgis = [
            k for k, v in exclude_list.items() if v.get(SZ_CLASS) == DEV_TYPE.HGI
        ]
        if not known_hgis:
            _LOGGER.info(f"The {SZ_KNOWN_LIST} should include the gateway (HGI)")
        else:
            self._extra[SZ_KNOWN_HGI] = known_hgis[0]
        if len(known_hgis) > 1:
            _LOGGER.info(f"The {SZ_KNOWN_LIST} should include only one gateway (HGI)")

        self._evofw_flag = kwargs.get(SZ_EVOFW3_FLAG, None)  # gwy.config.evofw_flag
        self._use_regex = kwargs.get(SZ_USE_REGEX, {})  # #    gwy.config.use_regex

        # for the pkt log, if any, also serves to discover the HGI's device_id
        # if not self._disable_sending:
        self._write_fingerprint_pkt()

    def _write_fingerprint_pkt(self) -> None:
        # FIXME: if not read-only...
        cmd = Command._puzzle()
        self._extra[SZ_FINGERPRINT] = cmd.payload
        # use write, not send_data to bypass throttles
        self.write(bytes(str(cmd), "ascii") + b"\r\n")

    def _is_wanted_addrs(self, src_id: str, dst_id: str) -> bool:
        """Return True if the packet is not to be filtered out.

        In any one packet, an excluded device_id 'trumps' an included device_id.
        """

        for dev_id in dict.fromkeys((src_id, dst_id)):  # removes duplicates
            # TODO: _unwanted exists since (in future) stale entries need to be removed

            if dev_id in self._exclude or dev_id in self._unwanted:
                return False

            if dev_id == self._extra[SZ_DEVICE_ID]:  # even if not in include list
                continue

            if dev_id not in self._include and self.enforce_include:
                return False

            if dev_id[:2] != DEV_TYPE_MAP.HGI:
                continue

            if dev_id not in self._include and self._extra[SZ_DEVICE_ID]:
                self._unwanted.append(dev_id)

                _LOGGER.warning(
                    f"Blacklisting a Foreign gateway (or is it a HVAC?): {dev_id}"
                    f" (Active gateway is: {self._extra[SZ_DEVICE_ID]}){TIP}"
                )

            if dev_id == self._extra[SZ_KNOWN_HGI] or (
                dev_id == src_id
                and self._this_pkt.payload == self._extra[SZ_FINGERPRINT]
            ):
                self._extra[SZ_DEVICE_ID] = dev_id

                if dev_id not in self._include:
                    _LOGGER.warning(f"Active gateway set to: {dev_id}{TIP}")

        return True

    def _pkt_received(self, pkt: Packet) -> None:
        """Validate a Packet and dispatch it to the protocol's callback."""

        if self._protocol and self._is_wanted_addrs(pkt.src.id, pkt.dst.id):
            super()._pkt_received(pkt)


# ### Read-Only Transports for dict / log file ########################################
class FileTransport(_TranFilter, _FileTransportWrapper):
    """Parse a file (or a dict) for packets."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._is_reading: bool = False
        self._protocol.pause_writing()  # but protocol would know is a R/O transport

        reader = self._loop.create_task(self._ensure_reader())
        reader.add_done_callback(self._handle_reader_done)
        self._extra[SZ_READER_TASK]: dict[str, asyncio.Task] = reader

        # FIXME: remove this somehow
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

    def _ensure_reader(self) -> None:  # TODO
        if self._extra[SZ_READER_TASK]:
            return
        self._is_reading = True

    def _remove_reader(self):
        if self._extra[SZ_READER_TASK]:
            self._loop.remove_reader(self._serial.fileno())  # FIXME
            self._extra[SZ_READER_TASK] = None

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
                self._frame_received(dtm_pkt_line[:26], dtm_pkt_line[27])  # .rstrip())?
                await asyncio.sleep(0)  # NOTE: big performance penalty if delay >0

        else:
            raise InvalidSourceError(
                f"Packet source is not dict or TextIOWrapper: {self._pkt_source:!r}"
            )

    async def _handle_reader_done(self) -> None:  # TODO
        """Loop through the packet source for Frames and process them."""

        if self._extra[SZ_READER_TASK]:
            return
        self._is_reading = True

    async def _frame_received(self, dtm: str, line: str) -> None:
        """Make a Packet from the Frame and process it."""
        self._dt_str_ = line[:26]  # HACK: FIXME: remove
        # line = _regex_hack(line, self._use_regex.get(SZ_INBOUND, {}))
        try:
            pkt = Packet.from_file(dtm, line)  # is OK for when src is dict
        except (InvalidPacketError, ValueError):  # VE from dt.fromisoformat()
            return

        self._this_pkt, self._prev_pkt = pkt, self._this_pkt  # TODO:
        self._pkt_received(pkt)

    # TODO: remove me (a convenience wrapper for breakpoint)
    def _pkt_received(self, pkt: Packet) -> None:
        super()._pkt_received(pkt)

    # TODO: remove me (a convenience wrapper for breakpoint)
    def write(self, data) -> None:  # convenience for breakpoint
        super().write(data)

    def close(self, exc: None | Exception = None) -> None:
        """Close the transport (calls self._protocol.connection_lost())."""
        if self._closing:
            return
        self._closing = True

        reader: asyncio.Task = self._extra.get(SZ_READER_TASK)
        if reader:
            reader.cancel()

        self._loop.call_soon(self._protocol.connection_lost, exc)


# ### Read-Write Transport for serial port ############################################
class PortTransport(_TranFilter, _PortTransportWrapper):  # from a serial port
    _recv_buffer: bytes = b""

    def get_extra_info(self, name, default=None):
        """Get optional transport information."""
        if name != SZ_IS_EVOFW3:
            return super().get_extra_info(name, default)

        # can probably cache this info, ?as evofw3 & HGI always use different ports
        # for now, leave that up to transport
        return bool(
            {
                x.name: x.product
                for x in comports()
                if x.name == self.serial.name and "evofw3" in x.product
            }
        )

    def _dt_now(self) -> dt:
        """Return a precise datetime, using the curent dtm."""

        return dt_now()

    # def _ensure_reader(self):  # TODO: remove
    #     if (not self._has_reader) and (not self._closing):
    #         self._loop.add_reader(self._serial.fileno(), self._read_ready)
    #         self._has_reader = True

    def _bytes_received(self, data: bytes) -> None:
        """Make a Frame from the data and process it."""

        def bytes_received(data: bytes) -> Iterable[tuple[dt, bytes]]:
            self._recv_buffer += data
            if b"\r\n" in self._recv_buffer:
                lines = self._recv_buffer.split(b"\r\n")
                self._recv_buffer = lines[-1]
                for line in lines[:-1]:
                    yield self._dt_now(), line

        for dtm, raw_line in bytes_received(data):
            self._frame_received(dtm, _normalise(_str(raw_line)))

    # TODO: remove raw_line attr from Packet()
    def _frame_received(self, dtm: str, line: str) -> None:
        """Make a Packet from the Frame and process it."""
        # line = _regex_hack(line, self._use_regex.get(SZ_INBOUND, {}))
        try:
            pkt = Packet.from_port(dtm, line)
        except (InvalidPacketError, ValueError):  # VE from dt.fromisoformat()
            return

        self._this_pkt, self._prev_pkt = pkt, self._this_pkt  # TODO:
        self._pkt_received(pkt)

    # TODO: remove me (a convenience wrapper for breakpoint)
    def _pkt_received(self, pkt: Packet) -> None:
        super()._pkt_received(pkt)

    # TODO: remove me (a convenience wrapper for breakpoint)
    def write(self, data) -> None:  # convenience for breakpoint
        super().write(data)


# ### Read-Write Transport *with QoS* for serial port #################################
class QosTransport(PortTransport):  # from a serial port, includes QoS
    pass


def transport_factory(
    protocol: Callable[[], _MsgProtocolT],
    /,
    *,
    port_name: None | _SerPortName = None,
    port_config: None | dict = None,
    packet_log: None | TextIOWrapper = None,
    packet_dict: None | dict = None,
    **kwargs,
) -> PktTransportT:
    # expected kwargs include:
    #  disable_sending: bool = None,
    #  enforce_include_list: bool = None,
    #  exclude_list: None | dict = None,
    #  include_list: None | dict = None,

    def get_serial_instance(ser_name: _SerPortName, ser_config: dict) -> Serial:
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

        # FTDI on Posix/Linux would be a common environment for this library...
        try:
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

    if len([x for x in (packet_dict, packet_log, port_name) if x is not None]) != 1:
        raise TypeError("must have exactly one of: serial port, pkt log or pkt dict")

    if (pkt_source := packet_log or packet_dict) is not None:
        return FileTransport(pkt_source, protocol, **kwargs)

    assert port_name is not None  # mypy: instead of: _type: ignore[arg-type]
    assert port_config is not None  # mypy: instead of: _type: ignore[arg-type]

    ser_instance = get_serial_instance(port_name, port_config)  # ?SerialException

    # TODO: ensure poller for NT
    if os.name == "nt" or ser_instance.portstr[:7] in ("rfc2217", "socket:"):
        issue_warning()
        return PortTransport(ser_instance, protocol, **kwargs)

    if kwargs.pop("disable_sending"):  # no need for QoS
        return PortTransport(ser_instance, protocol, **kwargs)

    return QosTransport(ser_instance, protocol, **kwargs)
