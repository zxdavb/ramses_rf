#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a packet (packet that was received).
"""

import logging
from datetime import datetime as dt
from datetime import timedelta as td
from typing import ByteString, Optional, Tuple

from .address import pkt_addrs
from .const import DONT_CREATE_ENTITIES, MESSAGE_REGEX

# from .devices import Device  # TODO: fix cyclic reference
from .exceptions import CorruptAddrSetError, CorruptPacketError, CorruptStateError
from .frame import PacketBase
from .logger import getLogger
from .ramses import EXPIRES, RAMSES_CODES

from .const import I_, RP, RQ, W_, __dev_mode__  # noqa: F401, isort: skip
from .const import (  # noqa: F401, isort: skip
    _0001,
    _0002,
    _0004,
    _0005,
    _0006,
    _0008,
    _0009,
    _000A,
    _000C,
    _000E,
    _0016,
    _0100,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _1030,
    _1060,
    _1090,
    _10A0,
    _10E0,
    _1100,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _1F09,
    _1F41,
    _1FC9,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2D49,
    _2E04,
    _30C9,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3220,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

_PKT_LOGGER = getLogger(f"{__name__}_log", pkt_log=True)


class Packet(PacketBase):
    """The packet class; should trap/log all invalid PKTs appropriately."""

    def __init__(self, gwy, dtm: dt, frame: str, **kwargs) -> None:
        """Create a packet from a valid frame."""
        super().__init__()

        self._gwy = gwy
        self.dtm = dtm

        # assert kwargs.get("dtm_str") is None or (
        #     kwargs.get("dtm_str") == dtm.isoformat(timespec="microseconds")
        # ), "dtm_str doesn't match dtm.isoformat"

        self._date, self._time = (
            kwargs.get("dtm_str") or dtm.isoformat(timespec="microseconds")
        ).split(
            "T"
        )  # assume kwargs.get("dtm_str") == dtm.isoformat(...)

        # self.created = dtm.timestamp()  # HACK: used by logger
        # self.msecs = (self.created - int(self.created)) * 1000

        self.rssi = frame[0:3]
        self.packet = frame[4:]
        self.comment = kwargs.get("comment")
        self.error_text = kwargs.get("err_msg")
        self.raw_frame = kwargs.get("raw_frame")

        # addrs are populated in self.is_valid()
        self.addrs = [None] * 3
        self.src = self.dst = None

        self._is_valid = None
        if not self.is_valid:
            raise ValueError(f"Invalid packet: {dtm} {frame}")

        self.verb = frame[4:6]
        self.seqn = frame[7:10]
        self.code = frame[41:45]
        self.len = int(frame[46:49])
        self.payload = frame[50:]

        self.__timeout = None

        # _ = self._has_array  # TODO: remove (is for testing only)
        # _ = self._has_ctl  # # TODO: remove (is for testing only)

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""

        hdr = f' # {self._hdr}{f" ({self._ctx})" if self._ctx else ""}'
        return f"{self.dtm.isoformat(timespec='microseconds')} {self.rssi} {self}{hdr}"

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""

        return self.packet

    def __eq__(self, other) -> bool:
        if not hasattr(other, "packet"):
            return NotImplemented
        return self.packet == other.packet

    @staticmethod
    def _partition(pkt_line: str) -> Tuple[str, str, str]:
        """Partition a packet line into its three parts.

        Format: packet[ < parser-hint: ...][ * evofw3-err_msg][ # evofw3-comment]
        """

        fragment, _, comment = pkt_line.partition("#")
        fragment, _, err_msg = fragment.partition("*")
        pkt_str, _, _ = fragment.partition("<")  # discard any parser hints
        return (
            pkt_str.strip(),
            f" * {err_msg.strip()}" if err_msg else " *" if "*" in pkt_line else "",
            f" # {comment.strip()}" if comment else "",
        )

    @property
    def _expired(self) -> float:
        """Return fraction used of the normal lifetime of packet.

        A packet is 'expired' when >1.0, and should be tombstoned when >2.0. Returns
        False if the packet does not expire.
        """

        if self.__timeout is None:
            self.__timeout = pkt_timeout(self) or False

        if self.__timeout is False:
            return False

        return (self._gwy._dt_now() - self.dtm) / self.__timeout

    @property
    def is_valid(self) -> bool:
        """Return True if the packet is valid (will log all packets, regardless).

        Will raise CorruptPacketError is the packe is not valid.
        """

        def invalid_addresses(addr_set: str) -> Optional[bool]:
            """Return True if the address fields are invalid (create any addresses)."""
            try:
                self.src, self.dst, self.addrs = pkt_addrs(addr_set)
                # print(pkt_addrs.cache_info())
            except CorruptAddrSetError as err:
                raise CorruptPacketError(err)

        if self._is_valid is not None or not self.packet:
            return self._is_valid

        self._is_valid = False
        if self.error_text:  # log all packets with an error
            _PKT_LOGGER.warning("%s < Bad packet:", self, extra=self.__dict__)
            raise CorruptPacketError(f"Bad packet: {self.error_text}")

        if not self.packet and self.comment:  # log null packets only if has a comment
            _PKT_LOGGER.warning("%s < Null packet", self, extra=self.__dict__)
            raise CorruptPacketError(f"Bad packet: {self.comment}")

        # TODO: these packets shouldn't go to the packet log, only STDERR?
        if not MESSAGE_REGEX.match(f"{self.rssi} {self.packet}"):
            err_msg = "invalid packet structure"
        elif int(self.packet[42:45]) * 2 != len(self.packet[46:]):
            err_msg = "mismatched payload length"
        elif invalid_addresses(self.packet[7:36]):
            err_msg = "invalid packet addresses"
        else:
            _PKT_LOGGER.info("%s", self.packet, extra=self.__dict__)
            self._is_valid = True
            return True

        _PKT_LOGGER.warning("%s < Bad packet: %s", self, err_msg, extra=self.__dict__)
        raise CorruptPacketError(f"Bad packet: {err_msg}")

    @classmethod
    def from_dict(cls, gwy, dtm: str, pkt_line: str):
        """Constructor to create a packet from a saved state (a curated dict)."""
        frame, _, comment = cls._partition(pkt_line)
        return cls(gwy, dt.fromisoformat(dtm), frame, comment=comment, dtm_str=dtm)

    @classmethod
    def from_file(cls, gwy, dtm: str, pkt_line: str):
        """Constructor to create a packet from a log file line."""
        frame, err_msg, comment = cls._partition(pkt_line)
        return cls(
            gwy,
            dt.fromisoformat(dtm),
            frame,
            dtm_str=dtm,
            err_msg=err_msg,
            comment=comment,
        )

    @classmethod
    def from_port(cls, gwy, dtm: dt, pkt_line: str, raw_line: ByteString = None):
        """Constructor to create a packet from a usb port (HGI80, evofw3)."""
        frame, err_msg, comment = cls._partition(pkt_line)
        return cls(
            gwy, dtm, frame, err_msg=err_msg, comment=comment, raw_frame=raw_line
        )


def pkt_timeout(pkt) -> Optional[float]:  # NOTE: import OtbGateway ??
    """Return the pkt lifetime.

    Will return None if the packet does not expire (e.g. 10E0).

    Some codes best require a valid payload, e.g.: 1F09
    """

    timeout = None

    if pkt.verb in (RQ, W_):
        timeout = td(seconds=3)

    elif pkt.code in (_0005, _000C, _10E0):
        return  # TODO: exclude/remove devices caused by corrupt ADDRs?

    elif pkt.code == _1FC9 and pkt.verb == RP:
        return  # TODO: check other verbs, they seem variable

    elif pkt.code == _1F09:
        timeout = td(seconds=300)  # usu: 180-300

    elif pkt.code == _000A and pkt._has_array:
        timeout = td(minutes=60)  # sends I /1h

    elif pkt.code in (_2309, _30C9) and pkt._has_array:
        timeout = td(minutes=15)  # sends I /sync_cycle

    elif pkt.code == _3220:
        from .devices import OtbGateway  # to prevent circular references

        if pkt.payload[4:6] in OtbGateway.SCHEMA_MSG_IDS:
            timeout = None
        elif pkt.payload[4:6] in OtbGateway.PARAMS_MSG_IDS:
            timeout = td(minutes=60)
        # elif pkt.payload[4:6] in OtbGateway.STATUS_MSG_IDS:
        #     timeout = td(minutes=5)
        else:
            timeout = td(minutes=5)

    # elif pkt.code in (_3B00, _3EF0, ):  # TODO: 0008, 3EF0, 3EF1
    #     timeout = td(minutes=6.7)  # TODO: WIP

    elif pkt.code in RAMSES_CODES:
        timeout = RAMSES_CODES[pkt.code].get(EXPIRES)

    return timeout or td(minutes=60)


def OUT_create_devices(this: Packet) -> None:
    """Discover and create any new devices."""
    from .devices import Device  # TODO: remove this

    if this.src.type in ("01", "23") and this.src is not this.dst:  # TODO: all CTLs
        this.src = this._gwy._get_device(this.src, ctl_addr=this.src)
        ctl_addr = this.src if this._gwy.config.enable_eavesdrop else None
        this._gwy._get_device(this.dst, ctl_addr=ctl_addr)

    elif this.dst.type in ("01", "23") and this.src is not this.dst:  # all CTLs
        this.dst = this._gwy._get_device(this.dst, ctl_addr=this.dst)
        ctl_addr = this.dst if this._gwy.config.enable_eavesdrop else None
        this._gwy._get_device(this.src, ctl_addr=ctl_addr)

    # this should catch all non-controller (and *some* controller) devices
    elif this.src is this.dst:
        this._gwy._get_device(this.src)

    # otherwise one will be a controller, *unless* dst is in ("--", "63")
    elif isinstance(this.src, Device) and this.src._is_controller:
        this._gwy._get_device(this.dst, ctl_addr=this.src)

    # TODO: may create a controller that doesn't exist
    elif isinstance(this.dst, Device) and this.dst._is_controller:
        this._gwy._get_device(this.src, ctl_addr=this.dst)

    else:
        # beware:  I --- --:------ --:------ 10:078099 1FD4 003 00F079
        [this._gwy._get_device(d) for d in (this.src, this.dst)]

    # where possible, swap each Address for its corresponding Device
    this.src = this._gwy.device_by_id.get(this.src.id, this.src)
    if this.dst is not None:
        this.dst = this._gwy.device_by_id.get(this.dst.id, this.dst)


def OUT_process_pkt(pkt: Packet) -> Optional[bool]:
    """Process the (valid) packet's metadata (but dont process the payload)."""

    if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
        _LOGGER.info(pkt)

    if not pkt.is_valid or pkt._gwy.config.reduce_processing >= DONT_CREATE_ENTITIES:
        return False

    try:  # process the packet meta-data
        # TODO: This will need to be removed for HGI80-impersonation
        if pkt.src.type != "18":  # 18:/RQs are unreliable, but corresponding RPs?
            OUT_create_devices(pkt)  # from pkt header & from pkt payload (e.g. 000C)

    except (AssertionError, NotImplementedError) as err:
        (_LOGGER.error if DEV_MODE else _LOGGER.warning)(
            "%s << %s", pkt._pkt, f"{err.__class__.__name__}({err})"
        )
        return False  # NOTE: use raise only when debugging

    except (AttributeError, LookupError, TypeError, ValueError) as err:
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)(
            "%s << %s", pkt._pkt, f"{err.__class__.__name__}({err})"
        )
        return False  # NOTE: use raise only when debugging

    except CorruptStateError as err:  # TODO: add CorruptPacketError
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)("%s << %s", pkt._pkt, err)
        return False  # TODO: bad pkt, or Schema

    pkt._gwy._prev_pkt = pkt
