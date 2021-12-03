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
from .exceptions import InvalidPacketError
from .frame import PacketBase
from .logger import getLogger
from .opentherm import PARAMS_MSG_IDS, SCHEMA_MSG_IDS, STATUS_MSG_IDS
from .ramses import EXPIRES, RAMSES_CODES

from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    MESSAGE_REGEX,
    RP,
    RQ,
    W_,
    __dev_mode__,
)

from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
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
    _0B04,
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
        """Create a packet from a valid frame.

        Will raise InvalidPacketError (or InvalidAddrSetError) if it is invalid.
        """
        super().__init__()

        self._gwy = gwy
        self._dtm = dtm
        self._frame = frame

        self.comment = kwargs.get("comment")
        self.error_text = kwargs.get("err_msg")
        self.raw_frame = kwargs.get("raw_frame")

        self._src, self._dst, self._addrs, self._len = self._validate(
            self._frame[11:40]
        )  # ? raise InvalidPacketError

        self._rssi = frame[0:3]
        self._verb = frame[4:6]
        self._seqn = frame[7:10]
        self._code = frame[41:45]
        self._payload = frame[50:]

        self._timeout = None

        # if DEV_MODE:  # TODO: remove (is for testing only)
        #     _ = self._has_array
        #     _ = self._has_ctl

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        hdr = f' # {self._hdr}{f" ({self._ctx})" if self._ctx else ""}'
        try:
            return f"{self.dtm.isoformat(timespec='microseconds')} ... {self}{hdr}"
        except AttributeError:
            print()

    @property
    def dtm(self) -> dt:
        return self._dtm

    def __eq__(self, other) -> bool:
        if not hasattr(other, "_frame"):
            return NotImplemented
        return self._frame[4:] == other._frame[4:]

    @staticmethod
    def _partition(pkt_line: str) -> Tuple[str, str, str]:
        """Partition a packet line into its three parts.

        Format: packet[ < parser-hint: ...][ * evofw3-err_msg][ # evofw3-comment]
        """

        fragment, _, comment = pkt_line.partition("#")
        fragment, _, err_msg = fragment.partition("*")
        pkt_str, _, _ = fragment.partition("<")  # discard any parser hints
        return map(str.strip, (pkt_str, err_msg, comment))

    @property
    def _expired(self) -> float:
        """Return fraction used of the normal lifetime of packet.

        A packet is 'expired' when >1.0, and should be tombstoned when >2.0. Returns
        False if the packet does not expire (or None is N/A?).

        NB: this is only the fact if the packet has expired, or not. Any opinion to
        whether it *matters* that the packet has expired, is up to higher layers of the
        stack.
        """

        if self._timeout is None:
            self._timeout = pkt_timeout(self) or False

        if self._timeout is False:
            return False

        return (self._gwy._dt_now() - self.dtm) / self._timeout

    def _validate(self, addr_frag) -> None:
        """Validate the packet, and parse the addresses if so (will log all packets).

        Raise an exception (InvalidPacketError, InvalidAddrSetError) if it is not valid.
        """

        try:
            if self.error_text:
                raise InvalidPacketError(self.error_text)

            if not self._frame and self.comment:  # log null pkts only if has a comment
                raise InvalidPacketError("Null packet")

            if not MESSAGE_REGEX.match(self._frame):
                raise InvalidPacketError("Invalid packet structure")

            length = int(self._frame[46:49])
            if len(self._frame[50:]) != length * 2:
                raise InvalidPacketError("Invalid payload length")

            src, dst, addrs = pkt_addrs(addr_frag)  # self._frame[11:40]

        except InvalidPacketError as exc:  # incl. InvalidAddrSetError
            if self._frame or self.error_text:
                _PKT_LOGGER.warning("%s", exc, extra=self.__dict__)
            raise

        _PKT_LOGGER.info("", extra=self.__dict__)
        return src, dst, addrs, length

    @classmethod
    def from_dict(cls, gwy, dtm: str, pkt_line: str):
        """Constructor to create a packet from a saved state (a curated dict)."""
        frame, _, comment = cls._partition(pkt_line)
        return cls(gwy, dt.fromisoformat(dtm), frame, comment=comment)

    @classmethod
    def from_file(cls, gwy, dtm: str, pkt_line: str):
        """Constructor to create a packet from a log file line."""
        frame, err_msg, comment = cls._partition(pkt_line)
        return cls(gwy, dt.fromisoformat(dtm), frame, err_msg=err_msg, comment=comment)

    @classmethod
    def from_port(cls, gwy, dtm: dt, pkt_line: str, raw_line: ByteString = None):
        """Constructor to create a packet from a usb port (HGI80, evofw3)."""
        frame, err_msg, comment = cls._partition(pkt_line)
        return cls(
            gwy, dtm, frame, err_msg=err_msg, comment=comment, raw_frame=raw_line
        )


def pkt_timeout(pkt) -> Optional[td]:  # NOTE: import OtbGateway ??
    """Return the pkt lifetime, or None if the packet does not expire (e.g. 10E0).

    Some codes require a valid payload to best determine lifetime (e.g. 1F09).
    """

    if pkt.verb in (RQ, W_):
        return td(seconds=3)

    if pkt.code in (_0005, _000C, _0404, _10E0):  # 0404 expired by 0006
        return  # TODO: exclude/remove devices caused by corrupt ADDRs?

    if pkt.code == _1FC9 and pkt.verb == RP:
        return  # TODO: check other verbs, they seem variable

    if pkt.code == _1F09:
        return td(seconds=300) if pkt.verb == I_ else td(seconds=3)

    if pkt.code == _000A and pkt._has_array:
        return td(minutes=60)  # sends I /1h

    if pkt.code in (_2309, _30C9) and pkt._has_array:
        return td(minutes=15)  # sends I /sync_cycle

    if pkt.code == _3220:  # FIXME
        # if pkt.payload[4:6] in WRITE_MSG_IDS and Write-Date:
        #     return td(seconds=3)
        if pkt.payload[4:6] in SCHEMA_MSG_IDS:
            return  # SCHEMA_MSG_IDS[pkt.payload[4:6]]
        if pkt.payload[4:6] in PARAMS_MSG_IDS:
            return PARAMS_MSG_IDS[pkt.payload[4:6]]
        if pkt.payload[4:6] in STATUS_MSG_IDS:
            return STATUS_MSG_IDS[pkt.payload[4:6]]
        return td(minutes=3)

    # if pkt.code in (_3B00, _3EF0, ):  # TODO: 0008, 3EF0, 3EF1
    #     return td(minutes=6.7)  # TODO: WIP

    if (code := RAMSES_CODES.get(pkt.code)) and EXPIRES in code:
        return RAMSES_CODES[pkt.code][EXPIRES]

    return td(minutes=60)
