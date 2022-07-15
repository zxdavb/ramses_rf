#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a packet (packet that was received).
"""
from __future__ import annotations

import logging
from datetime import datetime as dt
from datetime import timedelta as td

from .const import __dev_mode__
from .exceptions import InvalidPacketError
from .frame import Frame
from .logger import getLogger
from .opentherm import PARAMS_MSG_IDS, SCHEMA_MSG_IDS, STATUS_MSG_IDS
from .ramses import CODES_SCHEMA, EXPIRES

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)


# these trade memory for speed
_TD_SECONDS_000 = td(seconds=0)
_TD_SECONDS_003 = td(seconds=3)
_TD_SECONDS_360 = td(seconds=360)
_TD_MINUTES_005 = td(minutes=5)
_TD_MINUTES_060 = td(minutes=60)


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

_PKT_LOGGER = getLogger(f"{__name__}_log", pkt_log=True)


def fraction_expired(age: td, age_limit: td) -> float:
    """Return the packet's age as fraction of its 'normal' lifetime."""
    return (age - _TD_SECONDS_003) / age_limit


class Packet(Frame):
    """The Packet class (packets that were received).

    They have a datetime (when received) an RSSI, and other meta-fields.
    """

    _dtm: dt
    _rssi: str

    def __init__(self, gwy, dtm: dt, frame: str, **kwargs) -> None:
        """Create a packet from a string (actually from f"{RSSI} {frame}").

        Will raise InvalidPacketError if it is invalid.
        """

        super().__init__(frame[4:])  # remove RSSI

        self._gwy = gwy
        self._dtm: dt = dtm

        self._rssi: str = frame[0:3]

        self.comment: str = kwargs.get("comment", "")
        self.error_text: str = kwargs.get("err_msg", "")
        self.raw_frame: str = kwargs.get("raw_frame", "")

        self._timeout: None | bool | td = None  # track pkt expiry

        # if DEV_MODE:  # TODO: remove (is for testing only)
        #     _ = self._has_array
        #     _ = self._has_ctl

        self._validate(strict_checking=False)

    def _validate(self, *, strict_checking: bool = None) -> None:
        """Validate the packet, and parse the addresses if so (will log all packets).

        Raise an exception InvalidPacketError (InvalidAddrSetError) if it is not valid.
        """

        try:
            if self.error_text:
                raise InvalidPacketError(self.error_text)

            if not self._frame and self.comment:  # log null pkts only if has a comment
                raise InvalidPacketError("Null packet")

            super()._validate(strict_checking=strict_checking)  # no RSSI

            _PKT_LOGGER.info("", extra=self.__dict__)  # the packet.log line

        except InvalidPacketError as exc:  # incl. InvalidAddrSetError
            if self._frame or self.error_text:
                _PKT_LOGGER.warning("%s", exc, extra=self.__dict__)
            raise exc

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        try:
            hdr = f' # {self._hdr}{f" ({self._ctx})" if self._ctx else ""}'
        except (InvalidPacketError, NotImplementedError):
            hdr = ""
        try:
            dtm = self.dtm.isoformat(timespec="microseconds")
        except AttributeError:
            dtm = dt.min.isoformat(timespec="microseconds")
        return f"{dtm} ... {self}{hdr}"

    def __str__(self) -> str:
        """Return an brief readable string representation of this object."""
        return super().__repr__()

    @property
    def dtm(self) -> dt:
        return self._dtm

    def __eq__(self, other) -> bool:
        if not hasattr(other, "_frame"):
            return NotImplemented
        return self._frame[4:] == other._frame[4:]

    @staticmethod
    def _partition(pkt_line: str) -> tuple[str, str, str]:  # map[str]
        """Partition a packet line into its three parts.

        Format: packet[ < parser-hint: ...][ * evofw3-err_msg][ # evofw3-comment]
        """

        fragment, _, comment = pkt_line.partition("#")
        fragment, _, err_msg = fragment.partition("*")
        pkt_str, _, _ = fragment.partition("<")  # discard any parser hints
        return map(str.strip, (pkt_str, err_msg, comment))  # type: ignore[return-value]

    @property
    def _expired(self) -> bool | float:
        """Return the used fraction of the packet's 'normal' lifetime.

        A packet is 'expired' when >1.0 (should it be tombstoned when >2.0?). Returns
        False if the packet does not expire (e.g. a 10E0).

        NB: this is only the fact if the packet has expired, or not. Any opinion to if
        it *matters* that the packet has expired, is up to higher layers of the stack.
        """

        if self._timeout is None:  # add 3s to account for timing drift
            self._timeout = pkt_timeout(self) or False

        if self._timeout is False:
            return False

        return fraction_expired(
            self._gwy._dt_now() - self.dtm, self._timeout  # type: ignore[arg-type]
        )

    @classmethod
    def from_dict(cls, gwy, dtm: str, pkt_line: str):
        """Create a packet from a saved state (a curated dict)."""
        frame, _, comment = cls._partition(pkt_line)
        return cls(gwy, dt.fromisoformat(dtm), frame, comment=comment)

    @classmethod
    def from_file(cls, gwy, dtm: str, pkt_line: str):
        """Create a packet from a log file line."""
        frame, err_msg, comment = cls._partition(pkt_line)
        return cls(gwy, dt.fromisoformat(dtm), frame, err_msg=err_msg, comment=comment)

    @classmethod
    def from_port(cls, gwy, dtm: dt, pkt_line: str, raw_line: bytes = None):
        """Create a packet from a USB port (HGI80, evofw3)."""
        frame, err_msg, comment = cls._partition(pkt_line)
        return cls(
            gwy, dtm, frame, err_msg=err_msg, comment=comment, raw_frame=raw_line
        )


def pkt_timeout(pkt: Packet) -> None | td:  # NOTE: import OtbGateway ??
    """Return the pkt lifetime, or None if the packet does not expire (e.g. 10E0).

    Some codes require a valid payload to best determine lifetime (e.g. 1F09).
    """

    if pkt.verb in (RQ, W_):
        return _TD_SECONDS_000

    if pkt.code in (
        Code._0005,
        Code._000C,
        Code._0404,
        Code._10E0,
    ):  # 0404 expired by 0006
        return None  # TODO: exclude/remove devices caused by corrupt ADDRs?

    if pkt.code == Code._1FC9 and pkt.verb == RP:
        return None  # TODO: check other verbs, they seem variable

    if pkt.code == Code._1F09:  # sends I /sync_cycle
        # can't do better than 300s with reading the payload
        return _TD_SECONDS_360 if pkt.verb == I_ else _TD_SECONDS_000

    if pkt.code == Code._000A and pkt._has_array:
        return _TD_MINUTES_060  # sends I /1h

    if pkt.code in (Code._2309, Code._30C9) and pkt._has_array:  # sends I /sync_cycle
        return _TD_SECONDS_360

    if pkt.code == Code._3220:  # FIXME
        # if pkt.payload[4:6] in WRITE_MSG_IDS and Write-Data:  # TODO
        #     return _TD_SECONDS_003
        if pkt.payload[4:6] in SCHEMA_MSG_IDS:
            return None  # SCHEMA_MSG_IDS[pkt.payload[4:6]]
        if pkt.payload[4:6] in PARAMS_MSG_IDS:
            return PARAMS_MSG_IDS[pkt.payload[4:6]]
        if pkt.payload[4:6] in STATUS_MSG_IDS:
            return STATUS_MSG_IDS[pkt.payload[4:6]]
        return _TD_MINUTES_005

    # if pkt.code in (Code._3B00, Code._3EF0, ):  # TODO: 0008, 3EF0, 3EF1
    #     return td(minutes=6.7)  # TODO: WIP

    if (code := CODES_SCHEMA.get(pkt.code)) and EXPIRES in code:
        return CODES_SCHEMA[pkt.code][EXPIRES]

    return _TD_MINUTES_060
