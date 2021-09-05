#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a message (payload into JSON).
"""

import logging
from datetime import timedelta as td
from typing import Any, Optional, Tuple, Union

from .address import Address, dev_id_to_str
from .parsers import parse_payload
from .ramses import CODE_IDX_COMPLEX, RAMSES_CODES, RQ_NO_PAYLOAD

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

__all__ = ["Message"]

ATTR_ALIAS = "alias"  # duplicate

CODE_NAMES = {k: v["name"] for k, v in RAMSES_CODES.items()}

MSG_FORMAT_10 = "|| {:10s} | {:10s} | {:2s} | {:16s} | {:^4s} || {}"
MSG_FORMAT_18 = "|| {:18s} | {:18s} | {:2s} | {:16s} | {:^4s} || {}"

DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Message:
    """The message class; will trap/log all invalid MSGs appropriately."""

    CANT_EXPIRE = 0
    HAS_EXPIRED = 1.2  # i.e. any value >= HAS_EXPIRED
    IS_EXPIRING = 0.8  # expected lifetime == 1.0

    def __init__(self, gwy, pkt) -> None:
        """Create a message from a valid packet."""
        self._gwy = gwy
        self._pkt = pkt

        # prefer Devices but can use Addresses...
        self.src = gwy.device_by_id.get(pkt.src.id, pkt.src)
        self.dst = gwy.device_by_id.get(pkt.dst.id, pkt.dst)
        self._addrs = pkt.addrs

        self.dtm = pkt.dtm
        self._date = pkt._date
        self._time = pkt._time

        self.verb = pkt.verb
        self.seqn = pkt.seqn
        self.code = pkt.code
        self.len = pkt.len
        self.raw_payload = pkt.payload

        self.code_name = CODE_NAMES.get(self.code, f"unknown_{self.code}")
        self._payload = None
        self._str = None

        self.__has_payload = None

        self.__expired = None
        self._is_fragment = None

        self._is_valid = None
        if not self.is_valid:
            raise ValueError(f"Invalid message: {pkt}")

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return repr(self._pkt)  # or str?

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""

        def ctx(pkt) -> str:
            ctx = {True: "[..]", False: "", None: "??"}.get(pkt._ctx, pkt._ctx)
            if not ctx and pkt.payload[:2] not in ("00", "FF"):
                return f"({pkt.payload[:2]})"
            return ctx

        def display_name(dev: Union[Address, Any]) -> str:
            name = dev.schema.get(ATTR_ALIAS) if self._gwy.config.use_aliases else None
            return name[:20] if name else dev_id_to_str(dev.id)

        if self._str is not None:
            return self._str

        if self.src.id == self._addrs[0].id:
            name_0 = display_name(self.src)
            name_1 = "" if self.dst is self.src else display_name(self.dst)
        else:
            name_0 = ""
            name_1 = display_name(self.src)

        _format = MSG_FORMAT_18 if self._gwy.config.use_aliases else MSG_FORMAT_10
        self._str = _format.format(
            name_0, name_1, self.verb, self.code_name, ctx(self._pkt), self.payload
        )
        return self._str

    def __eq__(self, other) -> bool:
        if not isinstance(other, Message):
            return NotImplemented
        return all(
            (
                self.verb == other.verb,
                self.code == other.code,
                self.src == other.src,
                self.dst == other.dst,
                self.raw_payload == other.raw_payload,
            )
        )

    def __lt__(self, other) -> bool:
        if not isinstance(other, Message):
            return NotImplemented
        return self.dtm < other.dtm

    @property
    def _has_payload(self) -> bool:
        """Return False if no payload (may falsely Return True).

        The message (i.e. the raw payload) may still have an idx.
        """

        if self.__has_payload is not None:
            return self.__has_payload

        self.__has_payload = not bool(
            self.len == 1
            # or (self.len == 2 and self.verb == RQ)  # NOTE: see 0016
            or (self.verb == RQ and self.code in RQ_NO_PAYLOAD)
        )

        return self.__has_payload

    @property
    def payload(self) -> Any:  # Any[dict, List[dict]]:
        """Return the payload."""
        return self._payload

    @property
    def _has_array(self) -> bool:
        """Return True if the message's raw payload is an array.

        Does not neccessarily require a valid payload.
        """

        return self._pkt._has_array

    @property
    def _idx(self) -> Optional[dict]:
        """Return the zone_idx/domain_id of a message payload, if any.

        Used to identify the zone/domain that a message applies to. Returns an empty
        dict if there is none such, or None if undetermined.
        """

        #  I --- 01:145038 --:------ 01:145038 3B00 002 FCC8

        IDX_NAMES = {
            _0002: "other_idx",  # non-evohome: hometronics
            _0418: "log_idx",  # can be 2 DHW zones per system
            _10A0: "dhw_idx",  # can be 2 DHW zones per system
            _22C9: "ufh_idx",  # UFH circuit
            _2D49: "other_idx",  # non-evohome: hometronics
            _31D9: "hvac_id",
            _31DA: "hvac_id",
            _3220: "msg_id",
        }  # ALSO: "domain_id", "zone_idx"

        if self._pkt._idx in (True, False) or self.code in CODE_IDX_COMPLEX:
            return {}  # above was: CODE_IDX_COMPLEX + [_3150]:

        if self.code in (_3220,):  # FIXME: should be _SIMPLE
            return {}

        #  I --- 00:034798 --:------ 12:126457 2309 003 0201F4
        if not {self.src.type, self.dst.type} & {"01", "02", "12", "18", "22", "23"}:
            assert self._pkt._idx == "00", "What!! (00)"
            return {}

        #  I 035 --:------ --:------ 12:126457 30C9 003 017FFF
        if self.src.type == self.dst.type and self.src.type not in (
            "01",
            "02",
            "18",
            "23",
        ):
            assert self._pkt._idx == "00", "What!! (01)"
            return {}

        #  I --- 04:029362 --:------ 12:126457 3150 002 0162
        # if not getattr(self.src, "_is_controller", True) and not getattr(
        #     self.dst, "_is_controller", True
        # ):
        #     assert self._pkt._idx == "00", "What!! (10)"
        #     return {}

        #  I --- 04:029362 --:------ 12:126457 3150 002 0162
        # if not (
        #     getattr(self.src, "_is_controller", True)
        #     or getattr(self.dst, "_is_controller", True)
        # ):
        #     assert self._pkt._idx == "00", "What!! (11)"
        #     return {}

        if self.src.type == self.dst.type and not getattr(
            self.src, "_is_controller", True
        ):
            assert self._pkt._idx == "00", "What!! (12)"
            return {}

        index_name = IDX_NAMES.get(
            self.code, "domain_id" if self._pkt._idx[:1] == "F" else "zone_idx"
        )

        return {index_name: self._pkt._idx}

    @property
    def _expired(self) -> Tuple[bool, Optional[bool]]:
        """Return True if the message is dated (does not require a valid payload)."""

        if self.__expired is not None:
            if self.__expired == self.CANT_EXPIRE:
                return False
            if self.__expired >= self.HAS_EXPIRED * 2:  # TODO: should delete?
                return True

        if self.code == _1F09 and self.verb != RQ:  # RQs won't have remaining_seconds
            timeout = td(seconds=self.payload["remaining_seconds"])
            self.__expired = (self._gwy._dt_now() - self.dtm) / timeout
        else:
            self.__expired = self._pkt._expired

        if self.__expired is False:  # treat as never expiring
            _LOGGER.info("%s # cant expire", self._pkt)
            self.__expired = self.CANT_EXPIRE

        elif self.__expired >= self.HAS_EXPIRED:  # TODO: should renew?
            _LOGGER.warning(
                "%s # has expired %s", self._pkt, f"({self.__expired * 100:1.0f}%)"
            )

        # elif self.__expired >= self.IS_EXPIRING:  # this could log multiple times
        #     _LOGGER.error("%s # is expiring", self._pkt)

        # and self.dtm >= self._gwy._dt_now() - td(days=7)  # TODO: should be none >7d?
        return self.__expired >= self.HAS_EXPIRED

    @property
    def _is_fragment_WIP(self) -> bool:
        """Return True if the raw payload is a fragment of a message."""

        if self._is_fragment is not None:
            return self._is_fragment

        # packets have a maximum length of 48 (decimal)
        # if self.code == _000A and self.verb == I_:
        #     self._is_fragment = True if len(???.zones) > 8 else None
        # el
        if self.code == _0404 and self.verb == RP:
            self._is_fragment = True
        elif self.code == _22C9 and self.verb == I_:
            self._is_fragment = None  # max length 24!
        else:
            self._is_fragment = False

        return self._is_fragment

    @property
    def is_valid(self) -> bool:  # Main code here
        """Parse the payload, return True if the message payload is valid."""

        if self._is_valid is None:
            self._payload = parse_payload(self, logger=_LOGGER)
            # self._payload = {k: v for k, v in self._raw_payload.items() if k[:1] != "_"}
            self._is_valid = self._payload is not None
        return self._is_valid
