#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a message (payload into JSON).
"""
from __future__ import annotations

import logging
import re
from datetime import datetime as dt
from datetime import timedelta as td
from functools import lru_cache

from .address import Address
from .const import (
    DEV_TYPE_MAP,
    SZ_DHW_IDX,
    SZ_DOMAIN_ID,
    SZ_LOG_IDX,
    SZ_UFH_IDX,
    SZ_ZONE_IDX,
    __dev_mode__,
)
from .exceptions import InvalidPacketError, InvalidPayloadError
from .packet import fraction_expired
from .parsers import PAYLOAD_PARSERS, parser_unknown
from .ramses import CODE_IDX_COMPLEX, CODES_SCHEMA, RQ_IDX_COMPLEX
from .schemas import SZ_ALIAS

# TODO:
# long-format msg.__str__ - alias columns don't line up


# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    F9,
    FA,
    FC,
    FF,
    Code,
)


__all__ = ["Message"]

CODE_NAMES = {k: v["name"] for k, v in CODES_SCHEMA.items()}

MSG_FORMAT_10 = "|| {:10s} | {:10s} | {:2s} | {:16s} | {:^4s} || {}"
MSG_FORMAT_18 = "|| {:18s} | {:18s} | {:2s} | {:16s} | {:^4s} || {}"

DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Message:
    """The message class; will trap/log all invalid MSGs appropriately."""

    CANT_EXPIRE = -1
    IS_EXPIRING = 0.8  # expected lifetime == 1.0
    HAS_EXPIRED = 2.0  # incl. any value >= HAS_EXPIRED

    def __init__(self, gwy, pkt) -> None:
        """Create a message from a valid packet.

        Will raise InvalidPacketError if it is invalid.
        """
        self._gwy = gwy
        self._pkt = pkt

        self.src = pkt.src
        self.dst = pkt.dst
        self._addrs = pkt._addrs

        self.dtm: dt = pkt.dtm

        self.verb: str = pkt.verb
        self.seqn: str = pkt.seqn
        self.code: str = pkt.code
        self.len: int = pkt._len

        self.code_name = CODE_NAMES.get(self.code, f"unknown_{self.code}")

        self._payload = self._validate(self._pkt.payload)  # ? raise InvalidPacketError

        self._str: str = None  # type: ignore[assignment]
        self._fraction_expired: float = None  # type: ignore[assignment]
        # self._is_fragment: bool = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return str(self._pkt)  # repr or str?

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""

        def ctx(pkt) -> str:
            ctx = {True: "[..]", False: "", None: "??"}.get(pkt._ctx, pkt._ctx)
            if not ctx and pkt.payload[:2] not in ("00", FF):
                return f"({pkt.payload[:2]})"
            return ctx

        def display_name(addr: Address) -> str:
            """Return a friendly name for an Address, or a Device.

            Use the alias, if one exists, or use a slug instead of a device type.
            """

            try:
                if self._gwy.config.use_aliases:
                    return self._gwy._include[addr.id][SZ_ALIAS][:18]
                else:
                    return f"{self._gwy.device_by_id[addr.id]._SLUG}:{addr.id[3:]}"
            except KeyError:
                return f" {addr.id}"

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
        return (self.src, self.dst, self.verb, self.code, self._pkt.payload) == (
            other.src,
            other.dst,
            other.verb,
            other.code,
            other._pkt.payload,
        )

    def __lt__(self, other) -> bool:
        if not isinstance(other, Message):
            return NotImplemented
        return self.dtm < other.dtm

    @property
    def payload(self):  # Union[dict, list[dict]]:
        """Return the payload."""
        return self._payload

    @property
    def _has_payload(self) -> bool:
        """Return False if there is no payload (may falsely Return True).

        The message (i.e. the raw payload) may still have an idx.
        """

        return self._pkt._has_payload

    @property
    def _has_array(self) -> bool:
        """Return True if the message's raw payload is an array."""

        return self._pkt._has_array

    @property
    def _idx(self) -> dict:
        """Return the domain_id/zone_idx/other_idx of a message payload, if any.

        Used to identify the zone/domain that a message applies to. Returns an empty
        dict if there is none such, or None if undetermined.
        """

        # .I --- 01:145038 --:------ 01:145038 3B00 002 FCC8

        IDX_NAMES = {
            Code._0002: "other_idx",  # non-evohome: hometronics
            Code._0418: SZ_LOG_IDX,
            Code._10A0: SZ_DHW_IDX,  # can be 2 DHW zones per system, albeit unusual
            Code._1260: SZ_DHW_IDX,  # can be 2 DHW zones per system, albeit unusual
            Code._1F41: SZ_DHW_IDX,  # can be 2 DHW zones per system, albeit unusual
            Code._22C9: SZ_UFH_IDX,  # UFH circuit
            Code._2389: "other_idx",  # anachronistic
            Code._2D49: "other_idx",  # non-evohome: hometronics
            Code._31D9: "hvac_id",
            Code._31DA: "hvac_id",
            Code._3220: "msg_id",
        }  # ALSO: SZ_DOMAIN_ID, SZ_ZONE_IDX

        if self._pkt._idx in (True, False) or self.code in CODE_IDX_COMPLEX:
            return {}  # above was: CODE_IDX_COMPLEX + (Code._3150):

        if self.code in (Code._3220,):  # FIXME: should be _SIMPLE
            return {}

        # .I 068 03:201498 --:------ 03:201498 30C9 003 0106D6 # rare

        # .I --- 00:034798 --:------ 12:126457 2309 003 0201F4
        if True and not {self.src.type, self.dst.type} & {
            DEV_TYPE_MAP.CTL,
            DEV_TYPE_MAP.UFC,
            DEV_TYPE_MAP.HCW,  # ?remove (see above, rare)
            DEV_TYPE_MAP.DTS,
            DEV_TYPE_MAP.HGI,
            DEV_TYPE_MAP.DT2,
            DEV_TYPE_MAP.PRG,
        }:  # DEX
            assert self._pkt._idx == "00", "What!! (AA)"
            return {}

        # .I 035 --:------ --:------ 12:126457 30C9 003 017FFF
        if (
            True
            and self.src.type == self.dst.type
            and self.src.type
            not in (
                DEV_TYPE_MAP.CTL,
                DEV_TYPE_MAP.UFC,
                DEV_TYPE_MAP.HCW,  # ?remove (see above, rare)
                DEV_TYPE_MAP.HGI,
                DEV_TYPE_MAP.PRG,
            )
        ):  # DEX
            assert self._pkt._idx == "00", "What!! (AB)"
            return {}

        # .I --- 04:029362 --:------ 12:126457 3150 002 0162
        # if not getattr(self.src, "_is_controller", True) and not getattr(
        #     self.dst, "_is_controller", True
        # ):
        #     assert self._pkt._idx == "00", "What!! (BA)"
        #     return {}

        # .I --- 04:029362 --:------ 12:126457 3150 002 0162
        # if not (
        #     getattr(self.src, "_is_controller", True)
        #     or getattr(self.dst, "_is_controller", True)
        # ):
        #     assert self._pkt._idx == "00", "What!! (BB)"
        #     return {}

        if self.src.type == self.dst.type and not getattr(
            self.src, "_is_controller", True
        ):  # DEX
            assert self._pkt._idx == "00", "What!! (BC)"
            return {}

        # TODO: also 000C (but is a complex idx)
        # TODO: also 3150 (when not domain, and will be array if so)
        if self.code in (Code._000A, Code._2309) and self.src.type == DEV_TYPE_MAP.UFC:
            return {IDX_NAMES[Code._22C9]: self._pkt._idx}

        index_name = IDX_NAMES.get(
            self.code, SZ_DOMAIN_ID if self._pkt._idx[:1] == "F" else SZ_ZONE_IDX
        )

        return {index_name: self._pkt._idx}

    @property
    def _expired(self) -> bool:
        """Return True if the message is dated (or False otherwise)."""

        if self._fraction_expired is not None:
            if self._fraction_expired == self.CANT_EXPIRE:
                return False
            if self._fraction_expired > self.HAS_EXPIRED * 2:
                return True

        prev_fraction = self._fraction_expired

        if self.code == Code._1F09 and self.verb != RQ:
            # RQs won't have remaining_seconds, RP/Ws have only partial cycle times
            self._fraction_expired = fraction_expired(
                self._gwy._dt_now() - self.dtm,
                td(seconds=self.payload["remaining_seconds"]),
            )
        else:  # self._pkt._expired can be False (doesn't expire), wont be 0
            self._fraction_expired = self._pkt._expired or self.CANT_EXPIRE

        if self._fraction_expired < self.HAS_EXPIRED:
            return False

        # TODO: should renew?

        # only log expired packets once
        if prev_fraction is None or prev_fraction < self.HAS_EXPIRED:
            if (
                self.code == Code._1F09
                and self.verb != I_
                or self.code in (Code._0016, Code._3120, Code._313F)
                or self._gwy._engine_state is not None  # restoring from pkt log
            ):
                _logger = _LOGGER.info
            else:
                _logger = _LOGGER.warning if DEV_MODE else _LOGGER.info
            _logger(f"{self!r} # has expired ({self._fraction_expired * 100:1.0f}%)")

        # elif self._fraction_expired >= self.IS_EXPIRING:  # this could log multiple times
        #     _LOGGER.error("%s # is expiring", self._pkt)

        # and self.dtm >= self._gwy._dt_now() - td(days=7)  # TODO: should be none >7d?
        return self._fraction_expired > self.HAS_EXPIRED

    def _validate(self, raw_payload) -> dict | list:  # TODO: needs work
        """Validate the message, and parse the payload if so.

        Raise an exception (InvalidPacketError) if it is not valid.
        """

        try:  # parse the payload
            # TODO: only accept invalid packets to/from HGI when flag raised
            _check_msg_payload(self, self._pkt.payload)  # ? InvalidPayloadError

            if not self._has_payload and (
                self.verb == RQ and self.code not in RQ_IDX_COMPLEX
            ):
                # _LOGGER.error("%s", msg)
                return {}

            result = PAYLOAD_PARSERS.get(self.code, parser_unknown)(
                self._pkt.payload, self
            )

            if isinstance(result, list):
                return result
            if isinstance(result, dict):
                return {**self._idx, **result}

            raise TypeError(f"Invalid payload type: {type(result)}")

        except InvalidPacketError as exc:
            (_LOGGER.exception if DEV_MODE else _LOGGER.warning)(
                "%s < %s", self._pkt, exc
            )
            raise exc

        except AssertionError as exc:
            # beware: HGI80 can send 'odd' but parseable packets +/- get invalid reply
            (
                _LOGGER.exception
                if DEV_MODE and self.src.type != DEV_TYPE_MAP.HGI  # DEX
                else _LOGGER.exception
            )("%s < %s", self._pkt, f"{exc.__class__.__name__}({exc})")
            raise InvalidPacketError(exc)

        except (AttributeError, LookupError, TypeError, ValueError) as exc:  # TODO: dev
            _LOGGER.exception(
                "%s < Coding error: %s", self._pkt, f"{exc.__class__.__name__}({exc})"
            )
            raise InvalidPacketError from exc

        except NotImplementedError as exc:  # parser_unknown (unknown packet code)
            _LOGGER.warning("%s < Unknown packet code (cannot parse)", self._pkt)
            raise InvalidPacketError from exc


@lru_cache(maxsize=256)
def re_compile_re_match(regex: str, string: str) -> bool:  # Optional[Match[Any]]
    # TODO: confirm this does speed things up
    # Python has its own caching of re.complile, _MAXCACHE = 512
    # https://github.com/python/cpython/blob/3.10/Lib/re.py
    return re.compile(regex).match(string)  # type: ignore[return-value]


def _check_msg_payload(msg: Message, payload: str) -> None:
    """Validate the packet's payload against its verb/code pair.

    Raise an InvalidPayloadError if the payload is invalid, otherwise simply return.

    The HGI80-compatible devices can do what they like, but a warning is logged.
    Some parsers may also raise InvalidPayloadError (e.g. 3220), albeit later on.
    """

    try:
        _ = repr(msg._pkt)  # HACK: ? raise InvalidPayloadError

        if msg.code not in CODES_SCHEMA:
            raise InvalidPacketError(f"Unknown code: {msg.code}")

        try:
            regex = CODES_SCHEMA[msg.code][msg.verb]
        except KeyError:
            raise InvalidPacketError(f"Unknown verb/code pair: {msg.verb}/{msg.code}")

        if not re_compile_re_match(regex, payload):
            raise InvalidPayloadError(f"Payload doesn't match '{regex}': {payload}")

    except InvalidPacketError as exc:  # incl. InvalidPayloadError
        # HGI80s can do what they like...
        if msg.src.type != DEV_TYPE_MAP.HGI:
            raise
        if not msg._gwy.pkt_protocol or (
            hgi_id := msg._gwy.pkt_protocol._hgi80.get("device_id") is None
        ):
            _LOGGER.warning(f"{msg!r} < {exc}")
            return
        elif msg.src.id != hgi_id:
            raise
