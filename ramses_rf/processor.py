#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a message (payload into JSON).
"""
from __future__ import annotations

import logging
from datetime import timedelta as td

from .const import (
    DEV_TYPE,
    DEV_TYPE_MAP,
    DONT_CREATE_ENTITIES,
    DONT_UPDATE_ENTITIES,
    SZ_DEVICES,
    __dev_mode__,
)
from .device import Device
from .protocol import CODES_BY_DEV_SLUG, CODES_SCHEMA, Message
from .protocol.exceptions import EvohomeError, InvalidAddrSetError, InvalidPacketError
from .protocol.ramses import (
    CODES_OF_HEAT_DOMAIN,
    CODES_OF_HEAT_DOMAIN_ONLY,
    CODES_OF_HVAC_DOMAIN_ONLY,
)

# skipcq: PY-W2000
from .protocol import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

__all__ = ["process_msg"]

CODE_NAMES = {k: v["name"] for k, v in CODES_SCHEMA.items()}

MSG_FORMAT_10 = "|| {:10s} | {:10s} | {:2s} | {:16s} | {:^4s} || {}"
MSG_FORMAT_18 = "|| {:18s} | {:18s} | {:2s} | {:16s} | {:^4s} || {}"

DEV_MODE = __dev_mode__ and False  # or True  # set True for useful Tracebacks

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

STRICT_MODE = not DEV_MODE and False


def _create_devices_from_addrs(gwy, this: Message) -> None:
    """Discover and create any new devices using the packet addresses (not payload)."""

    # prefer Devices but can continue with Addresses if required...
    this.src = gwy.device_by_id.get(this.src.id, this.src)
    this.dst = gwy.device_by_id.get(this.dst.id, this.dst)

    # Devices need to know their controller, ?and their location ('parent' domain)
    # NB: only addrs processed here, packet metadata is processed elsewhere

    # Determinging bindings to a controller:
    #  - configury; As per any schema
    #  - discovery: If in 000C pkt, or pkt *to* device where src is a controller
    #  - eavesdrop: If pkt *from* device where dst is a controller

    # Determinging location in a schema (domain/DHW/zone):
    #  - configury; As per any schema
    #  - discovery: If in 000C pkt - unable for 10: & 00: (TRVs)
    #  - discovery: from packet fingerprint, excl. payloads (only for 10:)
    #  - eavesdrop: from packet fingerprint, incl. payloads

    if not isinstance(this.src, Device):
        this.src = gwy.get_device(this.src.id)  # may: LookupError (don't swallow)
        if this.dst.id == this.src.id:
            this.dst = this.src
            return

    if not gwy.config.enable_eavesdrop:
        return

    if not isinstance(this.dst, Device) and this.src is not gwy.hgi:
        try:
            this.dst = gwy.get_device(this.dst.id)  # may: LookupError (but swallow it)
        except LookupError:
            pass


def _check_msg_addrs(msg: Message) -> None:
    """Validate the packet's address set.

    Raise InvalidAddrSetError if the meta data is invalid, otherwise simply return.
    """

    # TODO: needs work: doesn't take into account device's explicit class at this layer

    if (
        msg.src.id != msg.dst.id
        and msg.src.type == msg.dst.type
        and msg.src.type in DEV_TYPE_MAP.HEAT_DEVICES  # could still be HVAC domain
    ):
        # .I --- 18:013393 18:000730 --:------ 0001 005 00FFFF0200     # invalid
        # .I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5         # invalid
        # .I --- 29:151550 29:237552 --:------ 22F3 007 00023C03040000 # valid? HVAC
        if msg.code in CODES_OF_HEAT_DOMAIN_ONLY:
            raise InvalidAddrSetError(f"Invalid src/dst addr pair: {msg.src}/{msg.dst}")
        elif msg.code in CODES_OF_HEAT_DOMAIN:
            _LOGGER.warning(
                f"{msg!r} < Invalid src/dst addr pair: {msg.src}/{msg.dst}, is it HVAC?"
            )
        elif msg.code not in CODES_OF_HVAC_DOMAIN_ONLY:
            _LOGGER.info(
                f"{msg!r} < Invalid src/dst addr pair: {msg.src}/{msg.dst}, is it HVAC?"
            )


def _check_msg_src(msg: Message, *, slug: str = None) -> None:
    """Validate the packet's source device class (type) against its verb/code pair.

    Raise InvalidPacketError if the meta data is invalid, otherwise simply return.
    """

    if slug is None:  # slug = best_dev_role(msg.src, msg=msg)._SLUG
        slug = getattr(msg.src, "_SLUG", DEV_TYPE.DEV)
    if slug in (DEV_TYPE.HGI, DEV_TYPE.DEV, DEV_TYPE.HEA, DEV_TYPE.HVC):
        return

    if slug not in CODES_BY_DEV_SLUG:
        if msg.code != Code._10E0 and msg.code not in CODES_OF_HVAC_DOMAIN_ONLY:
            err_msg = f"Unknown src type: {msg.dst}"
            if STRICT_MODE:
                raise InvalidPacketError(err_msg)
            (_LOGGER.warning if DEV_MODE else _LOGGER.info)(f"{msg!r} < {err_msg}")
            return
        _LOGGER.warning(f"{msg!r} < Unknown src type: {msg.src}, is it HVAC?")
        return

    #
    #

    if msg.code not in CODES_BY_DEV_SLUG[slug]:  # type: ignore[index]
        if slug != DEV_TYPE.DEV:
            err_msg = f"Invalid code for {msg.src} to Tx: {msg.code}"
            if STRICT_MODE:
                raise InvalidPacketError(err_msg)
            (_LOGGER.warning if DEV_MODE else _LOGGER.info)(f"{msg!r} < {err_msg}")
            return
        if msg.verb in (RQ, W_):
            return
        (_LOGGER.warning if DEV_MODE else _LOGGER.info)(
            f"{msg!r} < Invalid code for {msg.src} to Tx: {msg.code}"
        )
        return

    #
    #

    #
    # (code := CODES_BY_DEV_SLUG[slug][msg.code]) and msg.verb not in code:
    if msg.verb not in CODES_BY_DEV_SLUG[slug][msg.code]:  # type: ignore[index]
        err_msg = f"Invalid verb/code for {msg.src} to Tx: {msg.verb}/{msg.code}"
        if STRICT_MODE:
            raise InvalidPacketError(err_msg)
        (_LOGGER.warning if DEV_MODE else _LOGGER.info)(f"{msg!r} < {err_msg}")


def _check_msg_dst(msg: Message, *, slug: str = None) -> None:
    """Validate the packet's destination device class (type) against its verb/code pair.

    Raise InvalidPacketError if the meta data is invalid, otherwise simply return.
    """

    if slug is None:
        slug = getattr(msg.dst, "_SLUG", None)
    if slug in (None, DEV_TYPE.HGI, DEV_TYPE.DEV, DEV_TYPE.HEA, DEV_TYPE.HVC):
        return

    if slug not in CODES_BY_DEV_SLUG:
        if msg.code not in CODES_OF_HVAC_DOMAIN_ONLY:
            err_msg = f"Unknown dst type: {msg.dst}"
            if STRICT_MODE:
                raise InvalidPacketError(err_msg)
            (_LOGGER.warning if DEV_MODE else _LOGGER.info)(f"{msg!r} < {err_msg}")
            return
        _LOGGER.warning(f"{msg!r} < Unknown dst type: {msg.dst}, is it HVAC?")
        return

    if msg.verb == I_:  # TODO: not common, unless src=dst
        return  # receiving an I isn't currently in the schema & cant yet be tested
    if f"{slug}/{msg.verb}/{msg.code}" in (f"CTL/{RQ}/{Code._3EF1}",):
        return  # HACK: an exception-to-the-rule that need sorting

    if msg.code not in CODES_BY_DEV_SLUG[slug]:  # type: ignore[index]
        if False and slug != DEV_TYPE.HGI:  # NOTE: not yet needed because of 1st if
            err_msg = f"Invalid code for {msg.dst} to Rx: {msg.code}"
            if STRICT_MODE:
                raise InvalidPacketError(err_msg)
            (_LOGGER.warning if DEV_MODE else _LOGGER.info)(f"{msg!r} < {err_msg}")
            return
        if msg.verb == RP:
            return
        (_LOGGER.warning if DEV_MODE else _LOGGER.info)(
            f"{msg!r} < Invalid code for {msg.dst} to Rx/Tx: {msg.code}"
        )
        return

    if f"{msg.verb}/{msg.code}" in (f"{W_}/{Code._0001}",):
        return  # HACK: an exception-to-the-rule that need sorting
    if f"{slug}/{msg.verb}/{msg.code}" in (f"{DEV_TYPE.BDR}/{RQ}/{Code._3EF0}",):
        return  # HACK: an exception-to-the-rule that need sorting

    verb = {RQ: RP, RP: RQ, W_: I_}[msg.verb]
    # (code := CODES_BY_DEV_SLUG[klass][msg.code]) and verb not in code:
    if verb not in CODES_BY_DEV_SLUG[slug][msg.code]:  # type: ignore[index]
        err_msg = f"Invalid verb/code for {msg.dst} to Rx: {msg.verb}/{msg.code}"
        if STRICT_MODE:
            raise InvalidPacketError(err_msg)
        (_LOGGER.warning if DEV_MODE else _LOGGER.info)(f"{msg!r} < {err_msg}")


def process_msg(msg: Message, *, prev_msg: Message = None) -> None:
    """Decoding the packet payload and route it appropriately."""

    # All methods require a valid message (payload), except create_devices(), which
    # requires a valid message only for 000C.

    def detect_array_fragment(this, prev) -> dict:  # _PayloadT
        """Return complete array if this pkt is the latter half of an array."""
        # This will work, even if the 2nd pkt._is_array == False as 1st == True
        # .I --- 01:158182 --:------ 01:158182 000A 048 001201F409C4011101F409C40...
        # .I --- 01:158182 --:------ 01:158182 000A 006 081001F409C4
        if (
            not prev
            or not prev._has_array
            or this.code not in (Code._000A, Code._22C9)
            or this.code != prev.code
            or this.verb != prev.verb != I_
            or this.src != prev.src
            or this.dtm >= prev.dtm + td(seconds=3)
        ):
            return this.payload

        this._pkt._force_has_array()
        payload = this.payload if isinstance(this.payload, list) else [this.payload]
        return prev.payload + payload

    gwy = msg._gwy  # pylint: disable=protected-access, skipcq: PYL-W0212

    # HACK:  if CLI, double-logging with client.py proc_msg() & setLevel(DEBUG)
    if (log_level := _LOGGER.getEffectiveLevel()) < logging.INFO:
        _LOGGER.info(msg)
    elif log_level <= logging.INFO and not (
        msg.verb == RQ and msg.src.type == DEV_TYPE_MAP.HGI
    ):
        _LOGGER.info(msg)

    msg._payload = detect_array_fragment(msg, prev_msg)  # HACK: needs rethinking?

    try:  # process the packet payload

        _check_msg_addrs(msg)  # ? InvalidAddrSetError

        # TODO: any value in not creating a device unless the message is valid?
        if gwy.config.reduce_processing < DONT_CREATE_ENTITIES:
            try:
                _create_devices_from_addrs(gwy, msg)
            except LookupError as exc:
                (_LOGGER.error if DEV_MODE else _LOGGER.warning)(
                    "%s < %s(%s)", msg._pkt, exc.__class__.__name__, exc
                )
                return

        _check_msg_src(msg)  # ? InvalidPacketError
        if msg.dst is not msg.src or msg.verb != I_:
            _check_msg_dst(msg)  # ? InvalidPacketError

        if gwy.config.reduce_processing >= DONT_UPDATE_ENTITIES:
            return

        if isinstance(msg.src, Device):  # , HgiGateway)):  # could use DeviceBase
            msg.src._handle_msg(msg)

        if msg.code not in (
            Code._0008,
            Code._0009,
            Code._3B00,
            Code._3EF1,
        ):  # special case: are fakeable
            return

        # .I --- 22:060293 --:------ 22:060293 0008 002 000C
        # .I --- 01:054173 --:------ 01:054173 0008 002 03AA
        if msg.dst == msg.src and hasattr(msg.src, SZ_DEVICES):
            # needed for faked relays: each device will decide if the pkt is useful
            [
                d._handle_msg(msg)
                for d in msg.src.devices
                if getattr(d, "_is_faked", False)  # and d.xxx = "BDR"
            ]

        # NOTE: msgs are routed only to devices here: routing to other entities (e.g.
        # (systems, zones, circuits) is done by those devices (e.g. UFC to UfhCircuit)
        elif getattr(msg.dst, "_is_faked", False):
            msg.dst._handle_msg(msg)

    except (AssertionError, EvohomeError, NotImplementedError) as exc:
        (_LOGGER.error if DEV_MODE else _LOGGER.warning)(
            "%s < %s(%s)", msg._pkt, exc.__class__.__name__, exc
        )

    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)(
            "%s < %s(%s)", msg._pkt, exc.__class__.__name__, exc
        )
