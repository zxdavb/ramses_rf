#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a message (payload into JSON).
"""

import logging
from datetime import timedelta as td

from .const import DONT_CREATE_ENTITIES, DONT_UPDATE_ENTITIES, __dev_mode__
from .devices import Device  # , HgiGateway
from .protocol import (
    RAMSES_CODES,
    RAMSES_DEVICES,
    CorruptStateError,
    InvalidPacketError,
    Message,
)
from .protocol.message import HVAC_ONLY_CODES

from .protocol import I_, RP, RQ, W_  # noqa: F401, isort: skip
from .protocol import (  # noqa: F401, isort: skip
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
    _0150,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _0B04,
    _1030,
    _1060,
    _1081,
    _1090,
    _1098,
    _10A0,
    _10B0,
    _10E0,
    _10E1,
    _1100,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _12F0,
    _1300,
    _1F09,
    _1F41,
    _1FC9,
    _1FD0,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2389,
    _2400,
    _2401,
    _2410,
    _2420,
    _2D49,
    _2E04,
    _30C9,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3200,
    _3210,
    _3220,
    _3221,
    _3223,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)

__all__ = ["process_msg"]

CODE_NAMES = {k: v["name"] for k, v in RAMSES_CODES.items()}

MSG_FORMAT_10 = "|| {:10s} | {:10s} | {:2s} | {:16s} | {:^4s} || {}"
MSG_FORMAT_18 = "|| {:18s} | {:18s} | {:2s} | {:16s} | {:^4s} || {}"

DEV_MODE = __dev_mode__ and False  # set True for useful Tracebacks

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def _create_devices_from_addrs(this: Message) -> None:
    """Discover and create any new devices using the packet address set."""

    # prefer Devices but can still use Addresses if required...
    this.src = this._gwy.device_by_id.get(this.src.id, this.src)
    this.dst = this._gwy.device_by_id.get(this.dst.id, this.dst)

    # Devices need to know their controller, ?and their location ('parent' domain)
    # NB: only addrs prcoessed here, packet metadata is processed elsewhere

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
        this.src = this._gwy._get_device(this.src.id, msg=this)
        if this.dst.id == this.src.id:
            this.dst = this.src

    if (
        not this._gwy.config.enable_eavesdrop
        or this.dst.id in this._gwy._unwanted
        or this.src == this._gwy.hgi
    ):  # the above can't / shouldn't be eavesdropped for dst device
        return

    if not isinstance(this.dst, Device):
        this.dst = this._gwy._get_device(this.dst.id, msg=this)

    if getattr(this.dst, "_is_controller", False):
        this._gwy._get_device(this.src.id, ctl_id=this.dst.id, msg=this)  # or _set_ctl?

    elif isinstance(this.dst, Device) and getattr(this.src, "_is_controller", False):
        this._gwy._get_device(this.dst.id, ctl_id=this.src.id, msg=this)  # or _set_ctl?


def _check_msg_src(msg: Message, klass: str) -> None:
    """Validate the packet's source device class (type) against its verb/code pair.

    Raise InvalidPacketError if the meta data is invalid, otherwise simply return.
    """

    if klass not in RAMSES_DEVICES:  # DEX_done, TODO: fingerprint dev class
        if msg.code not in HVAC_ONLY_CODES:
            raise InvalidPacketError(f"Unknown src type: {msg.src}")
        _LOGGER.warning(f"{msg._pkt} < Unknown src type: {msg.src}, is it HVAC?")
        return

    #
    #

    #
    #

    if msg.code not in RAMSES_DEVICES[klass]:  # DEX_done
        if klass != "HGI":  # DEX_done
            raise InvalidPacketError(f"Invalid code for {msg.src} to Tx: {msg.code}")
        if msg.verb in (RQ, W_):
            return
        _LOGGER.warning(f"{msg._pkt} < Invalid code for {msg.src} to Tx: {msg.code}")
        return

    #
    #
    #
    #

    #
    # (code := RAMSES_DEVICES[klass][msg.code]) and msg.verb not in code:
    if msg.verb not in RAMSES_DEVICES[klass][msg.code]:  # DEX_done
        raise InvalidPacketError(
            f"Invalid verb/code for {msg.src} to Tx: {msg.verb}/{msg.code}"
        )


def _check_msg_dst(msg: Message, klass: str) -> None:
    """Validate the packet's destination device class (type) against its verb/code pair.

    Raise InvalidPacketError if the meta data is invalid, otherwise simply return.
    """

    if klass not in RAMSES_DEVICES:  # DEX_done, TODO: fingerprint dev class
        if msg.code not in HVAC_ONLY_CODES:
            raise InvalidPacketError(f"Unknown dst type: {msg.dst}")
        _LOGGER.warning(f"{msg._pkt} < Unknown dst type: {msg.dst}, is it HVAC?")
        return

    if msg.verb == I_:  # TODO: not common, unless src=dst
        return  # receiving an I isn't currently in the schema & cant yet be tested

    if f"{klass}/{msg.verb}/{msg.code}" in (f"CTL/{RQ}/{_3EF1}",):  # DEX_done
        return  # HACK: an exception-to-the-rule that need sorting

    if msg.code not in RAMSES_DEVICES[klass]:  # NOTE: not OK for Rx, DEX_done
        if klass != "HGI":  # NOTE: not yet needed because of 1st if, DEX_done
            raise InvalidPacketError(f"Invalid code for {msg.dst} to Rx: {msg.code}")
        if msg.verb == RP:
            return
        _LOGGER.warning(f"{msg._pkt} < Invalid code for {msg.dst} to Tx: {msg.code}")
        return

    if f"{msg.verb}/{msg.code}" in (f"{W_}/{_0001}",):
        return  # HACK: an exception-to-the-rule that need sorting
    if f"{klass}/{msg.verb}/{msg.code}" in (f"BDR/{RQ}/{_3EF0}",):  # DEX_done
        return  # HACK: an exception-to-the-rule that need sorting

    verb = {RQ: RP, RP: RQ, W_: I_}[msg.verb]
    # (code := RAMSES_DEVICES[klass][msg.code]) and verb not in code:
    if verb not in RAMSES_DEVICES[klass][msg.code]:  # DEX_done
        raise InvalidPacketError(
            f"Invalid verb/code for {msg.dst} to Rx: {msg.verb}/{msg.code}"
        )


def process_msg(msg: Message, prev_msg: Message = None) -> None:
    """Process the valid packet by decoding its payload."""

    # All methods require a valid message (payload), except create_devices(), which
    # requires a valid message only for 000C.

    def detect_array(this, prev) -> dict:
        """Return complete array if this pkt is the latter half of an array."""
        # This will work, even if the 2nd pkt._is_array == False as 1st == True
        #  I --- 01:158182 --:------ 01:158182 000A 048 001201F409C4011101F409C40...
        #  I --- 01:158182 --:------ 01:158182 000A 006 081001F409C4
        if (
            not prev
            or not prev._has_array
            or this.code not in (_000A, _22C9)
            or this.code != prev.code
            or this.verb != prev.verb != I_
            or this.src != prev.src
            or this.dtm >= prev.dtm + td(seconds=3)
        ):
            return this.payload

        msg._pkt._force_has_array()
        payload = this.payload if isinstance(this.payload, list) else [this.payload]
        return prev.payload + payload

    # HACK:  if CLI, double-logging with client.py proc_msg() & setLevel(DEBUG)
    if (log_level := _LOGGER.getEffectiveLevel()) < logging.INFO:
        _LOGGER.info(msg)
    elif log_level <= logging.INFO and not (msg.verb == RQ and msg.src.type == "18"):
        _LOGGER.info(msg)

    # NOTE: this is used to expose message timeouts (esp. when parsing)
    # [m._expired for d in msg._gwy.devices for m in d._msg_db]

    msg._payload = detect_array(msg, prev_msg)  # HACK - needs rethinking?

    if msg._gwy.config.reduce_processing >= DONT_CREATE_ENTITIES:
        return

    # # TODO: This will need to be removed for HGI80-impersonation
    # # 18:/RQs are unreliable, although any corresponding RPs are often required
    # if msg.src.type == "18":  # DEX
    #     return

    try:  # process the packet payload
        _create_devices_from_addrs(msg)  # from pkt header

        if isinstance(msg.src, Device):
            _check_msg_src(msg, msg.src._klass)  # ? InvalidPacketError
        # elif DEV_MODE and not isinstance(msg.src, HgiGateway):
        #     print(msg)
        #     print(type(msg.src), msg.src)
        #     print(type(msg.dst), msg.dst)

        if isinstance(msg.dst, Device):
            if msg.dst is not msg.src:
                # Device class doesn't usu. include HgiGateway
                _check_msg_dst(msg, msg.dst._klass)  # ? InvalidPacketError
        # elif DEV_MODE and msg.dst.type not in ("18", "63", "--"):
        #     print(msg)
        #     print(type(msg.src), msg.src)
        #     print(type(msg.dst), msg.dst)

        if msg._gwy.config.reduce_processing >= DONT_UPDATE_ENTITIES:
            return

        if isinstance(msg.src, Device):  # , HgiGateway)):  # could use DeviceBase
            msg.src._handle_msg(msg)

        if msg.code not in (_0008, _0009, _3B00, _3EF1):  # special case: are fakeable
            return

        #  I --- 01:054173 --:------ 01:054173 0008 002 03AA
        if msg.dst == msg.src:
            # this is needed for faked relays...
            # each device will have to decide if this packet is useful
            [
                d._handle_msg(msg)
                for d in msg.src.devices
                if getattr(d, "_is_faked", False)  # and d.xxx = "BDR"
            ]

        # RQ --- 18:006402 13:123456 --:------ 3EF1 001 00
        elif getattr(msg.dst, "_is_faked", False):
            msg.dst._handle_msg(msg)

    except (AssertionError, NotImplementedError) as exc:
        (_LOGGER.error if DEV_MODE else _LOGGER.warning)(
            "%s < %s", msg._pkt, f"{exc.__class__.__name__}({exc})"
        )
        return  # NOTE: use raise only when debugging

    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)(
            "%s < %s", msg._pkt, f"{exc.__class__.__name__}({exc})"
        )
        return  # NOTE: use raise only when debugging

    except (CorruptStateError, InvalidPacketError) as exc:  # TODO: CorruptEvohomeError
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)("%s < %s", msg._pkt, exc)
        return  # TODO: bad pkt, or Schema
