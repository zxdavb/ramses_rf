#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a message (payload into JSON).
"""

import logging

from .const import DONT_CREATE_ENTITIES, DONT_UPDATE_ENTITIES, __dev_mode__
from .devices import Device
from .protocol import Message
from .protocol.exceptions import CorruptStateError
from .protocol.ramses import RAMSES_CODES

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

__all__ = ["process_msg"]

CODE_NAMES = {k: v["name"] for k, v in RAMSES_CODES.items()}

MSG_FORMAT_10 = "|| {:10s} | {:10s} | {:2s} | {:16s} | {:^4s} || {}"
MSG_FORMAT_18 = "|| {:18s} | {:18s} | {:2s} | {:16s} | {:^4s} || {}"

DEV_MODE = __dev_mode__ and True

_LOGGER = logging.getLogger(__name__)
if False and DEV_MODE:
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


def _create_devices_from_payload(this: Message) -> None:
    """Discover and create any new devices using the message payload (1FC9/000C)."""
    pass


def process_msg(msg: Message) -> None:
    """Process the valid packet by decoding its payload.

    All methods require a valid message (payload), except create_devices, which requires
    a valid message only for 000C.
    """

    # def hack_pkts(this, prev) -> None:  # TODO: needs work, e.g. merge 000A fragments
    # # TODO: ?move to ctl._handle_msg() and/or system._handle_msg()?
    # if re.search("I.* 01.* 000A ", str(this._pkt)):  # HACK: and dtm < 3 secs
    #     # TODO: an edge case here: >2 000A packets in a row
    #     if prev is not None and re.search("I.* 01.* 000A ", str(prev._pkt)):
    #         this._payload = prev.payload + this.payload  # merge frags, and process

    # HACK:  if CLI, double-logging with client.py proc_msg() & setLevel(DEBUG)
    if (log_level := _LOGGER.getEffectiveLevel()) < logging.INFO:
        _LOGGER.info(msg)
    elif log_level <= logging.INFO and not (msg.verb == RQ and msg.src.type == "18"):
        _LOGGER.info(msg)

    # NOTE: this is used to expose message timeouts (esp. when parsing)
    # [m._expired for d in msg._gwy.devices for m in d._msg_db]

    if msg._gwy.config.reduce_processing >= DONT_CREATE_ENTITIES:
        return

    # # TODO: This will need to be removed for HGI80-impersonation
    # # 18:/RQs are unreliable, although any corresponding RPs are often required
    # if msg.src.type == "18":  # DEX
    #     return

    try:  # process the packet payload
        _create_devices_from_addrs(msg)  # from pkt header
        # _create_devices_from_payload(msg)  # from msg payload (e.g. 000C)

        if msg._gwy.config.reduce_processing >= DONT_UPDATE_ENTITIES:
            msg._gwy._prev_msg = msg
            return

        if msg.src.type == "07":
            _LOGGER.debug(f"{msg._pkt} < handling (01)")  # HACK: lloyda

        # _update_entities(msg, msg._gwy._prev_msg)  # update the state database
        if isinstance(msg.src, Device):
            msg.src._handle_msg(msg)
        else:
            _LOGGER.debug(f"{msg._pkt} < handling (02)")  # HACK: lloyda

        if msg.code not in (_0008, _0009, _3B00, _3EF1):  # special case: are fakeable
            msg._gwy._prev_msg = msg
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

    except CorruptStateError as exc:  # TODO: add CorruptEvohomeError
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)("%s < %s", msg._pkt, exc)
        return  # TODO: bad pkt, or Schema

    msg._gwy._prev_msg = msg
