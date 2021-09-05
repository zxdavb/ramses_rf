#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a message (payload into JSON).
"""

import logging

from .const import DONT_CREATE_ENTITIES, DONT_UPDATE_ENTITIES
from .devices import Device
from .protocol import Message
from .protocol.const import (
    _0005_ZONE_TYPE,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_HTG_CONTROL,
    ATTR_ZONE_ACTUATORS,
    ATTR_ZONE_SENSOR,
    ZONE_TYPE_SLUGS,
)
from .protocol.exceptions import CorruptStateError
from .protocol.ramses import RAMSES_CODES

from .protocol import I_, RP, RQ, W_, __dev_mode__  # noqa: F401, isort: skip
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

DEV_MODE = True  # __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def _create_devices(this: Message) -> None:
    """Discover and create any new devices."""

    def proc_000c():
        if this.src.type == "01":  # TODO
            this._gwy._get_device(this.dst.id, ctl_id=this.src.id)
            # if this.is_valid:
            key = "zone_idx" if "zone_idx" in this.payload else "domain_id"
            [
                this._gwy._get_device(
                    d,
                    ctl_id=this.src.id,
                    domain_id=this.payload[key],
                )
                for d in this.payload["devices"]
            ]
        elif this.src.type == "02":  # TODO
            # this._gwy._get_device(this.dst.id)
            if this.payload["devices"]:
                device_id = this.payload["devices"][0]
                this._gwy._get_device(this.src.id, ctl_id=device_id)

        elif this.payload["device_class"] == ATTR_HTG_CONTROL:
            # TODO: maybe the htg controller is an OTB? via eavesdropping
            # evo._set_htg_control(devices[0])
            pass

    if this.src.type == "18":
        return

    if this.code == _000C and this.verb == RP:
        proc_000c()

    if this.src.type in ("01", "23") and this.src is not this.dst:  # TODO: all CTLs
        this.src = this._gwy._get_device(this.src.id, ctl_id=this.src.id)
        ctl_id = this.src.id if this._gwy.config.enable_eavesdrop else None
        this._gwy._get_device(this.dst.id, ctl_id=ctl_id)

    elif this.dst.type in ("01", "23") and this.src is not this.dst:  # all CTLs
        this.dst = this._gwy._get_device(this.dst.id, ctl_id=this.dst.id)
        ctl_id = this.dst.id if this._gwy.config.enable_eavesdrop else None
        this._gwy._get_device(this.src.id, ctl_id=ctl_id)

    # this should catch all non-controller (and *some* controller) devices
    elif this.src is this.dst:
        this._gwy._get_device(this.src.id)

    # otherwise one will be a controller, *unless* dst is in ("--", "63")
    elif isinstance(this.src, Device) and this.src._is_controller:
        this._gwy._get_device(this.dst.id, ctl_id=this.src.id)

    # TODO: may create a controller that doesn't exist
    elif isinstance(this.dst, Device) and this.dst._is_controller:
        this._gwy._get_device(this.src.id, ctl_id=this.dst.id)

    else:
        # beware:  I --- --:------ --:------ 10:078099 1FD4 003 00F079
        [this._gwy._get_device(d) for d in (this.src.id, this.dst.id)]

    # where possible, swap each Address for its corresponding Device
    this.src = this._gwy.device_by_id.get(this.src.id, this.src)
    if this.dst is not None:
        this.dst = this._gwy.device_by_id.get(this.dst.id, this.dst)


def _create_zones(this: Message) -> None:
    """Discover and create any new zones (except HW)."""

    def proc_0005():
        if this._payload["zone_type"] in _0005_ZONE_TYPE.values():
            [
                evo._get_zone(
                    f"{idx:02X}",
                    zone_type=ZONE_TYPE_SLUGS.get(this._payload["zone_type"]),
                )
                for idx, flag in enumerate(this._payload["zone_mask"])
                if flag == 1
            ]

    def proc_000c():
        if not this.payload["devices"]:
            return

        devices = [this.src.device_by_id[d] for d in this.payload["devices"]]

        if this.payload["device_class"] == ATTR_ZONE_SENSOR:
            zone = evo._get_zone(this.payload["zone_idx"])
            try:
                zone._set_sensor(devices[0])
            except TypeError:  # ignore invalid device types, e.g. 17:
                pass

        elif this.payload["device_class"] == ATTR_ZONE_ACTUATORS:
            # evo._get_zone(this.payload["zone_idx"], actuators=devices)
            # TODO: which is better, above or below?
            zone = evo._get_zone(this.payload["zone_idx"])
            [d._set_parent(zone) for d in devices]

        elif this.payload["device_class"] == ATTR_HTG_CONTROL:
            evo._set_htg_control(devices[0])

        elif this.payload["device_class"] == ATTR_DHW_SENSOR:
            evo._get_dhw()._set_sensor(devices[0])

        elif this.payload["device_class"] == ATTR_DHW_VALVE:
            evo._get_dhw()._set_dhw_valve(devices[0])

        elif this.payload["device_class"] == ATTR_DHW_VALVE_HTG:
            evo._get_dhw()._set_htg_valve(devices[0])

        elif this.payload["device_class"] == ATTR_HTG_CONTROL:
            # TODO: maybe the htg controller is an OTB? via eavesdropping
            # evo._set_htg_control(devices[0])
            pass

    if this.src.type not in ("01", "23"):  # TODO: this is too restrictive!
        return

    evo = this.src._evo

    # TODO: a I/0005: zones have changed & may need a restart (del) or not (add)
    if this.code == _0005:  # RP, and also I
        proc_0005()

    if this.code == _000C and this.src.type == "01":
        proc_000c()

    # # Eavesdropping (below) is used when discovery (above) is not an option
    # # TODO: needs work, e.g. RP/1F41 (excl. null_rp)
    # elif this.code in (_10A0, _1F41):
    #     if isinstance(this.dst, Device) and this.dst._is_controller:
    #         this.dst._get_dhw()
    #     else:
    #         evo._get_dhw()

    # # TODO: also process ufh_idx (but never domain_id)
    # elif isinstance(this._payload, dict):
    #     # TODO: only creating zones from arrays, presently, but could do so here
    #     if this._payload.get("zone_idx"):  # TODO: parent_zone too?
    #         if this.src._is_controller:
    #             evo._get_zone(this._payload["zone_idx"])
    #         else:
    #             this.dst._get_zone(this._payload["zone_idx"])

    elif isinstance(this._payload, list):
        if this.code in (_000A, _2309, _30C9):  # the sync_cycle pkts
            [evo._get_zone(d["zone_idx"]) for d in this.payload]
        # elif this.code in (_22C9, _3150):  # TODO: UFH zone
        #     pass

    # else:  # should never get here
    #     raise TypeError


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

    if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
        _LOGGER.info(msg)

    if not msg.is_valid or msg._gwy.config.reduce_processing >= DONT_CREATE_ENTITIES:
        return

    # # TODO: This will need to be removed for HGI80-impersonation
    # # 18:/RQs are unreliable, although any corresponding RPs are often required
    # if msg.src.type == "18":
    #     return

    try:  # process the packet payload
        _create_devices(msg)  # from pkt header & from msg payload (e.g. 000C)
        _create_zones(msg)  # create zones & (TBD) ufh_zones too?

        if msg._gwy.config.reduce_processing >= DONT_UPDATE_ENTITIES:
            msg._gwy._prev_msg = msg
            return

        # _update_entities(msg, msg._gwy._prev_msg)  # update the state database
        if isinstance(msg.src, Device):
            msg.src._handle_msg(msg)

        if msg.code not in (_0008, _0009, _3B00, _3EF1):
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

    except (AssertionError, NotImplementedError) as err:
        (_LOGGER.error if DEV_MODE else _LOGGER.warning)(
            "%s << %s", msg._pkt, f"{err.__class__.__name__}({err})"
        )
        return  # NOTE: use raise only when debugging

    except (AttributeError, LookupError, TypeError, ValueError) as err:
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)(
            "%s << %s", msg._pkt, f"{err.__class__.__name__}({err})"
        )
        return  # NOTE: use raise only when debugging

    except CorruptStateError as err:  # TODO: add CorruptEvohomeError
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)("%s << %s", msg._pkt, err)
        return  # TODO: bad pkt, or Schema

    msg._gwy._prev_msg = msg
