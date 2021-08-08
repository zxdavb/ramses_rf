#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a message (payload into JSON).
"""

import logging
from datetime import datetime as dt
from datetime import timedelta as td
from typing import Any, Optional, Tuple, Union

from .address import NON_DEV_ADDR, NUL_DEV_ADDR, Address
from .const import (
    _0005_ZONE_TYPE,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_HTG_CONTROL,
    ATTR_ZONE_ACTUATORS,
    ATTR_ZONE_SENSOR,
    DEVICE_TYPES,
    DONT_CREATE_ENTITIES,
    DONT_UPDATE_ENTITIES,
    ZONE_TYPE_SLUGS,
)
from .devices import Device, OtbGateway
from .exceptions import CorruptStateError
from .opentherm import MSG_ID
from .parsers import parse_payload
from .ramses import CODE_IDX_COMPLEX, RAMSES_CODES

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

__all__ = ["Message", "process_msg"]

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
            raise ValueError(f"not a valid message: {pkt}")

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return self._pkt.packet

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""

        def display_name(dev: Union[Address, Device]) -> str:
            """Return a formatted device name, uses a friendly name if there is one."""
            if self._gwy.config.use_names:
                try:
                    return f"{self._gwy.known_devices[dev.id]['name']:<18}"
                except (KeyError, TypeError):
                    pass

            if dev is NON_DEV_ADDR:
                return f"{'':<10}"

            if dev is NUL_DEV_ADDR:
                return "NUL:------"

            return f"{DEVICE_TYPES.get(dev.type, f'{dev.type:>3}')}:{dev.id[3:]}"

        # return repr(self)

        if self._str is not None:
            return self._str

        if not self.is_valid:
            return  # "Invalid"

        if self.src.id == self._addrs[0].id:
            src = display_name(self.src)
            dst = display_name(self.dst) if self.dst is not self.src else ""
        else:
            src = ""
            dst = display_name(self.src)

        context = {True: "[..]", False: "", None: " ?? "}.get(
            self._pkt._ctx, self._pkt._ctx
        )

        if not self._pkt._ctx and self.raw_payload[:2] not in ("00", "FF"):
            context = f"({self.raw_payload[:2]})"

        _format = MSG_FORMAT_18 if self._gwy.config.use_names else MSG_FORMAT_10
        self._str = _format.format(
            src, dst, self.verb, self.code_name, context, self.payload
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

        if self.len == 1:
            self.__has_payload = False  # TODO: (WIP) has no payload
        elif RAMSES_CODES.get(self.code):
            self.__has_payload = RAMSES_CODES[self.code].get(self.verb) not in (
                r"^00$",
                r"^00(00)?$",
                r"^FF$",
            )
            assert (
                self.__has_payload or self.len < 3
            ), "Message not expected to have a payload! Is it corrupt?"
        else:
            self.__has_payload = True

        return self.__has_payload

    @property
    def payload(self) -> Any:  # Any[dict, List[dict]]:
        """Return the payload."""
        if self._payload is not None:
            return self._payload

        if self.is_valid:
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

        if self.code in (_3220,):
            return {}  # above was: CODE_IDX_COMPLEX + [_3150]:

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

        if self.__expired is not None:  # does not require self._is_valid
            if self.__expired == self.CANT_EXPIRE:
                return False
            if self.__expired >= self.HAS_EXPIRED * 2:  # TODO: should delete?
                return True

        if self.code in (_1F09, _3220):
            if self.code == _1F09:
                timeout = td(seconds=self.payload["remaining_seconds"])
            elif self.payload[MSG_ID] in OtbGateway.SCHEMA_MSG_IDS:
                timeout = None
            elif self.payload[MSG_ID] in OtbGateway.PARAMS_MSG_IDS:
                timeout = td(minutes=60)
            # elif self.payload[MSG_ID] in OtbGateway.STATUS_MSG_IDS:
            #     timeout = td(minutes=5)
            else:
                timeout = td(minutes=5)

            dtm_now = (
                dt.now()
                if (True or self._gwy.serial_port)  # TODO
                else (self._gwy._prev_msg.dtm if self._gwy._prev_msg else self.dtm)
            )  # FIXME: use global timer
            self.__expired = timeout / (dtm_now - self.dtm) if timeout else False

        else:
            self.__expired = self._pkt._expired

        if self.__expired is False:  # treat as never expiring
            _LOGGER.info("%s # can't expire", self._pkt)
            self.__expired = self.CANT_EXPIRE

        elif self.__expired >= self.HAS_EXPIRED:  # TODO: should renew?
            _LOGGER.warning(
                "%s # has expired %s", self._pkt, f"({self.__expired * 100:1.0f}%)"
            )

        # elif self.__expired >= self.IS_EXPIRING:  # this could log multiple times
        #     _LOGGER.error("%s # is expiring", self._pkt)

        # and self.dtm >= dt.now() - td(days=7)  # TODO: shouldn't be any >7d?
        return self.__expired >= self.HAS_EXPIRED

    @property
    def _is_fragment_WIP(self) -> bool:
        """Return True if the raw payload is a fragment of a message."""

        # if not self._is_valid:
        #     return
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
            self._is_valid = self._payload is not None
        return self._is_valid


def _create_devices(this: Message) -> None:
    """Discover and create any new devices."""

    def proc_000c():
        if this.src.type == "01":  # TODO
            this._gwy._get_device(this.dst, ctl_addr=this.src)
            # if this.is_valid:
            key = "zone_idx" if "zone_idx" in this.payload else "domain_id"
            [
                this._gwy._get_device(
                    Address(id=d, type=d[:2]),
                    ctl_addr=this.src,
                    domain_id=this.payload[key],
                )
                for d in this.payload["devices"]
            ]
        elif this.src.type == "02":  # TODO
            # this._gwy._get_device(this.dst)
            if this.payload["devices"]:
                device_id = this.payload["devices"][0]
                this._gwy._get_device(
                    this.src, ctl_addr=Address(id=device_id, type=device_id[:2])
                )

        elif this.payload["device_class"] == ATTR_HTG_CONTROL:
            # TODO: maybe the htg controller is an OTB? via eavesdropping
            # evo._set_htg_control(devices[0])
            pass

    if this.code == _000C and this.verb == RP:
        proc_000c()

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
            # TODO: whihc is better, above or below?
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


def _update_entities(this: Message, prev: Message) -> None:  # TODO: needs work
    """Update the state of entities (devices, zones, ufh_zones)."""

    # some devices aren't created if they're filtered out (in create_devices?)
    if this.src not in this._gwy.devices:
        assert False, "what!!"
        return
        # 0008: BDR/RP, ir CTL/I/domain_id = F9/FA
        # 10A0: CTL/RP/dhw_idx
        # 1260: RP from CTL, or eavesdrop sensor
        # 1F41: eavesdrop

    # some empty payloads may still be useful (e.g. Rx/3EF0/{}, RQ/3EF1/{})
    this._gwy.device_by_id[this.src.id]._handle_msg(this)
    # if payload is {} (empty dict; lists shouldn't ever be empty)
    # if not this.payload:
    #     return

    # # TODO: what follows is a mess - needs sorting out
    # evo = this._gwy.system_by_id.get(this.src.id)
    # if evo:
    #     evo._handle_msg(this)

    for evo in this._gwy.systems:
        # if this.src == evo:  # TODO: or this.src.id == evo.id?
        if this.code in (_10A0, _1260, _1F41) and evo._dhw is not None:
            evo._dhw._handle_msg(this)
        break

    evo = this.src._evo if hasattr(this.src, "_evo") else None
    if evo is None:
        evo = this.dst._evo if hasattr(this.dst, "_evo") else None
    if evo is None:
        return

    if this.src is evo._ctl:
        evo._handle_msg(this)

    if not hasattr(evo, "zone_by_idx"):
        return

    if isinstance(this.payload, dict) and "zone_idx" in this.payload:
        # 089  I --- 02:000921 --:------ 01:191718 3150 002 0300  # NOTE: is valid
        if this.payload["zone_idx"] in evo.zone_by_idx:
            evo.zone_by_idx[this.payload["zone_idx"]]._handle_msg(this)

        # elif "ufh_idx" in this.payload:
        #     # ufc = this.src._ufc if hasattr(this.src, "_ufc") else None
        #     pass

    elif isinstance(this.payload, list) and "zone_idx" in this.payload[0]:
        for z in this.payload:
            if z["zone_idx"] in evo.zone_by_idx:
                evo.zone_by_idx[z["zone_idx"]]._handle_msg(this)


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

    # TODO: This will need to be removed for HGI80-impersonation
    # 18:/RQs are unreliable, although any corresponding RPs are often required
    if msg.src.type == "18":
        return

    try:  # process the packet payload
        _create_devices(msg)  # from pkt header & from msg payload (e.g. 000C)
        _create_zones(msg)  # create zones & (TBD) ufh_zones too?

        if msg._gwy.config.reduce_processing < DONT_UPDATE_ENTITIES:
            _update_entities(msg, msg._gwy._prev_msg)  # update the state database

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
