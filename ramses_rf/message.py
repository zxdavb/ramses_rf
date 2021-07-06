#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Decode/process a message (payload into JSON).
"""

import logging
import re
from datetime import datetime as dt
from datetime import timedelta as td
from typing import Any, Optional, Tuple, Union

from . import parsers
from .const import (
    _0005_ZONE_TYPE,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_HTG_CONTROL,
    ATTR_ZONE_ACTUATORS,
    ATTR_ZONE_SENSOR,
    DEVICE_TYPES,
    MSG_FORMAT_10,
    MSG_FORMAT_18,
    NON_DEV_ADDR,
    NUL_DEV_ADDR,
    ZONE_TYPE_SLUGS,
    Address,
    __dev_mode__,
)
from .devices import Device, FanDevice, OtbGateway
from .exceptions import (
    CorruptEvohomeError,
    CorruptPacketError,
    CorruptPayloadError,
    CorruptStateError,
)
from .opentherm import MSG_ID
from .packet import _PKT_LOGGER  # TODO: bad packets are being logged twice!
from .ramses import CODES_WITH_COMPLEX_IDX, CODES_WITHOUT_IDX, RAMSES_CODES
from .schema import DONT_CREATE_ENTITIES, DONT_UPDATE_ENTITIES

# from .systems import Evohome

CODE_NAMES = {k: v["name"] for k, v in RAMSES_CODES.items()}

I_, RQ, RP, W_ = " I", "RQ", "RP", " W"

# TODO: WIP
MSG_TIMEOUTS = {
    "0004": {I_: td(days=1), RP: td(days=1)},
    "000A": {I_: td(days=1), RP: td(days=1)},
    "0100": {I_: td(days=1), RP: td(days=1)},
    "1060": {I_: td(days=1)},
    "10A0": {RP: td(hours=4)},
    "1100": {I_: td(days=1), RP: td(days=1)},
    "1260": {I_: td(hours=1), RP: td(hours=1)},
    "12B0": {I_: td(hours=1), RP: td(hours=1)},
    "1F41": {I_: td(hours=4), RP: td(hours=4)},
    "2309": {I_: td(minutes=30), RP: td(minutes=30)},
    "2349": {I_: td(hours=4), RP: td(hours=4)},
    "2E04": {I_: td(hours=4), RP: td(hours=4)},
    "313F": {I_: td(seconds=3), RP: td(seconds=3)},
    "3150": {I_: td(minutes=20)},
    "3C09": {I_: td(hours=4), RP: td(hours=4)},
}  # not arrays

DEV_MODE = True or __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

# _PKT_LOGGER = _LOGGER


class Message:
    """The message class.

    Will trap/log all invalid msgs appropriately.
    """

    HAS_EXPIRED = 2
    IS_EXPIRING = 1
    NOT_EXPIRED = 0

    def __init__(self, gwy, pkt) -> None:
        """Create a message, assumes a valid packet."""
        self._gwy = gwy
        self._pkt = pkt

        # prefer Devices but should use Addresses for now...
        self.src = pkt.src_addr  # gwy.device_by_id.get(pkt.src_addr.id, pkt.src_addr)
        self.dst = pkt.dst_addr  # gwy.device_by_id.get(pkt.dst_addr.id, pkt.dst_addr)

        self.devs = pkt.addrs
        self.date = pkt.date
        self.time = pkt.time
        self.dtm = pkt._dtm

        self.rssi = pkt.packet[0:3]
        self.verb = pkt.packet[4:6]
        self.seqn = pkt.packet[7:10]
        self.code = pkt.packet[41:45]
        self.len = int(pkt.packet[46:49])
        self.raw_payload = pkt.packet[50:]

        self.code_name = CODE_NAMES.get(self.code, f"unknown_{self.code}")
        self._payload = None
        self._str = None

        self._haz_payload = None
        self._haz_simple_idx = None

        self._is_array = None
        self._is_expired = None
        self._is_fragment = None

        self._is_valid = None
        if not self.is_valid:
            raise ValueError("not a valid message")

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
            try:
                return f"{DEVICE_TYPES.get(dev.type, f'{dev.type:>3}')}:{dev.id[3:]}"
            except AttributeError:  # TODO: 'NoneType' object has no attribute 'type'
                return "XXX:------"

        if self._str is not None:
            return self._str

        if not self.is_valid:
            return  # "Invalid"

        if self.src.id == self.devs[0].id:
            src = display_name(self.src)
            dst = display_name(self.dst) if self.dst is not self.src else ""
        else:
            src = ""
            dst = display_name(self.src)

        payload = self.raw_payload if self.len < 4 else f"{self.raw_payload[:5]}..."[:9]

        _format = MSG_FORMAT_18 if self._gwy.config.use_names else MSG_FORMAT_10
        self._str = _format.format(
            src, dst, self.verb, self.code_name, payload, self._payload
        )
        return self._str

    def __eq__(self, other) -> bool:
        if not isinstance(other, Message):
            return NotImplemented
        return all(
            self.verb == other.verb,
            self.code == other.code,
            self.src.id == other.src.id,
            self.dst.id == other.dst.id,
            self.raw_payload == other.raw_payload,
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

        if self._haz_payload is not None:
            return self._haz_payload

        if self.len == 1:
            self._haz_payload = False  # TODO: (WIP) has no payload
        elif RAMSES_CODES.get(self.code):
            self._haz_payload = RAMSES_CODES[self.code].get(self.verb) not in (
                r"^00$",
                r"^00(00)?$",
                r"^FF$",
            )
            assert (
                self._haz_payload or self.len < 3
            ), "Message not expected to have a payload! Is it corrupt?"
        else:
            self._haz_payload = True

        return self._haz_payload

    @property
    def _has_simple_idx(self) -> bool:
        """Return False if no index, or if it is complex.(may falsely Return True).

        The message may still have a payload.
        """

        if self._haz_simple_idx is not None:
            return self._haz_simple_idx

        if self.code in CODES_WITH_COMPLEX_IDX:
            self._haz_simple_idx = False  # has (complex) _idx via their parser
        elif self.code in CODES_WITHOUT_IDX:
            self._haz_simple_idx = False  # has no idx, even though some != "00"
        elif RAMSES_CODES.get(self.code):
            self._haz_simple_idx = (
                RAMSES_CODES[self.code].get(self.verb, "")[:3] != "^00"
            )  # has no _idx
            assert (
                self._haz_simple_idx or self.raw_payload[:2] == "00"
            ), "Message not expected to have a index! Is it corrupt?"
        else:
            self._haz_simple_idx = True

        return self._haz_simple_idx

    @property
    def payload(self) -> Any:  # Any[dict, List[dict]]:
        """Return the payload."""
        if self._payload is not None:
            return self._payload

        if self.is_valid:
            if self.code != "000C":  # TODO: assert here, or in is_valid()
                assert self.is_array == isinstance(self._payload, list)
            return self._payload

    @property
    def is_array(self) -> bool:
        """Return True if the message's raw payload is an array.

        Note that the corresponding parsed payload may not match, e.g. the 000C payload
        is not a list.

        Does not require a valid payload.
        """

        if self._is_array is not None:
            return self._is_array

        if self.verb in (RQ, W_):
            self._is_array = False

        elif self.code in ("000C", "1FC9"):  # also: 0005?
            # grep -E ' (I|RP).* 000C '  #  from 01:/30: (VMS) only
            # grep -E ' (I|RP).* 1FC9 '  #  from 01:/13:/other (not W)
            self._is_array = True

        elif self.verb == RP:
            self._is_array = False

        # 087  I 092 --:------ --:------ 12:126457 2309 006 0107D0-020708
        # 090  I 093 --:------ --:------ 12:126457 30C9 003 017FFF
        # 089  I 094 --:------ --:------ 12:126457 000A 012 010001F40BB8-020001F40BB8
        elif self.code in ("000A", "2309", "30C9") and self.src.type == "12":
            self._is_array = self.verb == I_ and self.dst.id == "--:------"

        elif self.verb not in (I_, RP) or self.src.id != self.dst.id:
            self._is_array = False

        # 045  I --- 01:158182 --:------ 01:158182 0009 003 0B00FF (or: FC00FF)
        # 045  I --- 01:145038 --:------ 01:145038 0009 006 FC00FFF900FF
        elif self.code in ("0009",) and self.src.type == "01":
            # grep -E ' I.* 01:.* 01:.* 0009 [0-9]{3} F' (and: grep -v ' 003 ')
            self._is_array = self.verb == I_ and self.raw_payload[:1] == "F"

        elif self.code in ("000A", "2309", "30C9") and self.src.type == "01":
            # grep ' I.* 01:.* 01:.* 000A '
            # grep ' I.* 01:.* 01:.* 2309 ' | grep -v ' 003 '  # TODO: some non-arrays
            # grep ' I.* 01:.* 01:.* 30C9 '
            self._is_array = self.verb == I_ and self.src.id == self.dst.id

        # 055  I --- 02:001107 --:------ 02:001107 22C9 024 0008340A28010108340A...
        # 055  I --- 02:001107 --:------ 02:001107 22C9 006 0408340A2801
        # 055  I --- 02:001107 --:------ 02:001107 3150 010 00640164026403580458
        # 055  I --- 02:001107 --:------ 02:001107 3150 010 00000100020003000400
        elif self.code in ("22C9", "3150") and self.src.type == "02":
            # grep -E ' I.* 02:.* 02:.* 22C9 '
            # grep -E ' I.* 02:.* 02:.* 3150' | grep -v FC
            self._is_array = self.verb == I_ and self.src.id == self.dst.id
            self._is_array = self._is_array if self.raw_payload[:1] != "F" else False

        # 095  I --- 23:100224 --:------ 23:100224 2249 007 007EFF7EFFFFFF
        # 095  I --- 23:100224 --:------ 23:100224 2249 007 007EFF7EFFFFFF
        elif self.code in ("2249",) and self.src.type == "23":
            self._is_array = self.verb == I_ and self.src.id == self.dst.id
            # self._is_array = self._is_array if self.raw_payload[:1] != "F" else False

        else:
            self._is_array = False

        return self._is_array

    @property
    def is_expired(self) -> Tuple[bool, Optional[bool]]:
        """Return True if the message is dated (does not require a valid payload)."""

        def _logger_send(logger, message) -> None:
            if True or DEV_MODE:  # TODO: remove 'True or'
                logger(
                    "Message(%s), received at %s: %s",
                    self._pkt._header,
                    self.dtm,
                    message,
                )

        def _timeout() -> td:  # TODO: move this to RAMSES pkt schema
            timeout = None

            if self.verb in (RQ, W_):
                timeout = td(seconds=3)

            elif self.code in ("0005", "000C", "10E0"):
                return  # TODO: exclude/remove devices caused by corrupt ADDRs?

            elif self.code == "1FC9" and self.verb == RP:
                return  # TODO: check other verbs, they seem variable

            elif self.code == "1F09":
                timeout = td(seconds=self.payload["remaining_seconds"])

            elif self.code == "000A" and self._is_array:
                timeout = td(minutes=60)  # sends I /1h

            elif self.code in ("2309", "30C9") and self._is_array:
                timeout = td(minutes=15)  # sends I /sync_cycle

            elif self.code == "3220":
                if self.payload[MSG_ID] in OtbGateway.SCHEMA_MSG_IDS:
                    timeout = None
                elif self.payload[MSG_ID] in OtbGateway.PARAMS_MSG_IDS:
                    timeout = td(minutes=60)
                else:  # incl. OtbGateway.STATUS_MSG_IDS
                    timeout = td(minutes=5)

            elif self.code in MSG_TIMEOUTS and self.verb in MSG_TIMEOUTS[self.code]:
                return MSG_TIMEOUTS[self.code][self.verb]

            # elif self.code in ("3B00", "3EF0", ):  # TODO: 0008, 3EF0, 3EF1
            #     timeout = td(minutes=6.7)  # TODO: WIP

            return timeout or td(minutes=60)

        if self._is_expired == self.HAS_EXPIRED:  # TODO: or CANT_EXPIRE
            return self._is_expired

        timeout = _timeout()  # TODO: needs fixing

        if timeout is None:  # treat as never expiring
            self._is_expired = self.NOT_EXPIRED  # TODO: CANT_EXPIRE
            # _logger_send(
            #    _LOGGER.debug,
            #    "msg is not expirable",
            # )
            return self._is_expired

        dtm_now = (
            dt.now()
            if self._gwy.serial_port
            else (self._gwy._prev_msg.dtm if self._gwy._prev_msg else self.dtm)
        )

        if self.dtm < dtm_now - timeout * 2:
            if self._is_expired != self.HAS_EXPIRED:
                _logger_send(
                    _LOGGER.error,
                    f"msg has tombstoned ({dtm_now - self.dtm}, {timeout})",
                )
            self._is_expired = self.HAS_EXPIRED

        elif self.dtm < dtm_now - timeout * 1:
            if self._is_expired != self.IS_EXPIRING:
                _logger_send(
                    _LOGGER.info,
                    f"msg has expired ({dtm_now - self.dtm}, {timeout})",
                )
            self._is_expired = self.IS_EXPIRING

        else:
            self._is_expired = self.NOT_EXPIRED
            # _logger_send(
            #     _LOGGER.debug,
            #     f"msg has not expired ({dtm_now - self.dtm}, {timeout})",
            # )
        return self._is_expired

    @property
    def _is_fragment_WIP(self) -> bool:
        """Return True if the raw payload is a fragment of a message."""

        # if not self._is_valid:
        #     return
        if self._is_fragment is not None:
            return self._is_fragment

        # packets have a maximum length of 48 (decimal)
        # if self.code == "000A" and self.verb == I_:
        #     self._is_fragment = True if len(???.zones) > 8 else None
        # el
        if self.code == "0404" and self.verb == RP:
            self._is_fragment = True
        elif self.code == "22C9" and self.verb == I_:
            self._is_fragment = None  # max length 24!
        else:
            self._is_fragment = False

        return self._is_fragment

    @property
    def is_valid(self) -> bool:  # Main code here
        """Parse the payload, return True if the message payload is valid.

        All exceptions are trapped, and logged appropriately.
        """

        def log_message(log_level, log_msg):
            log_level(log_msg, self._pkt, extra=self._pkt.__dict__)

        if self._is_valid is not None:
            return self._is_valid
        self._is_valid = False  # Assume is invalid

        try:  # determine which parser to use
            payload_parser = getattr(parsers, f"parser_{self.code}".lower())

        except AttributeError:  # there's no parser for this command code!
            payload_parser = getattr(parsers, "parser_unknown")

        try:  # parse the packet
            self._payload = payload_parser(self.raw_payload, self)
            assert isinstance(self._payload, dict) or isinstance(
                self._payload, list
            ), "message payload is not dict nor list"

        except AssertionError as err:
            # beware: HGI80 can send parseable but 'odd' packets +/- get invalid reply
            hint = f": {err}" if str(err) != "" else ""
            if not hint or DEV_MODE:
                log_message(_PKT_LOGGER.exception, "%s < Validation error ")
            elif self.src.type != "18":
                log_message(_PKT_LOGGER.exception, f"%s < Validation error{hint} ")
            else:  # elif DEV_MODE:  # TODO: consider info/debug for the following
                log_message(_PKT_LOGGER.exception, f"%s < Validation error{hint} ")

        except (CorruptPacketError, CorruptPayloadError) as err:  # CorruptEvohomeError
            if DEV_MODE:
                log_message(_PKT_LOGGER.exception, f"%s < {err}")
            else:
                log_message(_PKT_LOGGER.warning, f"%s < {err}")

        except (AttributeError, LookupError, TypeError, ValueError):  # TODO: dev only
            log_message(_PKT_LOGGER.exception, "%s < Coding error ")

        except NotImplementedError:  # parser_unknown (unknown packet code)
            log_message(_PKT_LOGGER.warning, "%s < Unknown packet code ")

        else:
            self._is_valid = True

        return self._is_valid


def process_msg(msg: Message) -> None:
    """Decode the packet and its payload.

    All methods require a valid message (payload), except create_devices, which requires
    a valid message only for 000C.
    """

    def create_devices(this) -> None:
        """Discover and create any new devices."""

        if this.code == "000C" and this.verb == RP:
            if this.src.type == "01":  # TODO
                this._gwy._get_device(this.dst, ctl_addr=this.src)
                if this.is_valid:
                    key = "zone_idx" if "zone_idx" in this.payload else "domain_id"
                    [
                        this._gwy._get_device(
                            Address(id=d, type=d[:2]),
                            ctl_addr=this.src,
                            domain_id=this.payload[key],
                        )
                        for d in this.payload["devices"]
                    ]
            if this.src.type == "02":  # TODO
                # this._gwy._get_device(this.dst)
                if this.payload["devices"]:
                    device_id = this.payload["devices"][0]
                    this._gwy._get_device(
                        this.src, ctl_addr=Address(id=device_id, type=device_id[:2])
                    )

        elif this.code in ("31D9", "31DA", "31E0") and this.verb in (I_, RP):
            device = this._gwy._get_device(this.src)
            if device.__class__ is Device:
                device.__class__ = FanDevice  # HACK: because my HVAC is a 30:

        if this.src.type in ("01", "23") and this.src is not this.dst:  # TODO: all CTLs
            this.src = this._gwy._get_device(this.src, ctl_addr=this.src)
            ctl_addr = this.src if msg._gwy.config.enable_eavesdrop else None
            this._gwy._get_device(this.dst, ctl_addr=ctl_addr)

        elif this.dst.type in ("01", "23") and this.src is not this.dst:  # all CTLs
            this.dst = this._gwy._get_device(this.dst, ctl_addr=this.dst)
            ctl_addr = this.dst if msg._gwy.config.enable_eavesdrop else None
            this._gwy._get_device(this.src, ctl_addr=ctl_addr)

        # TODO: will need other changes before these two will work...
        # TODO: the issue is, if the 1st pkt is not a 1F09 (or a list 000A/2309/30C9)
        # TODO: also could do 22D9 (UFC), others?
        # elif this.code == "1F09" and this.verb == I_:
        #     this._gwy._get_device(this.dst, ctl_addr=this.src)

        # TODO: ...such as means to promote a device to a controller

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

    def create_zones(this) -> None:
        """Discover and create any new zones (except HW)."""

        if this.src.type not in ("01", "23"):  # TODO: this is too restrictive!
            return

        evo = this.src._evo

        # TODO: a I/0005: zones have changed & may need a restart (del) or not (add)
        if this.code == "0005":  # RP, and also I
            if this._payload["zone_type"] in _0005_ZONE_TYPE.values():
                [
                    evo._get_zone(
                        f"{idx:02X}",
                        zone_type=ZONE_TYPE_SLUGS.get(this._payload["zone_type"]),
                    )
                    for idx, flag in enumerate(this._payload["zone_mask"])
                    if flag == 1
                ]

        if this.code == "000C" and this.src.type == "01":
            if this.payload["devices"]:  # i.e. if len(devices) > 0
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

        # # Eavesdropping (below) is used when discovery (above) is not an option
        # # TODO: needs work, e.g. RP/1F41 (excl. null_rp)
        # elif this.code in ("10A0", "1F41"):
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
            if this.code in ("000A", "2309", "30C9"):  # the sync_cycle pkts
                [evo._get_zone(d["zone_idx"]) for d in this.payload]
            # elif this.code in ("22C9", "3150"):  # TODO: UFH zone
            #     pass

        # else:  # should never get here
        #     raise TypeError

    def update_entities(this, prev) -> None:  # TODO: needs work
        """Update the state of entities (devices, zones, ufh_zones)."""

        # HACK: merge 000A fragments
        # TODO: ?move to ctl._handle_msg() and/or system._handle_msg()?
        if re.search("I.* 01.* 000A ", str(this._pkt)):  # HACK: and dtm < 3 secs
            # TODO: an edge case here: >2 000A packets in a row
            if prev is not None and re.search("I.* 01.* 000A ", str(prev._pkt)):
                this._payload = prev.payload + this.payload  # merge frags, and process

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
            if this.code in ("10A0", "1260", "1F41") and evo._dhw is not None:
                evo._dhw._handle_msg(this)
            break

        evo = this.src._evo if hasattr(this.src, "_evo") else None
        if evo is None:
            evo = this.dst._evo if hasattr(this.dst, "_evo") else None
        if evo is None:
            return

        if this.src is evo._ctl:
            evo._handle_msg(msg)

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

    if _LOGGER.getEffectiveLevel() == logging.INFO:  # i.e. don't log for DEBUG
        _LOGGER.info(msg)

    # TODO: This will need to be removed for HGI80-impersonation
    # 18:/RQs are unreliable, although any corresponding RPs are often required
    if msg.src.type == "18":
        return

    if msg._gwy.config.reduce_processing >= DONT_CREATE_ENTITIES:
        return

    try:  # process the payload
        create_devices(msg)  # from pkt header & from msg payload (e.g. 000C)
        # if msg._evo:  # TODO:
        create_zones(msg)  # create zones & (TBD) ufh_zones too?

        if msg._gwy.config.reduce_processing < DONT_UPDATE_ENTITIES:
            update_entities(msg, msg._gwy._prev_msg)  # update the state database

    except (AssertionError, NotImplementedError) as err:
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)(
            "%s < %s", msg._pkt, err.__class__.__name__
        )
        return  # NOTE: use raise only when debugging

    except (AttributeError, LookupError, TypeError, ValueError) as err:
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)(
            "%s < %s", msg._pkt, err.__class__.__name__
        )
        return  # NOTE: use raise only when debugging

    # except CorruptPacketError as err:
    #     (_LOGGER.exception if DEV_MODE else _LOGGER.error)(
    #         "%s < %s", msg._pkt, err
    #     )
    #     return  # NOTE: use raise only when debugging

    except CorruptStateError as err:
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)("%s < %s", msg._pkt, err)
        return  # TODO: bad pkt, or Schema

    except CorruptEvohomeError as err:
        (_LOGGER.exception if DEV_MODE else _LOGGER.error)("%s < %s", msg._pkt, err)
        raise

    msg._gwy._prev_msg = msg if msg.is_valid else None
