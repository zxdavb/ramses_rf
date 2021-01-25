#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser.

Decode/process a message (payload into JSON).
"""

from datetime import datetime as dt, timedelta as td
import logging
import re
from typing import Any, Optional, Union

from . import parsers
from .const import (
    ATTR_HTG_CONTROL,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE_HTG,
    ATTR_DHW_VALVE,
    ATTR_ZONE_SENSOR,
    DEVICE_TYPES,
    MSG_FORMAT_10,
    MSG_FORMAT_18,
    NON_DEVICE,
    NUL_DEVICE,
    CODE_0005_ZONE_TYPE,
    ZONE_TYPE_SLUGS,
    Address,
    _dev_mode_,
)
from .devices import Device
from .exceptions import EvoCorruptionError, CorruptPayloadError
from .packet import _PKT_LOGGER
from .ramses import HINTS_CODE_SCHEMA as HINTS_CODES
from .schema import (
    REDUCE_PROCESSING,
    USE_NAMES,
    DONT_CREATE_MESSAGES,
    DONT_CREATE_ENTITIES,
    DONT_UPDATE_ENTITIES,
)

CODE_NAMES = {k: v["name"] for k, v in HINTS_CODES.items()}

DEV_MODE = _dev_mode_ or True

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Message:
    """The message class.

    Will trap/log all invalid msgs appropriately.
    """

    def __init__(self, gwy, pkt) -> None:
        """Create a message, assumes a valid packet."""
        self._gwy = gwy
        self._pkt = pkt

        # prefer Device(s) but Address(es) will do
        self.src = self._gwy.device_by_id.get(pkt.src_addr.id, pkt.src_addr)
        self.dst = self._gwy.device_by_id.get(pkt.dst_addr.id, pkt.dst_addr)

        self.devs = pkt.addrs
        self.date = pkt.date
        self.time = pkt.time
        self.dtm = dt.fromisoformat(f"{pkt.date}T{pkt.time}")

        self.rssi = pkt.packet[0:3]
        self.verb = pkt.packet[4:6]
        self.seqn = pkt.packet[7:10]  # sequence number (as used by 31D9)?
        self.code = pkt.packet[41:45]

        self.len = int(pkt.packet[46:49])  # TODO:  is useful? / is user used?
        self.raw_payload = pkt.packet[50:]

        self._payload = self._str = None

        self._format = MSG_FORMAT_18 if gwy.config[USE_NAMES] else MSG_FORMAT_10

        self._is_valid = self._is_array = self._is_expired = self._is_fragment = None
        self._is_valid = self.is_valid

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return self._pkt.packet

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""

        def display_name(dev: Union[Address, Device]) -> str:
            """Return a formatted device name, uses a friendly name if there is one."""
            if self._gwy.config[USE_NAMES]:
                try:
                    return f"{self._gwy.known_devices[dev.id]['name']:<18}"
                except (KeyError, TypeError):
                    pass

            if dev is NON_DEVICE:
                return f"{'':<10}"

            if dev is NUL_DEVICE:
                return "NUL:------"

            return f"{DEVICE_TYPES.get(dev.type, f'{dev.type:>3}')}:{dev.id[3:]}"

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

        code_name = CODE_NAMES.get(self.code, f"unknown_{self.code}")
        payload = self.raw_payload if self.len < 4 else f"{self.raw_payload[:5]}..."[:9]

        self._str = self._format.format(
            src, dst, self.verb, code_name, payload, self._payload
        )
        return self._str

    def __eq__(self, other) -> bool:
        return all(
            self.verb == other.verb,
            self.code == other.code,
            self.src.id == other.src.id,
            self.dst.id == other.dst.id,
            self.raw_payload == other.raw_payload,
        )

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

        if self.code in ("000C", "1FC9"):  # also: 0005?
            # grep -E ' (I|RP).* 000C '  #  from 01:/30: (VMS) only
            # grep -E ' (I|RP).* 1FC9 '  #  from 01:/13:/other (not W)
            self._is_array = self.verb in (" I", "RP")

        elif self.verb not in (" I", "RP") or self.src.id != self.dst.id:
            self._is_array = False

        # 045  I --- 01:158182 --:------ 01:158182 0009 003 0B00FF (or: FC00FF)
        # 045  I --- 01:145038 --:------ 01:145038 0009 006 FC00FFF900FF
        elif self.code in ("0009",) and self.src.type == "01":
            # grep -E ' I.* 01:.* 01:.* 0009 [0-9]{3} F' (and: grep -v ' 003 ')
            self._is_array = self.verb == " I" and self.raw_payload[:1] == "F"

        elif self.code in ("000A", "2309", "30C9") and self.src.type == "01":
            # grep ' I.* 01:.* 01:.* 000A '
            # grep ' I.* 01:.* 01:.* 2309 ' | grep -v ' 003 '  # TODO: some non-arrays
            # grep ' I.* 01:.* 01:.* 30C9 '
            self._is_array = self.verb == " I" and self.src.id == self.dst.id

        # 055  I --- 02:001107 --:------ 02:001107 22C9 024 0008340A28010108340A...
        # 055  I --- 02:001107 --:------ 02:001107 22C9 006 0408340A2801
        # 055  I --- 02:001107 --:------ 02:001107 3150 010 00640164026403580458
        # 055  I --- 02:001107 --:------ 02:001107 3150 010 00000100020003000400
        elif self.code in ("22C9", "3150") and self.src.type == "02":
            # grep -E ' I.* 02:.* 02:.* 22C9 '
            # grep -E ' I.* 02:.* 02:.* 3150' | grep -v FC
            self._is_array = self.verb == " I" and self.src.id == self.dst.id
            self._is_array = self._is_array if self.raw_payload[:1] != "F" else False

        # 095  I --- 23:100224 --:------ 23:100224 2249 007 007EFF7EFFFFFF
        # 095  I --- 23:100224 --:------ 23:100224 2249 007 007EFF7EFFFFFF
        elif self.code in ("2249",) and self.src.type == "23":
            self._is_array = self.verb == " I" and self.src.id == self.dst.id
            # self._is_array = self._is_array if self.raw_payload[:1] != "F" else False

        else:
            self._is_array = False

        return self._is_array

    @property
    def is_expired(self) -> Optional[bool]:
        """Return True if the message is dated (does not require a valid payload)."""

        if self._is_expired is not None:
            return self._is_expired
        elif self.code in ("1F09", "313F"):
            timeout = td(seconds=3)
        elif self.code in ("2309", "3C09"):
            timeout = td(minutes=15)
        elif self.code in ("3150",):
            timeout = td(minutes=20)  # sends I /20min
        elif self.code in ("000A",):
            timeout = td(minutes=60)  # sends I (array) /1h
        elif self.code in ("1260", "12B0", "1F41", "2349", "2E04"):
            timeout = td(minutes=60)  # sends I /1h
        else:  # treat as never expiring
            self._is_expired = False
            return self._is_expired

        dtm = self._gwy._prev_msg.dtm if self._gwy.serial_port is None else dt.now()
        if self.dtm < dtm - timeout * 2:
            self._is_expired = True
        return self._is_expired

    @property
    def is_fragment_WIP(self) -> bool:
        """Return True if the raw payload is a fragment of a message."""

        # if not self._is_valid:
        #     return
        if self._is_fragment is not None:
            return self._is_fragment

        # packets have a maximum length of 48 (decimal)
        # if self.code == "000A" and self.verb == " I":
        #     self._is_fragment = True if len(???.zones) > 8 else None
        # el
        if self.code == "0404" and self.verb == "RP":
            self._is_fragment = True
        elif self.code == "22C9" and self.verb == " I":
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

        try:  # determine which parser to use
            payload_parser = getattr(parsers, f"parser_{self.code}".lower())

        except AttributeError:  # there's no parser for this command code!
            payload_parser = getattr(parsers, "parser_unknown")

        try:  # run the parser
            self._payload = payload_parser(self.raw_payload, self)
            assert isinstance(self._payload, dict) or isinstance(self._payload, list)

        except AssertionError as err:
            # beware: HGI80 can send parseable but 'odd' packets +/- get invalid reply
            hint = f": {err}" if str(err) != "" else ""
            log_message(
                _PKT_LOGGER.exception if DEV_MODE else _LOGGER.warning,
                f"%s < Validation error{hint} ",
            )
            self._is_valid = False
            return self._is_valid

        except CorruptPayloadError as err:
            hint = f": {err}" if str(err) != "" else ""
            log_message(_PKT_LOGGER.warning, f"%s < Validation error{hint} (payload) ")
            self._is_valid = False
            return self._is_valid

        except (AttributeError, LookupError, TypeError, ValueError):  # for development
            log_message(_PKT_LOGGER.exception, "%s < Coding error ")
            self._is_valid = False
            return self._is_valid

        except NotImplementedError:  # unknown packet code
            log_message(_PKT_LOGGER.warning, "%s < Unknown packet code ")
            self._is_valid = False
            return self._is_valid

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

        if this.code == "000C" and this.verb == "RP":
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
                if this.payload["devices"]:
                    device_id = this.payload["devices"][0]
                    this._gwy._get_device(
                        this.src, ctl_addr=Address(id=device_id, type=device_id[:2])
                    )

        elif this.src.type in ("01", "23"):  # TODO: "30" for VMS
            this._gwy._get_device(this.dst, ctl_addr=this.src)

        elif this.dst.type in ("01", "23"):  # TODO: "30" for VMS
            this._gwy._get_device(this.src, ctl_addr=this.dst)

        # TODO: will need other changes before these two will work...
        # TODO: the issue is, if the 1st pkt is not a 1F09 (or a list 000A/2309/30C9)
        # TODO: also could do 22D9 (UFC), others?
        # elif this.code == "1F09" and this.verb == " I":
        #     this._gwy._get_device(this.dst, ctl_addr=this.src)

        # elif this.code == "31D9" and this.verb == " I":  # HVAC
        #     this._gwy._get_device(this.dst, ctl_addr=this.src)
        # TODO: ...such as means to promote a device to a controller

        # this should catch all non-controller (and *some* controller) devices
        elif this.dst is this.src:
            this._gwy._get_device(this.src)

        # otherwise one will be a controller, *unless* dst is in ("--", "63")
        elif isinstance(this.src, Device) and this.src.is_controller:
            this._gwy._get_device(this.dst, ctl_addr=this.src)

        # TODO: may create a controller that doesn't exist
        elif isinstance(this.dst, Device) and this.dst.is_controller:
            this._gwy._get_device(this.src, ctl_addr=this.dst)

        else:
            [this._gwy._get_device(d) for d in (this.src, this.dst)]

        # where possible, swap each Address for its corresponding Device
        this.src = this._gwy.device_by_id.get(this.src.id, this.src)
        this.dst = this._gwy.device_by_id.get(this.dst.id, this.dst)

    def create_zones(this) -> None:
        """Discover and create any new zones (except HW)."""

        if this.src.type not in ("01", "23"):  # TODO: this is too restrictive!
            return

        evo = this.src._evo

        # TODO: a I/0005: zones have changed & may need a restart (del) or not (add)
        if this.code == "0005":  # RP, and also I
            if this._payload["zone_type"] in CODE_0005_ZONE_TYPE.values():
                [
                    evo._get_zone(
                        f"{idx:02X}",
                        zone_type=ZONE_TYPE_SLUGS.get(this._payload["zone_type"]),
                    )
                    for idx, flag in enumerate(this._payload["zone_mask"])
                    if flag == 1
                ]

        if this.code == "000C" and this.payload["devices"] and this.src.type == "01":
            devices = [this.src.device_by_id[d] for d in this.payload["devices"]]

            if this.payload["device_class"] == ATTR_ZONE_SENSOR:
                zone = evo._get_zone(this.payload["zone_idx"])
                try:
                    zone._set_sensor(devices[0])
                except TypeError:  # ignore invalid device types, e.g. 17:
                    pass

            elif this.payload["device_class"] == "zone_actuators":
                # TODO: is this better, or...
                # evo._get_zone(this.payload["zone_idx"], actuators=devices)
                # TODO: is it this one?
                zone = evo._get_zone(this.payload["zone_idx"])
                for d in devices:
                    d._set_zone(zone)

            elif this.payload["device_class"] == ATTR_HTG_CONTROL:
                evo._set_htg_control(devices[0])

            elif this.payload["device_class"] == ATTR_DHW_SENSOR:
                # evo._get_zone("HW")._set_sensor(devices[0])
                evo._get_zone("HW")._set_sensor(devices[0])

            elif this.payload["device_class"] == ATTR_DHW_VALVE:
                # evo._get_zone("HW")._set_dhw_valve(devices[0])
                evo._set_dhw_valve(devices[0])

            elif this.payload["device_class"] == ATTR_DHW_VALVE_HTG:
                # evo._get_zone("HW")._set_htg_valve(devices[0])
                evo._set_htg_valve(devices[0])

        # # Eavesdropping (below) is used when discovery (above) is not an option
        # # TODO: needs work, e.g. RP/1F41 (excl. null_rp)
        # elif this.code in ("10A0", "1F41"):
        #     if isinstance(this.dst, Device) and this.dst.is_controller:
        #         this.dst._get_zone("HW")
        #     else:
        #         evo._get_zone("HW ")

        # # TODO: also process ufh_idx (but never domain_id)
        # elif isinstance(this._payload, dict):
        #     # TODO: only creating zones from arrays, presently, but could do so here
        #     if this._payload.get("zone_idx"):  # TODO: parent_zone too?
        #         if this.src.is_controller:
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
            return

        # some empty payloads may still be useful (e.g. RQ/3EF1/{})
        this._gwy.device_by_id[this.src.id]._handle_msg(this)
        # if payload is {} (empty dict; lists shouldn't ever be empty)
        if not this.payload:
            return

        # # try to find the boiler relay, dhw sensor
        # for evo in this._gwy.systems:
        #     if this.src == evo:  # TODO: or this.src.id == evo.id?
        #         if this.code in ("10A0", "1260", "1F41") and evo._dhw is not None:
        #             evo._dhw._handle_msg(this)
        #         break

        #     if this.src.controller == evo:  # TODO: this.src.controller.id == evo.id?
        #         evo._handle_msg(this, prev)  # TODO: WIP
        #         break

        evo = this.src._evo if hasattr(this.src, "_evo") else None
        if evo is None:
            evo = this.dst._evo if hasattr(this.dst, "_evo") else None
        if evo is None:
            return

        evo._handle_msg(msg)

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

    try:
        if msg._gwy.config[REDUCE_PROCESSING] >= DONT_CREATE_MESSAGES:
            return

        # 18:/RQs are unreliable, although any corresponding RPs are often required
        if msg.src.type == "18":
            return

        if msg._gwy.config[REDUCE_PROCESSING] >= DONT_CREATE_ENTITIES:
            return

        create_devices(msg)  # from pkt header & from msg payload (e.g. 000C)
        create_zones(msg)  # create zones & ufh_zones (TBD)

        if msg._gwy.config[REDUCE_PROCESSING] >= DONT_UPDATE_ENTITIES:
            return

        update_entities(msg, msg._gwy._prev_msg)  # update the state database

    except (AssertionError, NotImplementedError) as err:
        _LOGGER.exception("%s < %s", msg._pkt, err.__class__.__name__)
        return

    except (AttributeError, LookupError, TypeError, ValueError) as err:
        _LOGGER.error("%s < %s", msg._pkt, err.__class__.__name__)
        raise

    except EvoCorruptionError as err:
        _LOGGER.error("%s < %s", msg._pkt, err.__class__.__name__)
        raise

    msg._gwy._prev_msg = msg if msg.is_valid else None
