#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Message processor."""

from datetime import datetime as dt
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
    CODE_MAP,
    DEVICE_TYPES,
    MSG_FORMAT_10,
    MSG_FORMAT_18,
    NON_DEVICE,
    NUL_DEVICE,
    CODE_0005_ZONE_TYPE,
    ZONE_TYPE_SLUGS,
    Address,
    __dev_mode__,
)
from .devices import Device
from .exceptions import CorruptPayloadError

_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


def exception_handler(func):
    """xxx."""

    def wrapper(*args, **kwargs) -> Optional[Any]:
        """xxx."""
        try:
            return func(*args, **kwargs)
        except (AssertionError, NotImplementedError) as err:
            msg = args[0]
            _LOGGER.exception(
                "%s < %s", msg._pkt, err.__class__.__name__, extra=msg.__dict__
            )
            raise
        # TODO: this shouldn't be required?
        except (AttributeError, LookupError, TypeError, ValueError) as err:
            msg = args[0]
            _LOGGER.error(
                "%s < %s", msg._pkt, err.__class__.__name__, extra=msg.__dict__
            )
            raise

    return wrapper


class Message:
    """The message class."""

    def __init__(self, gateway, pkt) -> None:
        """Create a message, assumes a valid packet."""
        self._gwy = gateway
        self._pkt = packet = pkt.packet

        # prefer Device(s) but Address(es) will do
        self.src = gateway.device_by_id.get(pkt.src_addr.id, pkt.src_addr)
        self.dst = gateway.device_by_id.get(pkt.dst_addr.id, pkt.dst_addr)

        self.devs = pkt.addrs
        self.date = pkt.date
        self.time = pkt.time
        self.dtm = dt.fromisoformat(f"{pkt.date}T{pkt.time}")

        self.rssi = packet[0:3]
        self.verb = packet[4:6]
        self.seqn = packet[7:10]  # sequence number (as used by 31D9)?
        self.code = packet[41:45]

        self.len = int(packet[46:49])  # TODO:  is useful? / is user used?
        self.raw_payload = packet[50:]

        self._payload = self._str = None

        self._is_valid = self._is_array = self._is_fragment = None
        self._is_valid = self.is_valid

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return self._pkt

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""

        def display_name(dev: Union[Address, Device]) -> str:
            """Return a formatted device name, uses a friendly name if there is one."""
            if dev is NON_DEVICE:
                return f"{'':<10}"

            if dev is NUL_DEVICE:
                return "NUL:------"

            if dev.id in self._gwy.known_devices:
                if self._gwy.known_devices[dev.id].get("friendly_name"):
                    return self._gwy.known_devices[dev.id]["friendly_name"]

            return f"{DEVICE_TYPES.get(dev.type, f'{dev.type:>3}')}:{dev.id[3:]}"

        if self._str is not None:
            return self._str

        if not self.is_valid:
            return

        _format = MSG_FORMAT_18 if self._gwy.config["known_devices"] else MSG_FORMAT_10

        if self.src.id == self.devs[0].id:
            src = display_name(self.src)
            dst = display_name(self.dst) if self.dst is not self.src else ""
        else:
            src = ""
            dst = display_name(self.src)

        code = CODE_MAP.get(self.code, f"unknown_{self.code}")
        payload = self.raw_payload if self.len < 4 else f"{self.raw_payload[:5]}..."[:9]

        self._str = _format.format(src, dst, self.verb, code, payload, self._payload)
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
        elif self.code in ("0009") and self.src.type == "01":
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
        elif self.code in ("2249") and self.src.type == "23":
            self._is_array = self.verb == " I" and self.src.id == self.dst.id
            # self._is_array = self._is_array if self.raw_payload[:1] != "F" else False

        else:
            self._is_array = False

        return self._is_array

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

        if self._is_valid is not None:
            return self._is_valid

        try:  # determine which parser to use
            payload_parser = getattr(parsers, f"parser_{self.code}".lower())

        except AttributeError:  # there's no parser for this command code!
            payload_parser = getattr(parsers, "parser_unknown")

        try:  # run the parser
            self._payload = payload_parser(self.raw_payload, self)
            assert isinstance(self._payload, dict) or isinstance(self._payload, list)

        except (AssertionError, CorruptPayloadError):
            # beware: HGI80 can send parseable but 'odd' packets +/- get invalid reply
            if self.src.type == "18":  # TODO: should be a warning
                _LOGGER.warning(
                    "%s < Validation error (this is OK to ignore)",
                    self._pkt,
                    extra=self.__dict__,
                )
            else:
                _LOGGER.exception(
                    "%s < Validation error", self._pkt, extra=self.__dict__
                )
            self._is_valid = False
            return self._is_valid

        except (AttributeError, LookupError, TypeError, ValueError):  # for development
            _LOGGER.exception("%s < Coding error", self._pkt, extra=self.__dict__)
            self._is_valid = False
            return self._is_valid

        except NotImplementedError:  # unknown packet code
            _LOGGER.warning("%s < Unknown packet code", self._pkt, extra=self.__dict__)
            self._is_valid = False
            return self._is_valid

        else:
            self._is_valid = True

        # any remaining messages are valid, so: log them with one of these schemes
        if False and __dev_mode__:  # a hack to colourize by cycle
            if self.src.type == "01" and self.verb == " I":
                if (
                    self.code == "1F09"
                    or self.code in ("2309", "30C9", "000A")
                    and isinstance(self.payload, list)
                ):
                    _LOGGER.warning("%s", self, extra=self.__dict__)
                else:
                    _LOGGER.info("%s", self, extra=self.__dict__)
            else:
                _LOGGER.info("%s", self, extra=self.__dict__)

        elif False and __dev_mode__:  # a hack to colourize by verb
            if " I" in str(self):
                _LOGGER.info("%s", self, extra=self.__dict__)
            elif "RP" in str(self):
                _LOGGER.warning("%s", self, extra=self.__dict__)
            else:
                _LOGGER.error("%s", self, extra=self.__dict__)

        # elif self.src.id == "13:237335":
        elif self.verb == "RP" and self.src.type == "13":
            _LOGGER.warning("%s", self, extra=self.__dict__)

        elif self.code == "3B00":
            _LOGGER.info("%s", self, extra=self.__dict__)

        else:  # the normal mode logging scheme
            # TODO: parsing is 2x fast without this logging...
            _LOGGER.info("%s", self, extra=self.__dict__)
            pass

        return self._is_valid

    @exception_handler
    def create_devices(self) -> None:
        """Discover and create any new devices.

        Requires a valid packet; only 000C requires a valid message.
        """

        if self.code == "000C" and self.verb == "RP":
            if self.src.type == "01":  # TODO
                self._gwy.get_device(self.dst, controller=self.src)
                if self.is_valid:
                    key = "zone_idx" if "zone_idx" in self.payload else "domain_id"
                    [
                        self._gwy.get_device(
                            Address(id=d, type=d[:2]),
                            controller=self.src,
                            domain_id=self.payload[key],
                        )
                        for d in self.payload["devices"]
                    ]
            if self.src.type == "02":  # TODO
                if self.payload["devices"]:
                    device_id = self.payload["devices"][0]
                    self._gwy.get_device(
                        self.src, controller=Address(id=device_id, type=device_id[:2])
                    )

        elif self.src.type in ("01", "23"):  # TODO: "30" for VMS
            self._gwy.get_device(self.dst, controller=self.src)

        elif self.dst.type in ("01", "23"):  # TODO: "30" for VMS
            self._gwy.get_device(self.src, controller=self.dst)

        # TODO: will need other changes before these two will work...
        # TODO: the issue is, if the 1st pkt is not a 1F09 (or a list 000A/2309/30C9)
        # TODO: also could do 22D9 (UFC), others?
        # elif self.code == "1F09" and self.verb == " I":
        #     self._gwy.get_device(self.dst, controller=self.src)

        # elif self.code == "31D9" and self.verb == " I":  # HVAC
        #     self._gwy.get_device(self.dst, controller=self.src)
        # TODO: ...such as means to promote a device to a controller

        # this should catch all non-controller (and *some* controller) devices
        elif self.dst is self.src:
            self._gwy.get_device(self.src)

        # otherwise one will be a controller, *unless* dst is in ("--", "63")
        elif isinstance(self.src, Device) and self.src.is_controller:
            self._gwy.get_device(self.dst, controller=self.src)

        # TODO: may create a controller that doesn't exist
        elif isinstance(self.dst, Device) and self.dst.is_controller:
            self._gwy.get_device(self.src, controller=self.dst)

        else:
            self._gwy.get_device(self.src)
            self._gwy.get_device(self.dst)

        # where possible, swap each Address for its corresponding Device
        self.src = self._gwy.device_by_id.get(self.src.id, self.src)
        self.dst = self._gwy.device_by_id.get(self.dst.id, self.dst)

    @exception_handler
    def create_zones(self) -> None:
        """Discover and create any new zones (except HW)."""

        if not self.is_valid:  # requires self.payload
            return

        if self.src.type not in ("01", "23"):  # TODO: this is too restrictive!
            return

        # TODO: a I/0005: zones have changed & may need a restart (del) or not (add)
        if self.code == "0005":  # RP, and also I
            if self._payload["zone_type"] in CODE_0005_ZONE_TYPE.values():
                [
                    self.src.get_zone(
                        f"{idx:02X}",
                        zone_type=ZONE_TYPE_SLUGS.get(self._payload["zone_type"]),
                    )
                    for idx, flag in enumerate(self._payload["zone_mask"])
                    if flag == 1
                ]

        if self.code == "000C" and self.payload["devices"] and self.src.type == "01":
            devices = [self.src.device_by_id[d] for d in self.payload["devices"]]

            if self.payload["device_class"] == ATTR_ZONE_SENSOR:
                zone = self.src.get_zone(self.payload["zone_idx"])
                zone._set_sensor(devices[0])

            elif self.payload["device_class"] == "zone_actuators":
                # TODO: is this better, or...
                # self.src.get_zone(self.payload["zone_idx"], actuators=devices)
                # TODO: is it this one?
                zone = self.src.get_zone(self.payload["zone_idx"])
                for d in devices:
                    d.zone = zone

            elif self.payload["device_class"] == ATTR_HTG_CONTROL:
                self.src.boiler_control = devices[0]

            elif self.payload["device_class"] == ATTR_DHW_SENSOR:
                self.src.get_zone("FA")._set_sensor(devices[0])

            elif self.payload["device_class"] == ATTR_DHW_VALVE:
                self.src.get_zone("FA").hotwater_valve = devices[0]

            elif self.payload["device_class"] == ATTR_DHW_VALVE_HTG:
                self.src.get_zone("FA").heating_valve = devices[0]

        # # Eavesdropping (below) is used when discovery (above) is not an option
        # # TODO: needs work, e.g. RP/1F41 (excl. null_rp)
        # elif self.code in ("10A0", "1F41"):
        #     if isinstance(self.dst, Device) and self.dst.is_controller:
        #         self.dst.get_zone("FA")
        #     else:
        #         self.src.get_zone("FA")

        # # TODO: also process ufh_idx (but never domain_id)
        # elif isinstance(self._payload, dict):
        #     # TODO: only creating zones from arrays, presently, but could do so here
        #     if self._payload.get("zone_idx"):  # TODO: parent_zone too?
        #         if self.src.is_controller:
        #             self.src.get_zone(self._payload["zone_idx"])
        #         else:
        #             self.dst.get_zone(self._payload["zone_idx"])

        elif isinstance(self._payload, list):
            if self.code in ("000A", "2309", "30C9"):  # the sync_cycle pkts
                [self.src.get_zone(d["zone_idx"]) for d in self.payload]
            # elif self.code in ("22C9", "3150"):  # TODO: UFH zone
            #     pass

        # else:  # should never get here
        #     raise TypeError

    @exception_handler
    def update_entities(self, prev) -> None:  # TODO: needs work
        """Update the state of entities (devices, zones, ufh_zones)."""

        if not self.is_valid:  # requires self.payload
            return

        # HACK: merge 000A fragments
        # TODO: do here, or in ctl._proc_msg() and/or system._proc_msg()
        if re.search("I.* 01.* 000A ", self._pkt):  # HACK: and dtm < 3 secs
            # TODO: an edge case here: >2 000A packets in a row
            if prev is not None and re.search("I.* 01.* 000A ", prev._pkt):
                self._payload = prev.payload + self.payload  # merge frags, and process

        # some devices aren't created if they're filtered out
        if self.src.id not in self._gwy.device_by_id:
            return

        # some empty payloads may still be useful (e.g. RQ/3EF1/{})
        self._gwy.device_by_id[self.src.id]._proc_msg(self)

        # if payload is {} (empty dict; lists shouldn't ever be empty)
        if not self.payload:
            return

        # try to find the boiler relay, dhw sensor
        for evo in self._gwy.systems:
            if self.src.controller == evo.id:  # TODO: check!
                evo._proc_msg(self, prev)  # TODO: WIP
                if self.src.controller is not None:
                    break
            if self.src.id == evo.id:  # TODO: check!
                if self.code in ("10A0", "1260", "1F41") and evo._dhw is not None:
                    evo._dhw._proc_msg(self)

        # lists only useful to devices (c.f. 000C)
        if isinstance(self.payload, dict) and "zone_idx" in self.payload:
            evo = self.src.controller  # TODO: needs device?
            # if evo is None and isinstance(self.dst, Device):
            #     evo = self.dst._evo

            if evo is not None and self.payload["zone_idx"] in evo.zone_by_idx:
                evo.zone_by_idx[self.payload["zone_idx"]]._proc_msg(self)

            # elif self.payload.get("ufh_idx") in ...:  # TODO: is this needed?
            #     pass
