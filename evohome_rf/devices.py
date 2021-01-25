#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser."""

from abc import ABCMeta, abstractmethod
import asyncio
import logging
from typing import Any, Dict, Optional

from .command import Command, Priority
from .const import (
    _dev_mode_,
    DEVICE_HAS_BATTERY,
    DEVICE_TABLE,
    DEVICE_TYPES,
    DISCOVER_SCHEMA,
    DISCOVER_PARAMS,
    DISCOVER_STATUS,
    DISCOVER_ALL,
    DOMAIN_TYPE_MAP,
)
from .exceptions import CorruptStateError
from .helpers import slugify_string as slugify, dev_id_to_hex
from .ramses import HINTS_DEVICE_TYPES as HINTS_DEVICES

DEV_MODE = _dev_mode_

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def _payload(msg, key=None) -> Optional[Any]:
    if msg and not msg.is_expired:
        if key:
            return msg.payload.get(key)
        return {k: v for k, v in msg.payload.items() if k[:1] != "_"}


class Entity:
    """The Device/Zone base class."""

    def __init__(self, gwy) -> None:
        self._gwy = gwy

        self.id = None

        self._msgs = {}

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        pass

    def _get_msg_value(self, code, key=None) -> dict:
        if self._msgs.get(code):
            if isinstance(self._msgs[code].payload, list):
                return self._msgs[code].payload

            if key is not None:
                return self._msgs[code].payload.get(key)

            result = self._msgs[code].payload
            return {
                k: v
                for k, v in result.items()
                if k[:1] != "_" and k not in ("domain_id", "zone_idx")
            }

    def _handle_msg(self, msg) -> None:  # TODO: beware, this is a mess
        if "domain_id" in msg.payload:  # isinstance(msg.payload, dict) and
            self._domain[msg.payload["domain_id"]] = {msg.code: msg}  # 01/02/23
            return

        if msg.verb == " W":
            if msg.code in self._msgs and self._msgs[msg.code].verb != msg.verb:
                return

        if msg.verb == "RQ":  # and msg.payload:
            if msg.code in self._msgs and self._msgs[msg.code].verb != msg.verb:
                return

        # may get an RQ/W initially, but RP/I will override
        # self._msgs.update({msg.code: msg})
        self._msgs[msg.code] = msg

    def _send_cmd(self, code, dest, payload, **kwargs) -> None:
        self._msgs.pop(code, None)  # remove the old one, so we can tell if RP'd rcvd

        cmd = Command(kwargs.pop("verb", "RQ"), dest, code, payload, **kwargs)
        try:  # TODO: convert create_task to run_coroutine_threadsafe
            asyncio.create_task(
                self._gwy.msg_protocol.send_data(cmd),
            )
        except RuntimeError:
            asyncio.run_coroutine_threadsafe(
                self._gwy.msg_protocol.send_data(cmd), self._gwy._loop
            )

    @property
    def _pkt_codes(self) -> list:
        return list(self._msgs.keys())

    @property
    def controller(self):  # -> Optional[Controller]:
        """Return the entity's controller, if known."""

        return self._ctl  # TODO: if the controller is not known, try to find it?


class DeviceBase(Entity, metaclass=ABCMeta):
    """The Device base class."""

    def __init__(self, gwy, dev_addr, ctl=None, domain_id=None) -> None:
        _LOGGER.debug("Creating a Device: %s (%s)", dev_addr.id, self.__class__)
        super().__init__(gwy)

        self.id = dev_addr.id
        gwy.devices.append(self)
        gwy.device_by_id[self.id] = self

        self._ctl = None
        if ctl:
            self._set_ctl(ctl)
        self._domain_id = domain_id

        self.addr = dev_addr
        self.hex_id = dev_id_to_hex(dev_addr.id)
        self.type = dev_addr.type

        if self.type in DEVICE_TABLE:
            self._has_battery = DEVICE_TABLE[self.addr.type].get("has_battery")
            self._is_actuator = DEVICE_TABLE[self.addr.type].get("is_actuator")
            self._is_sensor = DEVICE_TABLE[self.addr.type].get("is_sensor")
        else:
            self._has_battery = None
            self._is_actuator = None
            self._is_sensor = None

        self._zone = None
        self._domain = {}

    def __repr__(self) -> str:
        return f"{self.id} ({DEVICE_TYPES.get(self.type)})"

    def __str__(self) -> str:
        return f"{self.id} ({DEVICE_TYPES.get(self.id[:2])})"

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # sometimes, battery-powered devices do respond to an RQ (e.g. bind mode)
        # super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            # self._send_cmd("1FC9", retries=0)
            if self.type not in DEVICE_HAS_BATTERY and self.type not in ("13",):
                self._send_cmd("10E0", retries=0)  # TODO: use device hints

        if discover_flag & DISCOVER_PARAMS:
            pass

        if discover_flag & DISCOVER_STATUS:
            # self._send_cmd("0016", payload="0000", retries=0)
            pass

    def _send_cmd(self, code, **kwargs) -> None:
        dest = kwargs.pop("dest_addr", self.id)
        payload = kwargs.pop("payload", "00")
        super()._send_cmd(code, dest, payload, **kwargs)

    def _set_ctl(self, ctl) -> None:  # self._ctl
        """Set the device's parent controller, after validating it."""

        if self._ctl is None:
            _LOGGER.debug("Setting controller for %s to %s", self, ctl)

            # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5  # has been seen
            if not isinstance(ctl, Controller) and not ctl.is_controller:
                raise TypeError(f"Device {ctl} is not a controller")

            self._ctl = ctl
            self._ctl.devices.append(self)
            self._ctl.device_by_id[self.id] = self

        elif self._ctl is not ctl:
            raise CorruptStateError(
                f"{self} has changed controller: {self._ctl.id} to {ctl.id}"
            )

    @property
    @abstractmethod
    def schema(self) -> dict:
        """Return the fixed attributes of the device (e.g. TODO)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def params(self) -> dict:
        """Return the configuration of the device (e.g. TODO)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def status(self) -> dict:
        """Return the current state of the device (e.g. TODO)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def zone(self) -> Optional[Entity]:  # should be: Optional[Zone]
        """Return parent zone of the device, if known."""
        raise NotImplementedError

    # @abstractmethod
    # def _set_zone(self, zone: Entity) -> None:  # should be: zone: Zone
    #     """Set the parent zone of the device."""


class Actuator:  # 3EF0, 3EF1
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._actuator_cycle = None
        self._actuator_enabled = None
        self._actuator_state = None

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "3EF0" and msg.verb == " I":  # NOT "RP", TODO: why????
            self._actuator_state = msg
            self._actuator_enabled = msg

            qos = {"priority": Priority.LOW, "retries": 1}
            for code in ("0008", "3EF1"):
                self._send_cmd(code, qos=qos)

        elif msg.code == "3EF1" and msg.verb == "RP":
            self._actuator_cycle = msg
            self._actuator_enabled = msg

    @property
    def actuator_cycle(self) -> Optional[dict]:  # 3EF1
        return _payload(self._actuator_cycle)

    @property
    def actuator_state(self) -> Optional[dict]:  # 3EF0
        return _payload(self._actuator_state)

    @property
    def enabled(self) -> Optional[bool]:  # 3EF0, 3EF1
        return _payload(self._actuator_enabled, "actuator_enabled")

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "actuator_cycle": self.actuator_cycle,
            "actuator_state": self.actuator_state,
            "enabled": self.enabled,
        }


class BatteryState:  # 1060
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._battery_state = None

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "1060" and msg.verb == " I":
            self._battery_state = msg

    @property
    def battery_low(self) -> Optional[bool]:  # 1060
        return _payload(self._battery_state, "battery_low")

    @property
    def battery_state(self) -> Optional[dict]:  # 1060
        return _payload(self._battery_state)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "battery_state": self.battery_state,
        }


class Setpoint:  # 2309
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._setpoint = None

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "2309" and msg.verb in (" I", " W"):
            self._setpoint = msg

    @property
    def setpoint(self) -> Optional[float]:  # 2309
        return _payload(self._setpoint, "setpoint")

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "setpoint": self.setpoint,
        }


class Temperature:  # 30C9
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._temp = None

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "30C9" and msg.verb in (" I", "RP"):
            self._temp = msg

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        return _payload(self._temp, "temperature")

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "temperature": self.temperature,
        }


class DeviceInfo:  # 10E0
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._device_info = None

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "10E0" and msg.verb in (" I", "RP"):
            self._device_info = msg

    @property
    def device_info(self) -> Optional[dict]:  # 10E0
        return _payload(self._device_info)

    @property
    def schema(self) -> dict:
        return {
            **super().schema,
            "device_info": self.device_info,
        }


class Device(DeviceInfo, DeviceBase):
    """The Device base class - also used for unknown device types."""

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code in ("0016", "1FC9"):
            pass

        elif self.type not in HINTS_DEVICES:
            assert False, f"Unknown device type: {self.id}"

        elif msg.code not in HINTS_DEVICES[self.type]:
            assert (
                HINTS_DEVICES[self.type] == {}
            ), f"Unknown code for {self.id}: {msg.verb}/{msg.code}"

        elif msg.verb not in HINTS_DEVICES[self.type][msg.code]:
            assert (
                HINTS_DEVICES[self.type][msg.code] == []
            ), f"Unknown verb for {self.id}: {msg.verb}/{msg.code}"

        # TODO: status updates always, but...
        # TODO: schema updates only if eavesdropping is enabled.
        # if self._ctl is not None and "parent_idx" in msg.payload:
        #     self._set_zone(self._evo._get_zone(msg.payload["parent_idx"]))

    def _set_parent(self, parent, domain=None) -> None:
        """Set the device's parent zone, after validating it."""

        # NOTE: these imports are here to prevent circular references
        from .systems import System
        from .zones import DhwZone, Zone

        if isinstance(parent, Zone):
            if domain and domain != parent.idx:
                raise TypeError(f"domain can't be: {domain} (must be {parent.idx})")

            self._set_ctl(parent._ctl)
            self._domain_id = parent.idx

        elif isinstance(parent, DhwZone):
            if domain and domain not in ("F9", "FA"):
                raise TypeError(f"domain can't be: {domain}")

            self._set_ctl(parent._ctl)
            self._domain_id = domain

        elif isinstance(parent, System):
            if domain not in ("F9", "FA", "FC", "HW"):
                raise TypeError(f"domain can't be: {domain}")

            self._set_ctl(parent._ctl)
            self._domain_id = domain

        else:
            raise TypeError(f"paren can't be: {parent}")

        if self._zone is not None:
            if self._zone is not parent:
                raise CorruptStateError(
                    f"{self} shouldn't change parent: {self._zone} to {parent}"
                )
            self._zone = parent

    @property
    def zone(self) -> Optional[Entity]:  # should be: Optional[Zone]
        """Return the device's parent zone, if known."""

        return self._zone

    def _set_zone(self, zone: Entity) -> None:  # self._zone
        """Set the device's parent zone, after validating it.

        There are three possible sources for the parent zone of a device:
        1. a 000C packet (from their controller) for actuators only
        2. a message.payload["zone_idx"]
        3. the sensor-matching algorithm for zone sensors only

        All three will set device.zone to this zone.

        Devices don't have parents, rather: Zones have children; a mis-configured
        system could have a device as a child of two domains.
        """

        if not isinstance(zone, Entity):  # should be: zone, Zone)
            raise TypeError(f"Not a zone: {zone}")

        if self._zone is not None:
            if self._zone is not zone:
                raise CorruptStateError(
                    f"Device {self} has a mismatched parent zone: "
                    f"old={self._zone}, new={zone}"
                )
            return

        self._domain_id = zone.idx
        self._zone = zone
        if self._domain_id == "FA":
            # if isinstance(self, DhwSensor):
            #     self._sensor = self
            # else:
            #     self._dhw_valve = self
            pass

        elif self not in self._zone.devices:
            self._zone.devices.append(self)
            self._zone.device_by_id[self.id] = self
        _LOGGER.debug("Device %s: parent zone now set to %s", self.id, self._zone)

    @property
    def description(self) -> Optional[str]:
        return DEVICE_TABLE[self.type]["name"] if self.type in DEVICE_TABLE else None

    @property
    def has_battery(self) -> Optional[bool]:  # 1060
        """Return True if a device is battery powered (excludes battery-backup)."""

        if self._has_battery is not None:
            return self._has_battery

        if "1060" in self._msgs:
            self._has_battery = True

        return self._has_battery

    @property
    def is_controller(self) -> Optional[bool]:  # 1F09
        if self._ctl is self:
            return True
        # if isinstance(self, Controller):
        #     return True
        # if self.type in ("01", "23"):
        #     return True
        # if "1F09" in self._msgs:  # TODO: needs to add msg to instaition
        #     return self._msgs["1F09"].verb == " I"
        # if "31D9" in self._msgs:  # TODO: needs to add msg to instaition
        #     return self._msgs["31D9"].verb == " I"
        return False

    @property
    def _is_present(self) -> bool:
        return any([m.src.id == self.id for m in self._msgs.values()])

    @property
    def schema(self):
        return {}

    @property
    def params(self):
        return {}

    @property
    def status(self):
        return {}


# 01:
class Controller(Device):
    """The Controller base class."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._ctl = self  # or args[1]
        self._domain_id = "FF"
        self._evo = None

        self.devices = list()  # [self]
        self.device_by_id = dict()  # {self.id: self}


# 02: "10E0", "3150";; "0008", "22C9", "22D0"
class UfhController(Device):
    """The UFC class, the HCE80 that controls the UFH zones."""

    # 12:27:24.398 067  I --- 02:000921 --:------ 01:191718 3150 002 0360
    # 12:27:24.546 068  I --- 02:000921 --:------ 01:191718 3150 002 065A
    # 12:27:24.693 067  I --- 02:000921 --:------ 01:191718 3150 002 045C
    # 12:27:24.824 059  I --- 01:191718 --:------ 01:191718 3150 002 FC5C
    # 12:27:24.857 067  I --- 02:000921 --:------ 02:000921 3150 006 0060015A025C

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._circuits = {}
        self._setpoints = None

        self.devices = list()  # [self]
        self.device_by_id = dict()  # {self.id: self}

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            [  # 000C: used to find evo zone for each configured channel
                self._send_cmd("000C", payload=f"{idx:02X}{dev_type}")
                for dev_type in ("09",)  # CODE_000C_DEVICE_TYPE, also ("00", "04")
                # for dev_type in CODE_000C_DEVICE_TYPE
                for idx in range(8)  # for each possible UFH channel
            ]

        if discover_flag & DISCOVER_PARAMS:
            pass

        if discover_flag & DISCOVER_STATUS:
            pass

        # [  # 3150: no answer
        #     self._send_cmd("3150", payload=f"{zone_idx:02X}")for zone_idx in range(8)
        # ]

        # [  # 22C9: no answer
        #     self._send_cmd("22C9", payload=f"{payload}")
        #     for payload in ("00", "0000", "01", "0100")
        # ]

        # [  # 22D0: dunno, always: {'unknown': '000002'}
        #     self._send_cmd("22D0", payload=f"{payload}")
        #     for payload in ("00", "0000", "00000002")
        # ]

        # [  # 0005: shows which channels are active - ?no use? (see above)
        #     self._send_cmd("0005", payload=f"00{zone_type}")
        #     # for zone_type in ("09",)  # CODE_0005_ZONE_TYPE, also ("00", "04", "0F")
        #     for zone_type in CODE_0005_ZONE_TYPE
        # ]

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "000C":
            if "ufh_idx" in msg.payload and msg.payload["zone_id"] is not None:
                self._circuits[msg.payload["ufh_idx"]] = {
                    "zone_idx": msg.payload["zone_id"]
                }

        # "0008|FA/FC", "22C9|array", "22D0|none", "3150|ZZ/array(/FC?)"

        # if msg.code in ("22C9",) and not isinstance(msg.payload, list):
        #     pass
        # else:
        #     assert False, "Unknown packet code"

    @property
    def setpoints(self) -> Optional[Dict]:  # 22C9
        return _payload(self._setpoints)

    @property  # id, type
    def schema(self) -> dict:
        return {
            **super().schema,
            "ufh_circuits": self._circuits,
        }

    # @property  # setpoint, config, mode (not schedule)
    # def params(self) -> dict:

    #     return {
    #        **super().params,
    #     }

    # @property
    # def status(self) -> dict:
    #     return {
    #         **super().status,
    #     }


# 07: "1260" "10A0" (and "1060")
class DhwSensor(BatteryState, Device):
    """The DHW class, such as a CS92."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._domain_id = "FA"

        self._dhw_params = None
        self._temp = None

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "10A0" and msg.verb == "RQ":
            self._dhw_params = msg

        elif msg.code in "1260" and msg.verb == " I":
            self._temp = msg

    # @property
    # def dhw_params(self) -> Optional[dict]:
    #     return _payload(self._dhw_params)

    @property
    def temperature(self) -> Optional[float]:
        return _payload(self._temp, "temperature")

    # @property
    # def params(self) -> dict:
    #     return {
    #         **super().params,
    #         "dhw_params": self.dhw_params,
    #     }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "temperature": self.temperature,
        }


# 10: "10E0", "3EF0", "3150";; "22D9", "3220" ("1FD4"), TODO: 3220
class OtbGateway(Actuator, Device):
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._domain_id = "FC"

        self._boiler_setpoint = None
        self._modulation_level = None
        self._opentherm_msg = {}

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # 086 RQ --- 01:123456 63:262143 --:------ 3220 005 0000050000
        # 049 RP --- 63:262143 01:123456 --:------ 3220 005 00F0050000
        # 092 RQ --- 01:123456 63:262143 --:------ 3220 005 0000110000
        # 049 RP --- 63:262143 01:123456 --:------ 3220 005 00C0110000
        # 082 RQ --- 01:123456 63:262143 --:------ 3220 005 0000120000
        # 076 RQ --- 01:123456 63:262143 --:------ 3220 005 0000120000
        # 049 RP --- 63:262143 01:123456 --:------ 3220 005 0040120166
        # 075 RQ --- 01:123456 63:262143 --:------ 3220 005 0080130000
        # 049 RP --- 63:262143 01:123456 --:------ 3220 005 0070130000
        # 074 RQ --- 01:123456 63:262143 --:------ 3220 005 0080190000
        # 049 RP --- 63:262143 01:123456 --:------ 3220 005 00401929E6
        # 072 RQ --- 01:123456 63:262143 --:------ 3220 005 00801A0000
        # 048 RP --- 63:262143 01:123456 --:------ 3220 005 00401A3033
        # 073 RQ --- 01:123456 63:262143 --:------ 3220 005 00801C0000
        # 049 RP --- 63:262143 01:123456 --:------ 3220 005 00401C29B3
        # 074 RQ --- 01:123456 63:262143 --:------ 3220 005 0080730000
        # 048 RP --- 63:262143 01:123456 --:------ 3220 005 00407300CC
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            # TODO: From OT v2.2: version numbers
            for msg_id in range(124, 128):
                self._send_cmd("3220", payload=f"0000{msg_id:02X}0000")

        if discover_flag & DISCOVER_PARAMS:
            pass

        if discover_flag & DISCOVER_STATUS:  # TODO: these need to be periodic
            # From OT v2.2, these are mandatory: 00, 01, 03, 0E, 11, 19
            # From evohome:
            # 05 - Fault flags & OEM fault code
            # 11 - Relative modulation level
            # 12 - Central heating water pressure
            # 13 - DHW flow rate (litres/minute)
            # 19 - Boiler water temperature
            # 1A - DHW temperature
            for msg_id in ("0005", "0011", "0012", "8013", "8019", "801A"):
                self._send_cmd("3220", payload=f"00{msg_id}0000")
            # 1C - Return water temperature
            # 73 - OEM diagnostic code
            for msg_id in ("801C", "8073"):
                self._send_cmd("3220", payload=f"00{msg_id}0000")

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "22D9" and msg.verb == "RP":
            self._boiler_setpoint = msg

        elif msg.code == "3220" and msg.verb == "RP":  # TODO: what about I/W (or RQ)
            self._opentherm_msg[msg.payload["id"]] = msg  # TODO: these need to expire

        elif msg.code == "3EF0" and msg.verb == "RP":
            self._modulation_level = msg

        elif msg.code == "3EF1" and msg.verb == "RP":
            self._modulation_level = msg

    @property
    def boiler_temp(self) -> Optional[float]:  # 3220
        if "19" in self._opentherm_msg:
            return self._opentherm_msg["19"].payload["value"]

    @property
    def ch_pressure(self) -> Optional[float]:  # 3220
        if "12" in self._opentherm_msg:
            return self._opentherm_msg["12"].payload["value"]

    @property
    def dhw_flow_rate(self) -> Optional[float]:  # 3220
        if "13" in self._opentherm_msg:
            return self._opentherm_msg["13"].payload["value"]

    @property
    def dwh_temp(self) -> Optional[float]:  # 3220
        if "1A" in self._opentherm_msg:
            return self._opentherm_msg["1A"].payload["value"]

    @property
    def rel_modulation_level(self) -> Optional[float]:  # 3220
        if "11" in self._opentherm_msg:
            return self._opentherm_msg["11"].payload["value"]

    @property
    def return_cv_temp(self) -> Optional[float]:  # 3220
        if "1C" in self._opentherm_msg:
            return self._opentherm_msg["1C"].payload["value"]

    @property
    def boiler_setpoint(self) -> Optional[float]:  # 22D9
        return _payload(self._boiler_setpoint, "boiler_setpoint")

    @property
    def modulation_level(self) -> Optional[float]:  # 3EF0/3EF1
        return _payload(self._modulation_level, "modulation_level")

    @property
    def ot_status(self) -> dict:
        return {
            slugify(self._opentherm_msg[msg_id].payload["msg_name"]): (
                self._opentherm_msg[msg_id].payload["value"]
            )
            for msg_id in ("11", "12", "13", "19", "1A", "1C")
            if msg_id in self._opentherm_msg
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "boiler_setpoint": self.boiler_setpoint,
            "modulation_level": self.modulation_level,  # TODO: keep? (is duplicate)
            "boiler_temp": self.boiler_temp,
            "ch_pressure": self.ch_pressure,
            "dhw_flow_rate": self.dhw_flow_rate,
            "dwh_temp": self.dwh_temp,
            "rel_modulation_level": self.rel_modulation_level,
            "return_cv_temp": self.return_cv_temp,
        }


# 03/12/22/34: 1060/2309/30C9;; (03/22: 0008/0009/3EF1, 2349?) (34: 000A/10E0/3120)
class Thermostat(BatteryState, Setpoint, Temperature, Device):
    """The THM/STA class, such as a TR87RF."""

    def _handle_msg(self, msg) -> bool:  # TODO: needs checking for false +ves
        super()._handle_msg(msg)


# 13: 0008/1100/3B00/3EF0/3EF1
class BdrSwitch(Actuator, Device):
    """The BDR class, such as a BDR91.

    BDR91s can be used in six disctinct modes, including:
    - x2 boiler controller (FC/TPI): either traditional, or newer heat pump-aware
    - x1 electric heat zones (0x/ELE)
    - x1 zone valve zones (0x/VAL)
    - x2 DHW thingys (F9/DHW, FA/DHW)
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._relay_demand = None
        self._tpi_params = None

        self._is_tpi = None

        # if kwargs.get("domain_id") == "FC":  # TODO: F9/FA/FC, zone_idx
        #     self._ctl._set_htg_control(self)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        """The BDRs fail(?) to respond to RQs for: 3B00, 3EF0, 0009.

        They all seem to respond to (haven't checked a zone-valve zone):
        - 0008: varies on/off
        - 1100
        - 3EF1: has sub-domains?
        """

        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            pass

        if discover_flag & DISCOVER_PARAMS:
            self._send_cmd("1100")  # heater_relay wont RP to RQ/3B00?

        if discover_flag & DISCOVER_STATUS:
            for code in ("0008", "3EF1"):
                self._send_cmd(code)

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "0008" and msg.verb == "RP":
            self._relay_demand = msg

        elif msg.code == "1100" and msg.verb in (" I", "RP"):
            self._tpi_params = msg

        elif msg.code == "3B00" and msg.verb == " I":
            pass  # only a heater_relay will I/3B00
            # for code in ("0008", "3EF1"):
            #     self._send_cmd(code, delay=1)

    @property
    def role(self) -> Optional[str]:
        """Return the role of the BDR91A (there are six possibilities)."""

        if self._domain_id in DOMAIN_TYPE_MAP:
            return DOMAIN_TYPE_MAP[self._domain_id]
        elif self._zone:
            return self._zone.heating_type

    @property
    def _role(self) -> Optional[str]:  # TODO: XXX
        """Return the role of the BDR91A (there are six possibilities)."""

        if self._is_tpi is not None:
            return self._is_tpi

        elif "1FC9" in self._msgs and self._msgs["1FC9"].verb == "RP":
            if "3B00" in self._msgs["1FC9"].raw_payload:
                self._is_tpi = True

        elif "3B00" in self._msgs and self._msgs["3B00"].verb == " I":
            self._is_tpi = True

        if self._is_tpi:
            self._domain_id = "FC"  # TODO: check is None first
            self.ctl._set_htg_control(self)

        return self._is_tpi

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return _payload(self._relay_demand, "relay_demand")

    @property
    def tpi_params_wip(self) -> Optional[dict]:  # 1100
        return _payload(self._tpi_params)

    @property
    def params(self) -> dict:
        return {
            **super().params,
            "_tpi_params": self.tpi_params_wip,
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "relay_demand": self.relay_demand,
        }


class TrvActuator(BatteryState, Setpoint, Temperature, Device):
    """The TRV class, such as a HR92."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._heat_demand = None
        self._window_state = None

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "12B0" and msg.verb == " I":
            self._window_state = msg

        elif msg.code == "3150" and msg.verb == " I":
            self._heat_demand = msg

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return _payload(self._heat_demand, "heat_demand")

    @property
    def window_state(self) -> Optional[bool]:  # 12B0
        return _payload(self._window_state, "window_open")

    @property
    def enabled(self) -> Optional[bool]:  # 3EF0, 3EF1
        if self.heat_demand is not None:
            return bool(self.heat_demand)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "enabled": self.enabled,
            "heat_demand": self.heat_demand,
            "window_state": self.window_state,
        }


DEVICE_CLASSES = {
    "00": TrvActuator,
    "01": Controller,
    "02": UfhController,
    "03": Thermostat,
    "04": TrvActuator,
    "07": DhwSensor,
    "10": OtbGateway,
    "12": Thermostat,
    "13": BdrSwitch,
    "22": Thermostat,
    "23": Controller,
    "34": Thermostat,
}
