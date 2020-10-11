#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""The evohome-compatible devices."""

from abc import ABCMeta, abstractmethod
from datetime import datetime as dt, timedelta
import logging
from typing import Any, Optional

from .command import Command
from .const import (
    __dev_mode__,
    # CODE_SCHEMA,
    # CODE_0005_ZONE_TYPE,
    # CODE_000C_DEVICE_TYPE,
    DEVICE_HAS_BATTERY,
    DEVICE_LOOKUP,
    DEVICE_TABLE,
    DEVICE_TYPES,
    DISCOVER_SCHEMA,
    DISCOVER_PARAMS,
    DISCOVER_STATUS,
    DISCOVER_ALL,
)
from .exceptions import CorruptStateError
from .logger import dt_now

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


def dev_hex_to_id(device_hex: str, friendly_id=False) -> str:
    """Convert (say) '06368E' to '01:145038' (or 'CTL:145038')."""
    if device_hex == "FFFFFE":  # aka '63:262142'
        return ">null dev<" if friendly_id else "63:262142"
    if not device_hex.strip():  # aka '--:------'
        return f"{'':10}" if friendly_id else "--:------"
    _tmp = int(device_hex, 16)
    dev_type = f"{(_tmp & 0xFC0000) >> 18:02d}"
    if friendly_id:
        dev_type = DEVICE_TYPES.get(dev_type, f"{dev_type:<3}")
    return f"{dev_type}:{_tmp & 0x03FFFF:06d}"


def dev_id_to_hex(device_id: str) -> str:
    """Convert (say) '01:145038' (or 'CTL:145038') to '06368E'."""
    if len(device_id) == 9:  # e.g. '01:123456'
        dev_type = device_id[:2]
    else:  # len(device_id) == 10, e.g. 'CTL:123456', or ' 63:262142'
        dev_type = DEVICE_LOOKUP.get(device_id[:3], device_id[1:3])
    return f"{(int(dev_type) << 18) + int(device_id[-6:]):0>6X}"  # sans preceding 0x


def _dtm(value) -> str:
    """Convert a datetime to a hex string."""

    def dtm_to_hex(tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, *args):
        return f"{tm_min:02X}{tm_hour:02X}{tm_mday:02X}{tm_mon:02X}{tm_year:04X}"

    if value is None:
        return "FF" * 6

    if isinstance(value, str):
        try:
            value = dt.fromisoformat(value)
        except ValueError:
            raise ValueError("Invalid datetime isoformat string")
    elif not isinstance(value, dt):
        raise TypeError("Invalid datetime object")

    if value < dt_now() + timedelta(minutes=1):
        raise ValueError("Invalid datetime")

    return dtm_to_hex(*value.timetuple())


class Entity:
    """The Device/Zone base class."""

    def __init__(self, gateway, controller=None) -> None:
        self._gwy = gateway
        self._que = gateway.cmd_que
        self._ctl = controller

        self.id = None

        self._msgs = {}
        self._known_msg = None

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

    def _proc_msg(self, msg) -> None:
        self._known_msg = msg.code in ("0016", "1FC9")  # TODO: push to zone?

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
        self._msgs.pop(code, None)  # remove the old one, so we can tell if RP'd
        verb = kwargs.pop("verb", "RQ")
        self._que.put_nowait(Command(verb, dest, code, payload, **kwargs))

    @property
    def _pkt_codes(self) -> list:
        return list(self._msgs.keys())

    @property
    def controller(self):  # -> Optional[Controller]:
        """Return the id of the entity's controller, if known."""

        return self._ctl  # TODO: if the controller is not known, try to find it?

    @controller.setter
    def controller(self, controller) -> None:
        """Set the device's parent controller, after validating it."""

        if not isinstance(controller, Controller) and not controller.is_controller:
            raise TypeError(f"Not a controller: {controller}")

        if self._ctl is not None:  # zones have this set at instantiation
            if self._ctl is not controller:
                # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5
                raise CorruptStateError(
                    f"Device {self} has a mismatched controller: "
                    f"old={self._ctl.id}, new={controller.id}",
                )
            return

        self._ctl = controller
        self._ctl.devices.append(self)
        self._ctl.device_by_id[self.id] = self
        _LOGGER.debug("Device %s: controller now set to %s", self.id, self._ctl.id)


class DeviceBase(Entity, metaclass=ABCMeta):
    """The Device base class."""

    def __init__(self, gateway, device_addr, controller=None, domain_id=None) -> None:
        _LOGGER.debug("Creating a Device: %s %s", device_addr.id, self.__class__)
        super().__init__(gateway, controller=controller)
        assert device_addr.id not in gateway.device_by_id, "Duplicate device address"

        self.id = device_addr.id
        self.hex_id = dev_id_to_hex(device_addr.id)

        gateway.devices.append(self)
        gateway.device_by_id[device_addr.id] = self

        if controller is not None:  # here, assumed to be valid
            controller.devices.append(self)
            controller.device_by_id[self.id] = self

        self.addr = device_addr
        self.type = device_addr.type

        if self.addr.type in DEVICE_TABLE:
            self._has_battery = DEVICE_TABLE[self.addr.type].get("has_battery")
            self._is_actuator = DEVICE_TABLE[self.addr.type].get("is_actuator")
            self._is_sensor = DEVICE_TABLE[self.addr.type].get("is_sensor")
        else:
            self._has_battery = None
            self._is_actuator = None
            self._is_sensor = None

        self._zone = None
        self._domain = {}
        self._domain_id = domain_id

        attrs = gateway.known_devices.get(device_addr.id)
        self._friendly_name = attrs.get("friendly_name") if attrs else None
        self._ignored = attrs.get("ignored", False) if attrs else False

        self._discover()  # should be last thing in __init__()

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return f"{self.id} ({DEVICE_TYPES.get(self.type)})"

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""
        return f"{self.id} ({DEVICE_TYPES.get(self.type)})"

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # sometimes, battery-powered devices do respond to an RQ (e.g. bind mode)

        if self._gwy.config["disable_discovery"]:
            return
        # super()._discover()

        if discover_flag & DISCOVER_SCHEMA:
            self._send_cmd("1FC9", retry_limit=0)
            if self.type not in DEVICE_HAS_BATTERY:
                self._send_cmd("10E0", retry_limit=0)

        if discover_flag & DISCOVER_PARAMS:
            pass

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("0016", payload="0000", retry_limit=0)

    def _send_cmd(self, code, **kwargs) -> None:
        dest = kwargs.pop("dest_addr", self.id)
        payload = kwargs.pop("payload", "00")
        super()._send_cmd(code, dest, payload, **kwargs)

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
    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._actuator_enabled = None
        self._actuator_state = None

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        if self._gwy.config["disable_discovery"]:
            return
        super()._discover()

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("3EF1")

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if msg.code == "3EF0" and msg.verb == " I":
            self._actuator_enabled = msg.payload["actuator_enabled"]
            self._known_msg = True

        elif msg.code == "3EF1" and msg.verb == "RP":
            self._actuator_enabled = msg.payload["actuator_enabled"]
            self._actuator_state = msg.payload
            self._known_msg = True

    @property
    def actuator_enabled(self) -> Optional[bool]:  # 3EF0, TODO: does 10: RP/3EF1?
        return self._actuator_enabled

    @property
    def actuator_state(self) -> Optional[float]:  # 3EF1, TODO: not all actuators
        return self._actuator_state

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "actuator_enabled": self.actuator_enabled,
            "actuator_state": self.actuator_state,
        }


class BatteryState:  # 1060
    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._battery_state = {}

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if msg.code == "1060" and msg.verb == " I":
            self._battery_state = msg.payload
            self._known_msg = True

    @property
    def battery_state(self) -> dict:  # 1060
        return self._battery_state

    @property
    def status(self) -> dict:
        return {**super().status, "battery_state": self.battery_state}


class HeatDemand:  # 3150
    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._heat_demand = None

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if msg.code == "3150" and msg.verb == " I":
            self._heat_demand = msg.payload["heat_demand"]
            self._known_msg = True

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._heat_demand

    @property
    def status(self) -> dict:
        return {**super().status, "heat_demand": self.heat_demand}


class Setpoint:  # 2309
    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._setpoint = None

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if msg.code == "2309" and msg.verb in (" I", " W"):
            self._setpoint = msg.payload["setpoint"]
            self._known_msg = True

        elif msg.code == "2309" and msg.verb == "RQ":
            self._known_msg = True

    @property
    def setpoint(self) -> Optional[float]:  # 2309
        return self._setpoint

    @property
    def status(self) -> dict:
        return {**super().status, "setpoint": self.setpoint}


class Temperature:  # 30C9
    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._temperature = None

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if msg.code == "30C9" and msg.verb == " I":
            self._temperature = msg.payload["temperature"]
            self._known_msg = True

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        return self._temperature

    @property
    def status(self) -> dict:
        return {**super().status, "temperature": self.temperature}


# ######################################################################################

# 00: used for unknown device types
class Device(DeviceBase):
    """The Device class."""

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        self._known_msg = True
        if msg.code == "0016":
            pass  # self._rf_signal =
        elif msg.code == "10E0":
            pass  # self._hardware_info =
        elif msg.code == "1FC9":
            pass  # self._rf_level =
        else:
            self._known_msg = False

        # TODO: status updates always, but...
        # TODO: schema updates only if eavesdropping is enabled.
        if self._ctl is not None and "parent_idx" in msg.payload:
            self.zone = self._ctl.get_zone(msg.payload["parent_idx"])

    def _set_domain(self, ctl=None, dhw=None, zone=None) -> None:
        """Set the device's parent controller, after validating it."""

        if ctl is not None:
            self._domain_id = "FC"  # boiler_control

        elif dhw is not None:
            self._domain_id = "FA"
            ctl = dhw._ctl

        elif zone is not None:
            self._domain_id = zone.idx
            ctl = zone._ctl

        if self._ctl is None:  # zones have this set at instantiation
            self._ctl = ctl
            self._ctl.devices.append(self)
            self._ctl.device_by_id[self.id] = self
            _LOGGER.debug("Device %s: Controller now set to %s", self.id, self._ctl.id)

        elif self._ctl is not ctl:
            # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5
            raise CorruptStateError(
                f"Device {self} has a mismatched Controller: "
                f"old={self._ctl.id}, new={ctl.id}",
            )

        if dhw is not None:
            self._zone = dhw
            _LOGGER.debug("Device %s: DhwZone now set to %s", self.id, dhw.id)
            return

        elif zone is None:
            return

        if self._zone is None:
            self._zone = zone
            self._zone.devices.append(self)
            self._zone.device_by_id[self.id] = self
            _LOGGER.debug("Device %s: Zone now set to %s", self.id, zone.id)

        elif self._zone is not zone:
            raise CorruptStateError(
                f"Device {self} has a mismatched Zone: "
                f"old={self._zone.idx}, new={zone.idx}",
            )

    @property
    def zone(self) -> Optional[Entity]:  # should be: Optional[Zone]
        """Return the device's parent zone, if known."""

        return self._zone

    @zone.setter
    def zone(self, zone: Entity) -> None:  # should be: zone: Zone
        """Set the device's parent zone, after validating it.

        There are three possible sources for the parent zone of a device:
        1. a 000C packet (from their controller) for actuators only
        2. a message.payload["zone_idx"]
        3. the sensor-matching algorithm fro zone sensors only

        All three will execute a dev.zone = zone (i.e. via this setter).

        Devices don't have parents, rather: Zones have children; a mis-configured
        system could have a device as a child of two domains.
        """

        if not isinstance(zone, Entity):  # should be: zone, Zone)
            raise TypeError(f"Not a zone: {zone}")

        if self._zone is not None:
            if self._zone is not zone:
                raise CorruptStateError(
                    f"Device {self} has a mismatched parent zone: "
                    f"old={self._zone}, new={zone}",
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
    def hardware_info(self) -> Optional[str]:  # 10E0
        return self._get_msg_value("10E0")

    @property
    def has_battery(self) -> Optional[bool]:  # 1060
        """Return True if a device is battery powered.

        Devices with a battery-backup may still be mains-powered.
        """
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
    def params(self):
        return {}

    @property
    def status(self):
        return {}


# 01:
class Controller(Device):
    """The Controller base class, supports child devices and zones only."""

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self.devices = [self]
        self.device_by_id = {self.id: self}

        self._ctl = self
        # self._domain_id = "FF"


# 02: "10E0", "3150";; "0008", "22C9", "22D0"
class UfhController(Device):
    """The UFC class, the HCE80 that controls the UFH zones."""

    # 12:27:24.398 067  I --- 02:000921 --:------ 01:191718 3150 002 0360
    # 12:27:24.546 068  I --- 02:000921 --:------ 01:191718 3150 002 065A
    # 12:27:24.693 067  I --- 02:000921 --:------ 01:191718 3150 002 045C
    # 12:27:24.824 059  I --- 01:191718 --:------ 01:191718 3150 002 FC5C
    # 12:27:24.857 067  I --- 02:000921 --:------ 02:000921 3150 006 0060015A025C

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._circuits = {}

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        if self._gwy.config["disable_discovery"]:
            return
        super()._discover()

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

    def _proc_msg(self, msg) -> None:
        def do_3150_magic() -> None:
            return

        super()._proc_msg(msg)

        #
        if self._known_msg:
            pass
        elif msg.code in (
            "0001",
            "0005",
            "0008",
            "000A",
            "000C",
            "22C9",
            "22D0",
            "2309",
            "3150",
        ):
            pass
        else:
            assert False, f"Unknown packet verb/code for {self.id}"

        # "0008|FA/FC", "22C9|array", "22D0|none", "3150|ZZ/array(/FC?)"

        if msg.code == "000C":
            if "ufh_idx" in msg.payload and msg.payload["zone_id"] is not None:
                self._circuits[msg.payload["ufh_idx"]] = {
                    "zone_idx": msg.payload["zone_id"]
                }

        # if msg.code in ("22C9") and not isinstance(msg.payload, list):
        #     pass
        # else:
        #     assert False, "Unknown packet code"

    @property
    def setpoints(self):  # 22C9
        return self._get_msg_value("22C9")

    @property  # id, type
    def schema(self) -> dict:
        schema = {"ufh_circuits": self._circuits}

        return schema

    # @property  # setpoint, config, mode (not schedule)
    # def params(self) -> dict:
    #     ATTR_NAME = "name"
    #     ATTR_MODE = "mode"
    #     ATTR_CONFIG = "zone_config"

    #     return {
    #         ATTR_NAME: self.name,
    #         ATTR_MODE: self.mode,
    #         ATTR_CONFIG: self.zone_config,
    #     }

    # @property
    # def status(self) -> dict:
    #     return {
    #         ATTR_SETPOINT: self.setpoint,
    #         ATTR_TEMP: self.temperature,
    #     }


# 07: "1060";; "1260" "10A0"
class DhwSensor(BatteryState, Device):
    """The DHW class, such as a CS92."""

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._domain_id = "FA"

        # self._dhw_params = {}
        self._temperature = None

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if self._known_msg:
            pass
        elif msg.verb in ("RP", " W"):
            assert False, f"Unknown packet verb for {self.id}"
        elif msg.code in "1260" and msg.verb == " I":
            self._temperature = msg.payload["temperature"]
        elif msg.verb == "RQ" and msg.code == "10A0":
            self._dhw_params = msg.payload
        else:
            assert False, f"Unknown packet code for {self.id}"

    # @property
    # def dhw_params(self) -> dict:
    #     return self._dhw_params

    @property
    def temperature(self) -> Optional[float]:
        return self._temperature

    # @property
    # def params(self) -> dict:
    #     return {**super().params, "dhw_params": self.dhw_params}

    @property
    def status(self) -> dict:
        return {**super().status, "temperature": self.temperature}


# 10: "10E0", "3EF0", "3150";; "22D9", "3220" ("1FD4"), TODO: 3220
class OtbGateway(Actuator, HeatDemand, Device):
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._domain_id = "FC"

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if self._known_msg:
            pass
        elif msg.verb == "RP" and msg.code in ("22D9", "3220", "3EF0"):
            pass
        elif msg.code in (
            "10A0",
            "1260",
            "1290",
            "1FD4",
            "2349",
        ):  # and msg.verb == " I":
            pass
        else:
            assert False, f"Unknown packet code for {self.id}"

    @property
    def boiler_setpoint(self) -> Optional[Any]:  # 22D9
        return self._get_msg_value("22D9", "boiler_setpoint")

    @property
    def _last_opentherm_msg(self) -> Optional[Any]:  # 3220
        return self._get_msg_value("3220")

    @property
    def status(self) -> dict:
        return {**super().status, "boiler_setpoint": self.boiler_setpoint}


# 03/12/22/34: 1060/2309/30C9;; (03/22: 0008/0009/3EF1, 2349?) (34: 000A/10E0/3120)
class Thermostat(BatteryState, Setpoint, Temperature, Device):
    """The THM/STA class, such as a TR87RF."""

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if self._known_msg:
            pass

        elif self.type == "03":
            if msg.verb == " I" and msg.code in ("0008", "0009", "1100"):
                pass
            else:
                assert False, f"Unknown packet code for {self.id}"

        elif self.type in ("12", "22"):
            if msg.verb == " I" and msg.code in (
                "0008",
                "0009",
                "1030",
                "1100",
                "313F",
            ):
                pass
            elif msg.verb == "RQ" and msg.code in ("000A", "3EF1"):
                pass
            elif msg.verb == " W" and msg.code in ("2349"):
                pass
            else:
                assert False, f"Unknown packet code for {self.id}"

        elif self.type == "34":
            if msg.verb == " I" and msg.code in ("0008", "042F", "10E0", "3120"):
                pass
            elif msg.verb == "RQ" and msg.code in ("000A",):
                pass
            else:
                assert False, f"Unknown packet code for {self.id}"


class BdrSwitch(Actuator, Device):
    """The BDR class, such as a BDR91.

    BDR91s can be used in six disctinct modes, including:
    - x2 boiler controller (FC/TPI): normal, and heat pump (new)
    - x1 electric heat zones (0x/ELE)
    - x1 zone valve zones (0x/VAL)
    - x2 DHW thingys (HW/xxx)
    """

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._relay_demand = None

        self._is_tpi = kwargs.get("domain_id") == "FC"
        if self._is_tpi:
            self._ctl.boiler_control = self

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        """The BDRs fail(?) to respond to RQs for: 3B00, 3EF0, 0009.

        They seem to respond to:
        - 0008: varies on/off
        - 1100
        - 3EF1: has sub-domains?
        """

        if self._gwy.config["disable_discovery"]:
            return
        super()._discover()

        if discover_flag & DISCOVER_SCHEMA:
            pass

        if discover_flag & DISCOVER_PARAMS:
            # self._send_cmd("1100")  # will just repeat the controller config
            pass

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("0008")

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if self._is_tpi is None:
            _ = self.is_tpi

        if self._known_msg:
            pass
        elif msg.code == "0008" and msg.verb == "RP":
            self._relay_demand = msg.payload["relay_demand"]
        elif msg.code == "1100":
            pass
        elif msg.code in "3B00":
            for code in ("0008", "3EF1"):
                self._send_cmd(code, retry_limit=5)
        else:
            assert False, f"Unknown packet verb/code for {self.id}"

    @property
    def is_tpi(self) -> Optional[bool]:  # 3B00
        if self._is_tpi is not None:
            return self._is_tpi

        elif "1FC9" in self._msgs and self._msgs["1FC9"].verb == "RP":
            if "3B00" in self._msgs["1FC9"].raw_payload:
                self._is_tpi = True

        elif "3B00" in self._msgs and self._msgs["3B00"].verb == " I":
            self._is_tpi = True

        if self._is_tpi:
            self._domain_id = "FC"  # TODO: check is None first
            self.ctl.boiler_control = self

        return self._is_tpi

    @property
    def _tpi_params(self) -> dict:  # 1100
        return self._get_msg_value("1100")  # if self.is_tpi else None

    @property
    def relay_demand(self) -> dict:  # 0008
        return self._relay_demand


class TrvActuator(BatteryState, HeatDemand, Setpoint, Temperature, Device):
    """The TRV class, such as a HR92."""

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)
        self._window_state = None

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if self._known_msg:
            pass
        elif msg.verb == "RQ" and msg.code in ("0004", "0100", "1F09", "313F"):
            pass
        elif msg.verb == " W" and msg.code in ("01D0", "01E9"):
            pass
        elif msg.code == "12B0":  # and msg.verb == " I":
            self._window_state = msg.payload["window_open"]
        else:
            assert False, f"Unknown packet verb/code for {self.id}"

    @property
    def window_state(self) -> Optional[bool]:  # 12B0
        return self._window_state

    @property
    def status(self) -> dict:
        return {**super().status, "window_state": self.window_state}


DEVICE_CLASSES = {
    "01": Controller,  # use EvoSystem instead?
    "02": UfhController,
    "03": Thermostat,
    "04": TrvActuator,
    "07": DhwSensor,
    "10": OtbGateway,
    "12": Thermostat,
    "13": BdrSwitch,
    "22": Thermostat,
    "23": Controller,  # a Programmer, use System instead?
    "34": Thermostat,
}
