#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""The evohome-compatible zones."""

from abc import ABCMeta, abstractmethod
import asyncio
import json
import logging
from typing import Optional

from .command import Schedule
from .const import (
    ATTR_DEVICES,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_HEAT_DEMAND,
    ATTR_SETPOINT,
    ATTR_TEMP,
    ATTR_OPEN_WINDOW,
    ATTR_ZONE_SENSOR,
    ATTR_ZONE_TYPE,
    # CODE_000C_DEVICE_TYPE,
    DEVICE_HAS_ZONE_SENSOR,
    DHW_STATE_MAP,
    DISCOVER_SCHEMA,
    DISCOVER_PARAMS,
    DISCOVER_STATUS,
    DISCOVER_ALL,
    ZONE_CLASS_MAP,
    ZONE_TYPE_MAP,
    ZONE_TYPE_SLUGS,
    ZONE_MODE_LOOKUP,
    ZONE_MODE_MAP,
    __dev_mode__,
)
from .devices import Device, Entity, HeatDemand, _dtm
from .exceptions import CorruptStateError

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


def _temp(value) -> str:
    """Return a two's complement Temperature/Setpoint."""
    if value is None:
        return "7FFF"

    try:
        _value = float(value)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid temperature: {value}")

    if _value < 0:
        raise ValueError(f"Invalid temperature: {value}")

    return f"{int(_value*100):04X}"


class ZoneBase(Entity, metaclass=ABCMeta):
    """The Zone/DHW base class."""

    def __init__(self, controller, zone_idx) -> None:
        _LOGGER.debug(
            "Creating a Domain: %s_%s %s", controller.id, zone_idx, self.__class__
        )
        super().__init__(controller._gwy, controller=controller)
        assert zone_idx not in controller.zone_by_idx, "Duplicate zone idx"

        self.id = f"{controller.id}_{zone_idx}"
        self.idx = zone_idx

        self._name = None
        self._zone_type = None

        self._discover()  # should be last thing in __init__()

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return json.dumps(self.schema, indent=2)

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""
        return f"{self.id} ({self._zone_type})"

    @abstractmethod
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        raise NotImplementedError

    def _send_cmd(self, code, **kwargs) -> None:
        dest = kwargs.pop("dest_addr", self._ctl.id)
        payload = kwargs.pop("payload", f"{self.idx}00")
        super()._send_cmd(code, dest, payload, **kwargs)

    @property
    @abstractmethod
    def schema(self) -> dict:
        """Return the schema of the zone/DHW (e.g. sensor_id, zone_type)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def params(self) -> dict:
        """Return the configuration of the zone/DHW (e.g. min_temp, overrun)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def status(self) -> dict:
        """Return the current state of the zone/DHW (e.g. setpoint, temperature)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def sensor(self) -> Device:
        """Return the temperature sensor of the zone/DHW."""
        raise NotImplementedError

    @abstractmethod
    def _set_sensor(self, value: Device) -> None:
        """Set the temperature sensor for the zone (or for the DHW)."""
        raise NotImplementedError

    @property
    def name(self) -> Optional[str]:
        """Return the name of the zone/DHW."""
        return self._name

    @property
    @abstractmethod
    def mode(self) -> dict:
        """Return the operating mode of the zone/DHW ({mode, setpoint, until})."""
        raise NotImplementedError

    @property
    @abstractmethod
    def setpoint(self) -> Optional[float]:
        """Return the target temperature of the zone/DHW."""
        raise NotImplementedError

    # @setpoint.setter
    # @abstractmethod
    # def setpoint(self, value: float) -> None:  # TODO: also mode, name attrs
    #     """Set the target temperature of the zone/DHW."""
    #     raise NotImplementedError

    @property
    @abstractmethod
    def temperature(self) -> Optional[float]:
        """Return the measured temperature of the zone/DHW.

        The controller, not the temperature sensor, is the source of this data.
        """
        raise NotImplementedError

    # @property
    # @abstractmethod
    # def type(self) -> str:
    #     """Return the type of the zone/DHW (e.g. electric_zone, stored_dhw)."""
    #     raise NotImplementedError

    # @abstractmethod
    # def _set_type(self, value: str) -> None:
    #     """Set the type of the zone/DHW (e.g. electric_zone, stored_dhw)."""
    #     raise NotImplementedError


class DhwZone(ZoneBase, HeatDemand):
    """The DHW class.

    FC - 0008, 0009, 1100, 3150, 3B00, (& rare: 0001, 1FC9)
    """

    def __init__(self, controller, sensor=None, relay=None) -> None:
        super().__init__(controller, "FA")

        controller.dhw = self

        self._sensor = None
        self._dhw_valve = None
        self._htg_valve = None
        self.heating_type = "DHW"
        self._name = "Stored DHW"

        self._dhw_mode = {}
        self._dhw_params = {}
        self._temperature = None
        self._relay_demand = None
        self._relay_failsafe = None

    def _discover(self, discover_flags=DISCOVER_ALL) -> None:
        if self._gwy.config["disable_discovery"]:
            return
        # super()._discover()

        # if False and __dev_mode__ and self.idx == "FA":  # dev/test code
        #     self.async_set_override(state="On")

        if discover_flags & DISCOVER_SCHEMA:
            [  # 000C: find the DHW relay(s), if any, see: CODE_000C_DEVICE_TYPE
                self._send_cmd("000C", payload=dev_type)
                for dev_type in ("000D", "000E", "010E")  # for DHW sensor, relay(s)
            ]

        if discover_flags & DISCOVER_PARAMS:
            for code in ("10A0",):
                self._send_cmd(code, payload="00")  # payload="00" or "0000", not "FA"

        if discover_flags & DISCOVER_STATUS:
            for code in ("1260", "1F41"):
                self._send_cmd(code, payload="00")  # payload="00" or "0000", not "FA"

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if msg.code == "0008":
            self._relay_demand = msg.payload["relay_demand"]
        elif msg.code == "0009":
            self._relay_failsafe = msg.payload
        elif msg.code == "10A0":
            self._dhw_params = {
                x: msg.payload[x] for x in ("setpoint", "overrun", "differential")
            }
        elif msg.code == "1260":
            self._temperature = msg.payload["temperature"]
        elif msg.code == "1F41":
            self._setpoint_status = {
                x: msg.payload[x] for x in ("active", "dhw_mode", "until")
            }
        else:
            assert False, "Unknown packet code"

    @property
    def schema(self) -> dict:
        """Return the stored HW's schema."""

        return {
            ATTR_DHW_SENSOR: self._sensor.id if self._sensor else None,
            ATTR_DHW_VALVE: self._dhw_valve.id if self._dhw_valve else None,
            ATTR_DHW_VALVE_HTG: self._htg_valve.id if self._htg_valve else None,
        }

    @property  # setpoint, config, mode (not schedule)
    def params(self) -> dict:
        """Return the stored HW's configuration (excl. schedule)."""

        return {
            "dhw_params": self._dhw_params,
        }

    @property  # temp, open_windows
    def status(self) -> dict:
        """Return the stored HW's current state."""

        return {
            "temperature": self._temperature,
            "dhw_mode": self._dhw_mode,
        }

    @property
    def sensor(self) -> Device:
        """Blah it now.

        Check and Verb the DHW sensor (07:) of this system/CTL (if there is one).

        There is only 1 way to find a controller's DHW sensor:
        1.  The 10A0 RQ/RP *from/to a 07:* (1x/4h)

        The RQ is initiated by the DHW, so is not authorative (the CTL will RP any RQ).
        The I/1260 is not to/from a controller, so is not useful.
        """  # noqa: D402

        # 07:38:39.124 047 RQ --- 07:030741 01:102458 --:------ 10A0 006 00181F0003E4
        # 07:38:39.140 062 RP --- 01:102458 07:030741 --:------ 10A0 006 0018380003E8

        if "10A0" in self._msgs:
            return self._msgs["10A0"].dst.addr

        return self._sensor

    def _set_sensor(self, device: Device) -> None:
        """Set the sensor for this DHW (must be: 07:)."""

        if not isinstance(device, Device) or device.type != "07":
            raise TypeError(f"Invalid device type for DHW sensor: {device}")

        if self._sensor is None:
            self._sensor = device
            device._set_domain(dhw=self)  # TODO: check have same controller

        elif self._sensor != device:
            raise CorruptStateError(f"DHW sensor changed: {self._sensor} to {device}")

    @property
    def hotwater_valve(self) -> Device:
        return self._dhw_valve

    @hotwater_valve.setter
    def hotwater_valve(self, device: Device) -> None:
        if not isinstance(device, Device) or device.type != "13":
            raise TypeError

        if self._dhw_valve is not None and self._dhw_valve != device:
            raise CorruptStateError("The DHW HW valve has changed")
        # elif device.evo is not None and device.evo != self:
        #     raise LookupError  #  do this in add_devices

        if self._dhw_valve is None:
            self._dhw_valve = device
            device._set_domain(dhw=self)

    @property
    def heating_valve(self) -> Device:
        return self._htg_valve

    @heating_valve.setter
    def heating_valve(self, device: Device) -> None:
        if not isinstance(device, Device) or device.type != "13":
            raise TypeError

        if self._htg_valve is not None and self._htg_valve != device:
            raise CorruptStateError("The DHW heating valve has changed")
        # elif device.evo is not None and device.evo != self:
        #     raise LookupError  #  do this in add_devices

        if self._htg_valve is None:
            self._htg_valve = device
            device._set_domain(dhw=self)

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return self._relay_demand

    @property  # only seen with FC, but seems should pair with 0008?
    def relay_failsafe(self) -> Optional[float]:  # 0009
        return self._relay_failsafe

    @property
    def dhw_config(self) -> dict:  # 10A0
        return self._dhw_params

    @property
    def mode(self) -> dict:  # 1F41
        return self._dhw_mode

    @property
    def setpoint(self) -> Optional[float]:  # 1F41
        return self._dhw_mode.get("setpoint")

    @property
    def temperature(self) -> Optional[float]:  # 1260
        return self._temperature

    async def cancel_override(self) -> bool:  # 1F41
        """Reset the DHW to follow its schedule."""
        return False

    async def set_override(self, mode=None, state=None, until=None) -> bool:
        """Force the DHW on/off for a duration, or indefinitely.

        Use until = ? for 1hr boost (obligates on)
        Use until = ? for until next scheduled on/off
        Use until = None for indefinitely
        """
        # 053  I --- 01:145038 --:------ 01:145038 1F41 012 00 01 04 FFFFFF 1E061B0607E4
        # 048  I --- 01:145038 --:------ 01:145038 1F41 012 00 00 04 FFFFFF 1E061B0607E4

        # if mode is None and until is None:
        #     mode = "00" if setpoint is None else "02"  # Follow, Permanent
        # elif mode is None:  # and until is not None
        #     mode = "04"  # Temporary
        # elif isinstance(mode, int):
        #     mode = f"{mode:02X}"
        # elif not isinstance(mode, str):
        #     raise TypeError("Invalid zone mode")
        # elif mode in ZONE_MODE_LOOKUP:
        #     mode = ZONE_MODE_LOOKUP[mode]

        # if mode not in ZONE_MODE_MAP:
        #     raise ValueError("Unknown zone mode")

        # if state is None and until is None:
        #     state = "01"
        # elif state is None:  # and until is not None
        #     state = "01"
        # elif isinstance(state, int):
        #     mode = f"{mode:02X}"
        # elif isinstance(state, bool):
        #     mode = "01" if mode is True else "00"
        # elif not isinstance(mode, str):
        #     raise TypeError("Invalid DHW state")
        # elif state in DHW_STATE_LOOKUP:
        #     state = DHW_STATE_LOOKUP[mode]

        if state not in DHW_STATE_MAP:
            raise ValueError("Unknown DHW state")

        if until is None:
            payload = f"00{state}{mode}FFFFFF"
        else:  # required only by: 04, Temporary, ignored by others
            payload = f"00{state}{mode}FFFFFF{_dtm(until)}"

        self._send_cmd("1F41", verb=" W", payload=payload)
        return False

    async def reset_config(self) -> bool:  # 10A0
        """Reset the DHW parameters to their default values."""
        return False

    async def set_config(self, setpoint, overrun=None, differential=None) -> bool:
        """Set the DHW parameters."""
        return False


class Zone(ZoneBase):
    """The Zone class."""

    def __init__(self, controller, zone_idx, sensor=None, actuators=None) -> None:
        """Create a zone.

        The type of zone may not be known at instantiation. Even when it is known, zones
        are still created without a type before they are subsequently promoted, so that
        both schemes (e.g. eavesdropping, vs probing) are the same.

        In addition, an electric zone may subsequently turn out to be a zone valve zone.
        """
        super().__init__(controller, zone_idx)

        assert (
            zone_idx not in controller.zone_by_idx
        ), "Duplicate zone idx on controller"
        if int(zone_idx, 16) >= self._gwy.config["max_zones"]:
            raise ValueError  # TODO: better to aloow to disable via assert?

        controller.zones.append(self)
        controller.zone_by_idx[zone_idx] = self
        # controller.zone_by_name[self.name] = self

        self.devices = []
        self.device_by_id = {}
        self._sensor = None

        # attributes for .params and .status
        self._mode = None
        self._setpoint = None
        self._temperature = None
        self._window_open = None
        self._zone_config = None

        self._schedule = Schedule(self)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        if self._gwy.config["disable_discovery"]:
            return
        # super()._discover()

        if __dev_mode__ and self.idx == "99":  # dev/test code
            asyncio.create_task(  # TODO: test/dev only
                self.async_cancel_override()
                # self.async_set_override(
                #     setpoint=15.9,
                #     mode="AdvancedOverride",
                #     # until=dt_now() + timedelta(minutes=120)
                # )
            )

        # TODO: add code to determine zone type if it doesn't have one, using 0005s

        [  # 000C: find the sensor and the actuators, if any
            self._send_cmd("000C", payload=f"{self.idx}{dev_type}")
            for dev_type in ("00", "04")  # CODE_0005_ZONE_TYPE
            # for dev_type, description in CODE_000C_DEVICE_TYPE.items()
            # if description is not None
        ]

        # start collecting the schedule
        # self._schedule.req_schedule()  # , restart=True) start collecting schedule

        for code in ("0004",):
            self._send_cmd(code, payload=f"{self.idx}00")

        for code in ("000A", "2349", "30C9"):  # sadly, no 3150
            self._send_cmd(code, payload=self.idx)

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if msg.code == "0004":
            self._name = msg.payload.get("name")

        # not UFH (it seems), but ELE or VAL; and possibly a MIX support 0008 too
        elif msg.code in ("0008", "0009"):  # TODO: how to determine is/isn't MIX?
            assert msg.src.type in ("01", "13")  # 01 as a stat
            assert self._zone_type in (None, "ELE", "VAL")

            if self._zone_type is None:
                self._set_type("ELE")  # might eventually be: "VAL"

        elif msg.code == "000A":
            payload = msg.payload if msg.is_array else [msg.payload]
            self._zone_config = {
                k: v
                for z in payload
                for k, v in z.items()
                if z["zone_idx"] == self.idx and k[:1] != "_" and k != "zone_idx"
            }

        elif msg.code == "0404" and msg.verb == "RP":
            _LOGGER.error("Zone(%s).update: Received RP/0404 (schedule)", self.id)
            self._schedule.add_fragment(msg)
            self._schedule.req_fragment()  # do only if we self._schedule.req_schedule()

        elif msg.code == "2309":
            payload = msg.payload if msg.is_array else [msg.payload]
            self._setpoint = {
                k: v for z in payload for k, v in z.items() if z["zone_idx"] == self.idx
            }["setpoint"]

        elif msg.code == "2349":
            self._mode = {
                k: v
                for k, v in msg.payload.items()
                if k in ("mode", "setpoint", "until")
            }
            self._setpoint = msg.payload["setpoint"]

        elif msg.code == "30C9":  # required for sensor matching
            assert msg.src.type in DEVICE_HAS_ZONE_SENSOR + ("01",)
            payload = msg.payload if msg.is_array else [msg.payload]
            self._temperature = {
                k: v for z in payload for k, v in z.items() if z["zone_idx"] == self.idx
            }["temperature"]

        elif msg.code == "3150":  # TODO: and msg.verb in (" I", "RP")?
            assert msg.src.type in ("02", "04", "13")
            assert self._zone_type in (None, "RAD", "UFH", "VAL")  # ELE don't have 3150

            if msg.src.type in ("02", "04", "13"):
                zone_type = ZONE_CLASS_MAP[msg.src.type]
                self._set_type("VAL" if zone_type == "ELE" else zone_type)

        # elif "zone_idx" in msg.payload:
        #     pass

        # elif msg.code not in ("FFFF"):
        #     assert False, "Unknown packet code"

    @property  # id, type
    def schema(self) -> dict:
        """Return the zone's schema."""

        return {
            ATTR_ZONE_TYPE: self.heating_type,
            ATTR_ZONE_SENSOR: self._sensor.id if self._sensor else None,
            ATTR_DEVICES: [d.id for d in self.devices],
        }

    @property  # setpoint, config, mode (not schedule)
    def params(self) -> dict:
        """Return the zone's configuration (excl. schedule)."""

        ATTR_NAME = "name"
        ATTR_MODE = "mode"
        ATTR_CONFIG = "zone_config"

        return {
            ATTR_NAME: self.name,
            ATTR_MODE: self.mode,
            ATTR_CONFIG: self.zone_config,
        }

    @property
    def status(self) -> dict:
        """Return the zone's current state."""

        return {
            ATTR_SETPOINT: self.setpoint,
            ATTR_TEMP: self.temperature,
        }

    @property
    def sensor(self) -> Device:
        return self._sensor

    def _set_sensor(self, device: Device):
        """Set the sensor for this zone (one of: 01:, 03:, 04:, 12:, 22:, 34:)."""

        sensor_types = ("01", "03", "04", "12", "22", "34")
        if not isinstance(device, Device) or device.type not in sensor_types:
            raise TypeError(f"Invalid device type for zone sensor: {device}")

        if self._sensor is None:
            self._sensor = device  # if TRV, zone type likely (but not req'd) RAD
            device._set_domain(zone=self)  # TODO: check have same controller

        elif self._sensor is not device:
            raise CorruptStateError(f"zone sensor changed: {self._sensor} to {device}")

    @property
    def heating_type(self) -> Optional[str]:
        """TODO.

        There are three ways to determine the type of a zone:
        1. Use a 0005 packet (deterministic)
        2. Eavesdrop (non-deterministic, slow to converge)
        3. via a config file (a schema)
        """

        if self._zone_type is not None:  # isinstance(self, ???)
            return ZONE_TYPE_MAP.get(self._zone_type)

        # TODO: actuators
        dev_types = [d.type for d in self.devices if d.type in ("02", "04", "13")]

        if "02" in dev_types:
            zone_type = "UFH"
        elif "13" in dev_types and "3150" in self._msgs:
            zone_type = "VAL"
        elif "13" in dev_types:
            zone_type = "ELE"  # could still be a VAL
        # elif "??" in dev_types:  # TODO:
        #     zone_type = "MIX"
        elif "04" in dev_types:  # beware edge case: TRV as sensor for a non-RAD zone
            zone_type = "RAD"
        else:
            zone_type = None

        if zone_type is not None:
            self._set_type(zone_type)

        return ZONE_TYPE_MAP.get(self._zone_type)

    def _set_type(self, zone_type: str):
        """Set the zone's type, after validating it.

        There are two possible sources for the type of a zone:
        1. eavesdropping packet codes
        2. analyzing child devices

        Both will execute a zone.type = type (i.e. via this setter).
        """

        _type = ZONE_TYPE_SLUGS.get(zone_type, zone_type)
        if _type not in ZONE_CLASSES:
            raise ValueError(f"Not a known zone type: {zone_type}")

        if self._zone_type is not None:
            if self._zone_type != _type and (
                self._zone_type != "ELE" and _type != "VAL"
            ):
                raise CorruptStateError(
                    f"Zone {self} has a mismatched type: "
                    f"old={self._zone_type}, new={_type}",
                )

        self._zone_type = _type
        self.__class__ = ZONE_CLASSES[_type]
        _LOGGER.debug("Zone %s: type now set to %s", self.id, self._zone_type)

    @property
    def zone_config(self) -> Optional[dict]:  # 000A
        return self._zone_config

    @property
    def mode(self) -> Optional[dict]:  # 2349
        # result = self._get_msg_value("2349")
        # self._mode = (
        #     {k: v for k, v in result.items() if k != "zone_idx"} if result else None
        # )

        return self._mode

    @property
    def setpoint(self) -> Optional[float]:  # 2309 (2349 is a superset of 2309)
        msg = self._ctl._msgs.get("2309")
        if msg is not None:
            self._setpoint = {
                k: v
                for z in msg.payload
                for k, v in z.items()
                if z["zone_idx"] == self.idx
            }.get("setpoint")
        return self._setpoint

    @setpoint.setter
    def setpoint(self, value) -> None:
        """Set the target temperature, until the next scheduled setpoint."""
        if value is None:
            self.cancel_override()
        else:
            self.set_override(mode="advanced_override", setpoint=value)

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        # TODO: this wont wokr if the controller is the sensor
        # if self.sensor and self.sensor.temperature:
        #     return self.sensor.temperature

        msg = self._ctl._msgs.get("30C9")
        if msg is not None:
            self._temperature = {
                k: v
                for z in msg.payload
                for k, v in z.items()
                if z["zone_idx"] == self.idx
            }.get("temperature")
        return self._temperature

    @property
    def heat_demand(self) -> Optional[float]:
        demands = [
            d.heat_demand
            for d in self.devices
            if hasattr(d, "heat_demand") and d.heat_demand is not None
        ]
        # return max(demands) if demands else None
        return round(sum(demands) / len(demands), 1) if demands else None

    def schedule(self, force_update=False) -> Optional[dict]:
        """Return the schedule if any."""
        return self._schedule.schedule if self._schedule else None

    def cancel_override(self) -> None:  # 2349
        """Revert to following the schedule."""
        self.set_override()

    def frost_protect(self) -> None:  # 2349
        """Set the zone to the lowest possible setpoint, indefinitely."""
        self.set_override(mode="permanent_override", setpoint=5)  # TODO

    def set_override(self, mode=None, setpoint=None, until=None) -> None:
        """Override the setpoint for a specified duration, or indefinitely.

        The setpoint has a resolution of 0.1 C. If a setpoint temperature is required,
        but none is provided, the controller will use the maximum possible value.

        The until has a resolution of 1 min.

        Incompatible combinations:
          - mode == Follow & setpoint not None (will silently ignore setpoint)
          - mode == Temporary & until is None (will silently ignore)
        """

        if mode is not None:
            if isinstance(mode, int):
                mode = f"{mode:02X}"
            elif not isinstance(mode, str):
                raise TypeError(f"Invalid zone mode: {mode}")
            if mode in ZONE_MODE_MAP:
                mode = ZONE_MODE_MAP["mode"]
            elif mode not in ZONE_MODE_LOOKUP:
                raise TypeError(f"Unknown zone mode: {mode}")
        elif until is None:  # mode is None
            mode = "advanced_override" if setpoint else "follow_schedule"
        else:  # if until is not None:
            mode = "temporary_override" if setpoint else "advanced_override"

        setpoint = _temp(setpoint)  # None means max, if a temp is required

        if until is None:
            mode = "advanced_override" if mode == "temporary_override" else mode

        mode = ZONE_MODE_LOOKUP[mode]

        if until is None:
            payload = f"{self.idx}{setpoint}{mode}FFFFFF"
        else:  # required only by temporary_override, ignored by others
            payload = f"{self.idx}{setpoint}{mode}FFFFFF{_dtm(until)}"

        self._send_cmd("2349", verb=" W", payload=payload)


class ZoneHeatDemand:  # not all zone types call for heat
    """Not all zones call for heat."""

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        if self._gwy.config["disable_discovery"]:
            return
        super()._discover()

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("12B0")  # , payload=self.idx

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        demands = [
            d.heat_demand
            for d in self.devices
            if hasattr(d, "heat_demand") and d.heat_demand is not None
        ]
        return max(demands + [0]) if demands else None

    @property
    def status(self) -> dict:
        return {**super().status, ATTR_HEAT_DEMAND: self.heat_demand}


class EleZone(Zone):  # Electric zones (do *not* call for heat)
    """Base for Electric Heat zones.

    For a small (5A) electric load controlled by a BDR91 (never calls for heat).
    """

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        # ZV zones are Elec zones that also call for heat; ? and also 1100/unkown_0 = 00
        if msg.code == "3150":
            self._set_type("VAL")

        # if msg.code == "FFFF":
        #     pass
        # else:
        #     assert False, "Unknown packet code"

    @property
    def actuator_enabled(self) -> Optional[bool]:  # 3EF0
        return self._get_msg_value("3EF0")  # , "actuator_enabled"

    @property
    def actuator_state(self) -> Optional[float]:  # 3EF1
        return self._get_msg_value("3EF1")

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "actuator_enabled": self.actuator_enabled,
            "actuator_state": self.actuator_state,
        }


class ValZone(ZoneHeatDemand, EleZone):  # Zone valve zones
    """Base for Zone Valve zones.

    For a motorised valve controlled by a BDR91 (will also call for heat).
    """


class RadZone(ZoneHeatDemand, Zone):  # Radiator zones
    """Base for Radiator Valve zones.

    For radiators controlled by HR92s or HR80s (will also call for heat).
    """

    def _proc_msg(self, msg) -> None:
        super()._proc_msg(msg)

        if msg.code == "12B0":
            self._window_open = msg.payload["window_open"]

        # if msg.code == "FFFF":
        #     pass
        # else:
        #     assert False, "Unknown packet code"

    # 3150 (heat_demand) but no 0008 (relay_demand)

    @property
    def window_open(self) -> Optional[bool]:  # 12B0
        return self._window_open

    @property
    def status(self) -> dict:
        return {
            **super().status,
            ATTR_OPEN_WINDOW: self.window_open,
        }


class UfhZone(ZoneHeatDemand, Zone):  # UFH zones
    """Base for Underfloor Heating zones.

    For underfloor heating controlled by an HCE80 or HCC80 (will also call for heat).
    """

    @property
    def ufh_setpoint(self) -> Optional[float]:  # 3B00
        return self._get_msg_value("22C9")

    @property
    def status(self) -> dict:
        return {**super().status, "ufh_setpoint": self.ufh_setpoint}


class MixZone(ZoneHeatDemand, Zone):  # Mix valve zones
    """Base for Mixing Valve zones.

    For a modulating valve controlled by a HM80 (will also call for heat).
    """

    @property
    def mix_config(self) -> dict:
        attrs = ("pump_run_time", "actuator_run_time", "min_flow_temp", "max_flow_temp")
        return {x: self._get_msg_value("1030", x) for x in attrs}

    @property
    def params(self) -> dict:
        return {**super().status, "mix_config": self.mix_config}


ZONE_CLASSES = {
    "RAD": RadZone,
    "ELE": EleZone,
    "VAL": ValZone,
    "UFH": UfhZone,
    "MIX": MixZone,
    "DHW": DhwZone,
}
