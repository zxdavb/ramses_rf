#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - The evohome-compatible zones."""

import logging
from asyncio import Task
from datetime import datetime as dt
from datetime import timedelta as td
from inspect import getmembers, isclass
from sys import modules
from types import SimpleNamespace
from typing import Optional

from .command import Command, Schedule
from .const import (
    _000C_DEVICE,
    ATTR_DEVICES,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_HEAT_DEMAND,
    ATTR_RELAY_DEMAND,
    ATTR_SETPOINT,
    ATTR_TEMP,
    ATTR_WINDOW_OPEN,
    ATTR_ZONE_SENSOR,
    ATTR_ZONE_TYPE,
    DEVICE_HAS_ZONE_SENSOR,
    DISCOVER_ALL,
    DISCOVER_PARAMS,
    DISCOVER_SCHEMA,
    DISCOVER_STATUS,
    ZONE_CLASS_MAP,
    ZONE_TYPE_MAP,
    ZONE_TYPE_SLUGS,
    ZoneMode,
    __dev_mode__,
)
from .devices import BdrSwitch, Device, DhwSensor, Entity
from .exceptions import CorruptStateError
from .helpers import schedule_task

# from .ramses import RAMSES_ZONES, RAMSES_ZONES_ALL

I_, RQ, RP, W_ = " I", "RQ", "RP", " W"

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


ZONE_CLASS = SimpleNamespace(
    DHW="DHW",  # Stored HW (not a zone)
    ELE="ELE",  # Electric
    MIX="MIX",  # Mix valve
    RAD="RAD",  # Radiator
    UFH="UFH",  # Underfloor heating
    VAL="VAL",  # Zone valve
)


class ZoneBase(Entity):
    """The Zone/DHW base class."""

    # __zon_class__ = None  # NOTE: this would cause problems

    def __init__(self, evo, zone_idx) -> None:
        _LOGGER.debug("Creating a Zone: %s_%s (%s)", evo, zone_idx, self.__class__)
        super().__init__(evo._gwy)

        self.id, self.idx = f"{evo.id}_{zone_idx}", zone_idx
        self._evo, self._ctl = self._set_system(evo, zone_idx)

        self._name = None
        self._zone_type = None

    def __repr__(self) -> str:
        return f"{self.id} ({self.heating_type})"

    def __lt__(self, other) -> bool:
        if not hasattr(other, "idx"):
            return NotImplemented
        return self.idx < other.idx

    def _set_system(self, parent, zone_idx):
        """Set the zone's parent system, after validating it."""

        # these imports are here to prevent circular references
        from .systems import System

        try:
            if zone_idx != "HW" and int(zone_idx, 16) >= parent.max_zones:
                raise ValueError(f"{self}: invalid zone_idx {zone_idx} (> max_zones")
        except (TypeError, ValueError):
            raise TypeError(f"{self}: invalid zone_idx {zone_idx}")

        if not isinstance(parent, System):
            raise TypeError(f"{self}: parent must be a System, not {parent}")

        if zone_idx != "HW":
            if self.idx in parent.zone_by_idx:
                raise LookupError(f"{self}: duplicate zone_idx: {zone_idx}")
            parent.zone_by_idx[zone_idx] = self
            parent.zones.append(self)

        self._ctl = parent._ctl

        return parent, parent._ctl

    def _handle_msg(self, msg) -> None:
        """Validate packets by verb/code."""
        # TODO: assert msg.src is self, "Devices should only keep msgs they sent"
        super()._handle_msg(msg)

        # if not self._zone_type:
        #     return
        # ramses_zones = RAMSES_ZONES.get(self._zone_type, RAMSES_ZONES_ALL)
        # assert (
        #     msg.code in ramses_zones
        # ), f"Unknown code for {str(self)}: {msg.verb}/{msg.code}"
        # assert (
        #     msg.verb in ramses_zones[msg.code]
        # ), f"Unknown verb for {str(self)}: {msg.verb}/{msg.code}"

    def _send_cmd(self, code, **kwargs) -> None:
        dest = kwargs.pop("dest_addr", self._ctl.id)
        payload = kwargs.pop("payload", f"{self.idx}00")
        super()._send_cmd(code, dest, payload, **kwargs)

    @property
    def heating_type(self) -> Optional[str]:
        """Return the type of the zone/DHW (e.g. electric_zone, stored_dhw)."""
        return self.__zon_class__


class ZoneSchedule:  # 0404  # TODO: add for DHW
    """Evohome zones have a schedule."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._schedule = Schedule(self)

    # def _discover(self, discover_flag=DISCOVER_ALL) -> None:

    #     if discover_flag & DISCOVER_STATUS:  # TODO: add back in
    #         self._loop.create_task(self.get_schedule())  # 0404

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "0404" and msg.verb == RP:
            _LOGGER.debug("Zone(%s): Received RP/0404 (schedule) pkt", self)

    async def get_schedule(self, force_refresh=None) -> Optional[dict]:
        schedule = await self._schedule.get_schedule(force_refresh=force_refresh)
        if schedule:
            return schedule["schedule"]

    async def set_schedule(self, schedule) -> None:
        schedule = {"zone_idx": self.idx, "schedule": schedule}
        await self._schedule.set_schedule(schedule)

    @property
    def status(self) -> dict:
        return {**super().status, "schedule": self._schedule.schedule.get("schedule")}


class RelayDemand:  # 0008
    """Not all zones call for heat."""

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("0008")  # , payload=self.idx

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        if "0008" in self._msgs:
            return self._msgs["0008"].payload[ATTR_RELAY_DEMAND]

    @property
    def status(self) -> dict:
        return {**super().status, ATTR_RELAY_DEMAND: self.relay_demand}


class DhwZone(ZoneBase):  # CS92A  # TODO: add Schedule
    """The DHW class."""

    __zon_class__ = ZONE_CLASS.DHW

    def __init__(
        self, ctl, zone_idx="HW", sensor=None, dhw_valve=None, htg_valve=None
    ) -> None:
        super().__init__(ctl, zone_idx)

        ctl._set_dhw(self)
        # if profile == ZONE_CLASS.DHW and evo.dhw is None:
        #     evo.dhw = zone

        self._dhw_sensor = None
        self._dhw_valve = None
        self._htg_valve = None

        self._zone_type = ZONE_CLASS.DHW

        self._dhw_mode = None
        self._dhw_params = None
        self._dhw_temp = None
        self._relay_demand = None
        self._relay_failsafe = None

        self._heat_demand = None

        if sensor:
            self._set_sensor(sensor)
        if dhw_valve:
            self._set_dhw_valve(dhw_valve)
        if htg_valve:
            self._set_htg_valve(htg_valve)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)

        # if False and __dev_mode__ and self.idx == "FA":  # dev/test code
        #     self.async_set_override(state="On")

        if discover_flag & DISCOVER_SCHEMA:
            [  # 000C: find the DHW relay(s), if any, see: _000C_DEVICE_TYPE
                self._send_cmd("000C", payload=dev_type)
                for dev_type in (
                    f"00{_000C_DEVICE.DHW_SENSOR}",
                    f"00{_000C_DEVICE.DHW}",
                    f"01{_000C_DEVICE.DHW}",
                )
            ]

        if discover_flag & DISCOVER_PARAMS:
            self._gwy.send_cmd(
                Command.get_dhw_params(self._ctl.id), period=td(hours=12)
            )

        if discover_flag & DISCOVER_STATUS:
            self._gwy.send_cmd(Command.get_dhw_mode(self._ctl.id), period=td(hours=12))
            self._gwy.send_cmd(
                Command.get_dhw_temp(self._ctl.id), period=td(minutes=30)
            )

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "0008":
            self._relay_demand = msg

        elif msg.code == "0009":
            self._relay_failsafe = msg

        elif msg.code == "10A0":
            self._dhw_params = msg

        elif msg.code == "1260":
            self._dhw_temp = msg

        elif msg.code == "1F41":
            self._dhw_mode = msg

    def _set_dhw_device(self, new_dev, old_dev, attr_name, dev_class, domain_id):
        if old_dev is new_dev:
            return old_dev
        if old_dev is not None:
            raise CorruptStateError(
                f"{self} changed {attr_name}: {old_dev} to {new_dev}"
            )

        if not isinstance(new_dev, dev_class):
            raise TypeError(f"{self}: {attr_name} can't be {dev_class}")

        new_dev._set_parent(self, domain=domain_id)
        return new_dev

    def _set_sensor(self, device: DhwSensor) -> None:
        """Set the temp sensor for this DHW system (07: only)."""

        # 07:38:39.124 047 RQ --- 07:030741 01:102458 --:------ 10A0 006 00181F0003E4
        # 07:38:39.140 062 RP --- 01:102458 07:030741 --:------ 10A0 006 0018380003E8

        self._dhw_sensor = self._set_dhw_device(
            device, self._dhw_sensor, ATTR_ZONE_SENSOR, DhwSensor, "FA"
        )

    @property
    def sensor(self) -> DhwSensor:  # self._dhw_sensor
        return self._dhw_sensor

    def _set_dhw_valve(self, device: BdrSwitch) -> None:  # self._dhw_valve
        """Set the hotwater valve relay for this DHW system (13: only).

        Check and Verb the DHW sensor (07:) of this system/CTL (if there is one).

        There is only 1 way to eavesdrop a controller's DHW sensor:
        1.  The 10A0 RQ/RP *from/to a 07:* (1x/4h)

        The RQ is initiated by the DHW, so is not authorative (the CTL will RP any RQ).
        The I/1260 is not to/from a controller, so is not useful.
        """  # noqa: D402

        self._dhw_valve = self._set_dhw_device(
            device, self._dhw_valve, ATTR_DHW_VALVE, BdrSwitch, "FA"
        )

    @property
    def hotwater_valve(self) -> BdrSwitch:  # self._dhw_valve
        return self._dhw_valve

    def _set_htg_valve(self, device: BdrSwitch) -> None:  # self._htg_valve
        """Set the heating valve relay for this DHW system (13: only)."""

        self._htg_valve = self._set_dhw_device(
            device, self._htg_valve, ATTR_DHW_VALVE_HTG, BdrSwitch, "F9"
        )

    @property
    def heating_valve(self) -> BdrSwitch:  # self._htg_valve
        return self._htg_valve

    @property
    def name(self) -> str:
        return "Stored HW"

    @property
    def config(self) -> Optional[dict]:  # 10A0
        result = self._msg_payload(self._dhw_params)
        if result:
            return {k: v for k, v in result.items() if k != "dhw_idx"}

    @property
    def mode(self) -> Optional[dict]:  # 1F41
        # active (setpoint), mode, until
        return self._msg_payload(self._dhw_mode)

    @property
    def setpoint(self) -> Optional[float]:  # 1F41
        return self._msg_payload(self._dhw_params, ATTR_SETPOINT)

    @setpoint.setter
    def setpoint(self, value) -> None:  # 1F41
        return self.set_config(setpoint=value)

    @property
    def temperature(self) -> Optional[float]:  # 1260
        return self._msg_payload(self._dhw_temp, ATTR_TEMP)

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._msg_payload(self._heat_demand, ATTR_HEAT_DEMAND)

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return self._msg_payload(self._relay_demand, "relay_demand")

    @property  # only seen with FC, but seems should pair with 0008?
    def relay_failsafe(self) -> Optional[float]:  # 0009
        return self._msg_payload(self._relay_failsafe, "relay_failsafe")

    def set_mode(self, mode=None, active=None, until=None) -> Task:
        """Set the DHW mode (mode, active, until)."""
        cmd = Command.set_dhw_mode(self._ctl.id, mode=mode, active=active, until=until)
        return self._gwy.send_cmd(cmd)

    def set_boost_mode(self) -> Task:
        """Enable DHW for an hour, despite any schedule."""
        return self.set_mode(
            mode=ZoneMode.TEMPORARY, active=True, until=dt.now() + td(hours=1)
        )

    def reset_mode(self) -> Task:  # 1F41
        """Revert the DHW to following its schedule."""
        return self.set_mode(mode=ZoneMode.SCHEDULE)

    def set_config(self, setpoint=None, overrun=None, differential=None) -> Task:
        """Set the DHW parameters (setpoint, overrun, differential)."""
        # if self._dhw_params:  # 10A0
        # if setpoint is None:
        #     setpoint = self._msg_payload(self._dhw_params, ATTR_SETPOINT)
        # if overrun is None:
        #     overrun = self._msg_payload(self._dhw_params, "overrun")
        # if differential is None:
        #     setpoint = self._msg_payload(self._dhw_params, "differential")

        cmd = Command.set_dhw_params(self._ctl.id, setpoint, overrun, differential)
        return self._gwy.send_cmd(cmd)

    def reset_config(self) -> Task:  # 10A0
        """Reset the DHW parameters to their default values."""
        return self.set_config(setpoint=50, overrun=5, differential=1)

    @property
    def schema(self) -> dict:
        """Return the DHW's schema (devices)."""
        return {
            ATTR_DHW_SENSOR: self.sensor.id if self.sensor else None,
            ATTR_DHW_VALVE: self.hotwater_valve.id if self.hotwater_valve else None,
            ATTR_DHW_VALVE_HTG: self.heating_valve.id if self.heating_valve else None,
        }

    @property
    def params(self) -> dict:
        """Return the DHW's configuration (excl. schedule)."""
        return {a: getattr(self, a) for a in ("config", "mode")}

    @property
    def status(self) -> dict:
        """Return the DHW's current state."""
        return {a: getattr(self, a) for a in (ATTR_TEMP, ATTR_HEAT_DEMAND)}


class Zone(ZoneSchedule, ZoneBase):
    """The Zone base class."""

    __zon_class__ = None  # Unknown

    def __init__(self, evo, zone_idx, sensor=None, actuators=None) -> None:
        """Create a zone.

        The type of zone may not be known at instantiation. Even when it is known, zones
        are still created without a type before they are subsequently promoted, so that
        both schemes (e.g. eavesdropping, vs probing) are the same.

        In addition, an electric zone may subsequently turn out to be a zone valve zone.
        """
        if int(zone_idx, 16) >= evo.max_zones:
            raise ValueError(f"Invalid zone idx: {zone_idx} (exceeds max_zones)")

        super().__init__(evo, zone_idx)

        self.devices = []
        self.device_by_id = {}
        self._sensor = None

        self._heat_demand = None  # Not used by ELE
        self._mode = None
        # self._name = None  # from super()
        self._setpoint = None
        self._temperature = None
        self._zone_config = None

        # these needed here, as we can't use those __init__()s
        self._mix_config = None  # MIX
        self._ufh_setpoint = None  # UFH
        self._window_open = None  # RAD (or: ALL)
        self._actuator_state = None  # ELE, ZON

        # self._schedule = Schedule(self)  # TODO:

        if sensor:
            self._set_sensor(sensor)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        # TODO: add code to determine zone type if it doesn't have one, using 0005s
        if discover_flag & DISCOVER_SCHEMA:
            self._send_cmd("000C", payload=f"{self.idx}{_000C_DEVICE.ALL}")
            self._send_cmd("000C", payload=f"{self.idx}{_000C_DEVICE.ALL_SENSOR}")

        if discover_flag & DISCOVER_PARAMS:
            self._gwy.send_cmd(Command.get_zone_config(self._ctl.id, self.idx))
            self._gwy.send_cmd(
                Command.get_zone_name(self._ctl.id, self.idx), period=td(hours=4)
            )

        if discover_flag & DISCOVER_STATUS:  # every 1h, CTL will not respond to a 3150
            self._gwy.send_cmd(
                Command.get_zone_mode(self._ctl.id, self.idx), period=td(minutes=30)
            )
            self._gwy.send_cmd(Command.get_zone_temperature(self._ctl.id, self.idx))
            self._gwy.send_cmd(Command.get_zone_window_state(self._ctl.id, self.idx))

        # start collecting the schedule
        # self._schedule.req_schedule()  # , restart=True) start collecting schedule

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if isinstance(msg.payload, list):
            assert self.idx in [d["zone_idx"] for d in msg.payload]

        if msg.code == "0004":
            self._name = msg

        # not UFH (it seems), but ELE or VAL; and possibly a MIX support 0008 too
        elif msg.code in ("0008", "0009"):  # TODO: how to determine is/isn't MIX?
            assert msg.src.type in ("01", "13"), msg.src.type  # 01 as a stat
            assert self._zone_type in (None, "ELE", "VAL", "MIX"), self._zone_type

            if self._zone_type is None:
                self._set_zone_type("ELE")  # might eventually be: "VAL"

        elif msg.code == "000A":
            self._zone_config = msg

        elif msg.code == "12B0":
            self._window_open = msg

        elif msg.code == "2309" and msg.verb in (I_, RP):  # setpoint
            assert msg.src.type == "01", "coding error zxw"
            self._setpoint = msg

        elif msg.code == "2349" and msg.verb in (I_, RP):  # mode, setpoint
            assert msg.src.type == "01", "coding error zxx"
            self._mode = msg
            self._setpoint = msg

        elif msg.code == "30C9" and msg.verb in (I_, RP):  # used by sensor matching
            assert msg.src.type in DEVICE_HAS_ZONE_SENSOR + ("01",), "coding error"
            self._temperature = msg

        elif msg.code == "3150":  # TODO: and msg.verb in (I_, RP)?
            assert msg.src.type in ("00", "02", "04", "13")
            assert self._zone_type in (None, "RAD", "UFH", "VAL")  # MIX/ELE don't 3150

            if msg.src.type in ("00", "02", "04", "13"):
                zone_type = ZONE_CLASS_MAP[msg.src.type]
                self._set_zone_type("VAL" if zone_type == "ELE" else zone_type)

        # elif "zone_idx" in msg.payload:
        #     pass

    @property
    def sensor(self) -> Device:
        return self._sensor

    def _set_sensor(self, device: Device) -> None:  # self._sensor
        """Set the temp sensor for this zone (one of: 01:, 03:, 04:, 12:, 22:, 34:)."""

        if self._sensor is device:
            return
        if self._sensor is not None:
            raise CorruptStateError(
                f"{self} changed {ATTR_ZONE_SENSOR}: {self._sensor} to {device}"
            )

        sensor_types = ("00", "01", "03", "04", "12", "22", "34")
        if not isinstance(device, Device) or device.type not in sensor_types:
            # TODO: or not hasattr(device, "temperature")
            raise TypeError(f"{self}: {ATTR_ZONE_SENSOR} can't be: {device}")

        self._sensor = device
        device._set_parent(self)  # , domain=self.idx)

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
        dev_types = [d.type for d in self.devices if d.type in ("00", "02", "04", "13")]

        if "02" in dev_types:
            zone_type = "UFH"
        elif "13" in dev_types:
            zone_type = "VAL" if "3150" in self._msgs else "ELE"
        # elif "??" in dev_types:  # TODO:
        #     zone_type = "MIX"
        elif "04" in dev_types or "00" in dev_types:
            # beware edge case: TRV as sensor for a non-RAD zone
            zone_type = "RAD"
        else:
            zone_type = None

        if zone_type is not None:
            self._set_zone_type(zone_type)

        return ZONE_TYPE_MAP.get(self._zone_type)

    def _set_zone_type(self, zone_type: str):  # self._zone_type
        """Set the zone's type, after validating it.

        There are two possible sources for the type of a zone:
        1. eavesdropping packet codes
        2. analyzing child devices

        Both will execute a zone.type = type (i.e. via this setter).
        """

        _type = ZONE_TYPE_SLUGS.get(zone_type, zone_type)
        if _type not in ZONE_BY_CLASS_ID:
            raise ValueError(f"Not a known zone_type: {zone_type}")

        if self._zone_type == _type:
            return
        if self._zone_type is not None and (
            self._zone_type != "ELE" and _type != "VAL"
        ):
            raise CorruptStateError(
                f"{self} changed zone_type: {self._zone_type} to {_type}"
            )

        self._zone_type = _type
        self.__class__ = ZONE_BY_CLASS_ID[_type]
        self._discover()  # TODO: needs tidyup (ref #67)

    @property
    def name(self) -> Optional[str]:
        """Return the name of the zone."""
        return self._msg_payload(self._name, "name")

    @name.setter
    def name(self, value) -> Optional[str]:
        """Set the name of the zone."""
        self._gwy.send_cmd(Command.set_zone_name(self._ctl.id, self.idx, value))

        # async def get_name(self, force_refresh=None) -> Optional[str]:
        #     """Return the name of the zone."""
        #     if not force_refresh and self._name is not None:
        #         return self._msg_payload(self._name, "name")

        #     self._name = None
        #     self._send_cmd("0004", payload=f"{self.idx}00")
        #     while self._name is None:
        #         await asyncio.sleep(0.05)

        #     return self._msg_payload(self._name, "name")

    @property
    def config(self) -> Optional[dict]:  # 000A
        if not self._zone_config or self._zone_config.is_expired:
            return

        elif isinstance(self._zone_config.payload, dict):
            result = self._msg_payload(self._zone_config)

        elif isinstance(self._zone_config.payload, list):
            tmp = [z for z in self._zone_config.payload if z["zone_idx"] == self.idx]
            result = {k: v for k, v in tmp[0].items() if k[:1] != "_"}

        if result:
            return {k: v for k, v in result.items() if k != "zone_idx"}

    @property
    def mode(self) -> Optional[dict]:  # 2349
        # setpoint, mode, until
        if not self._mode or self._mode.is_expired:
            return

        result = self._msg_payload(self._mode)
        if result:
            return {k: v for k, v in result.items() if k != "zone_idx"}

    @property
    def setpoint(self) -> Optional[float]:  # 2309 (2349 is a superset of 2309)
        if not self._setpoint or self._setpoint.is_expired:
            return

        elif isinstance(self._setpoint.payload, dict):
            return self._msg_payload(self._setpoint, ATTR_SETPOINT)

        elif isinstance(self._setpoint.payload, list):
            _zone = [z for z in self._setpoint.payload if z["zone_idx"] == self.idx]
            return _zone[0][ATTR_SETPOINT]

    @setpoint.setter
    def setpoint(self, value) -> None:
        """Set the target temperature, until the next scheduled setpoint."""
        if value is None:
            self.reset_mode()
        else:
            cmd = Command.set_zone_setpoint(self._ctl.id, self.idx, value)
            self._gwy.send_cmd(cmd)
            # NOTE: the following doesn't wotk for e.g. Hometronics
            # self.set_mode(mode=ZoneMode.ADVANCED, setpoint=value)

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        # if not self._temperature or self._temperature.is_expired:
        #       # NOTE: CTL (as sensor) won't have this attr...
        #     if self.sensor and self.sensor.temperature:
        #         self._temperature = self.sensor._temp

        if not self._temperature or (
            self._temperature.is_expired == self._temperature.HAS_EXPIRED
        ):
            return

        elif isinstance(self._temperature.payload, dict):
            return self._msg_payload(self._temperature, ATTR_TEMP)

        elif isinstance(self._temperature.payload, list):
            tmp = [z for z in self._temperature.payload if z["zone_idx"] == self.idx]
            return tmp[0][ATTR_TEMP]

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        """Return the zone's heat demand, estimated from its devices' heat demand."""
        demands = [
            d.heat_demand
            for d in self.devices
            if hasattr(d, ATTR_HEAT_DEMAND) and d.heat_demand is not None
        ]
        # return round(sum(demands) / len(demands), 1) if demands else None
        return max(demands + [0]) if demands else None

    @property
    def window_open(self) -> Optional[bool]:  # 12B0  # TODO: don't work >1 TRV?
        """Return an estimate of the zone's current window_open state."""
        windows = [
            d.window_open
            for d in self.devices
            if hasattr(d, ATTR_WINDOW_OPEN) and d.window_open is not None
        ]
        return any(windows) if windows else None

    def reset_config(self) -> Task:
        """Reset the zone's parameters to their default values."""
        return self.set_config()

    def set_config(
        self,
        min_temp=5,
        max_temp=35,
        local_override: bool = False,
        openwindow_function: bool = False,
        multiroom_mode: bool = False,
    ) -> Task:
        """Set the zone's parameters (min_temp, max_temp, etc.)."""
        cmd = Command.set_zone_config(
            self._ctl.id,
            self.idx,
            min_temp=min_temp,
            max_temp=max_temp,
            local_override=local_override,
            openwindow_function=openwindow_function,
            multiroom_mode=multiroom_mode,
        )
        return self._gwy.send_cmd(cmd)

    def reset_mode(self) -> Task:  # 2349
        """Revert the zone to following its schedule."""
        return self.set_mode(mode=ZoneMode.SCHEDULE)

    def set_frost_mode(self) -> Task:  # 2349
        """Set the zone to the lowest possible setpoint, indefinitely."""
        return self.set_mode(mode=ZoneMode.PERMANENT, setpoint=5)  # TODO

    def set_mode(self, mode=None, setpoint=None, until=None) -> Task:
        """Override the zone's setpoint for a specified duration, or indefinitely."""
        cmd = Command.set_zone_mode(self._ctl.id, self.idx, mode, setpoint, until)
        return self._gwy.send_cmd(cmd)

    def set_name(self, name) -> Task:
        """Set the zone's name."""
        cmd = Command.set_zone_name(self._ctl.id, self.idx, name)
        return self._gwy.send_cmd(cmd)

    @property
    def schema(self) -> dict:
        """Return the zone's schema (type, devices)."""
        if not self._sensor:
            sensor_schema = None
        elif getattr(self._sensor, "_30C9_faked", None) is None:
            # NOTE: CTL (as sensor) won't have this attr...
            sensor_schema = self._sensor.id
        else:
            sensor_schema = {
                "device_id": self._sensor.id,
                "is_faked": self._sensor._30C9_faked,
            }

        return {
            ATTR_ZONE_TYPE: self.heating_type,
            ATTR_ZONE_SENSOR: sensor_schema,
            ATTR_DEVICES: [d.id for d in self.devices],
        }

    @property  # TODO: setpoint
    def params(self) -> dict:
        """Return the zone's configuration (excl. schedule)."""
        return {a: getattr(self, a) for a in ("config", "mode", "name")}

    @property
    def status(self) -> dict:
        """Return the zone's current state."""
        return {
            a: getattr(self, a) for a in (ATTR_SETPOINT, ATTR_TEMP, ATTR_HEAT_DEMAND)
        }


class EleZone(RelayDemand, Zone):  # BDR91A/T  # TODO: 0008/0009/3150
    """For a small electric load controlled by a relay (never calls for heat)."""

    __zon_class__ = ZONE_CLASS.ELE

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # NOTE: we create, then promote, so shouldn't super()
        # super()._discover(discover_flag=discover_flag)
        if False and discover_flag & DISCOVER_SCHEMA:
            self._send_cmd("000C", payload=f"{self.idx}{_000C_DEVICE.ELE}")

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        # if msg.code == "0008":  # ZON zones are ELE zones that also call for heat
        #     self._set_zone_type("VAL")
        if msg.code == "3150":
            raise TypeError("WHAT 1")
        elif msg.code == "3EF0":
            raise TypeError("WHAT 2")

    @property
    def heat_demand(self) -> None:  # Electric zones (do *not* call for heat)
        """Return None as the zone's heat demand, electric zones don't call for heat."""
        return


class MixZone(Zone):  # HM80  # TODO: 0008/0009/3150
    """For a modulating valve controlled by a HM80 (will also call for heat).

    Note that HM80s are listen-only devices.
    """

    __zon_class__ = ZONE_CLASS.MIX

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # NOTE: we create, then promote, so shouldn't super()
        # super()._discover(discover_flag=discover_flag)
        if False and discover_flag & DISCOVER_SCHEMA:
            self._send_cmd("000C", payload=f"{self.idx}{_000C_DEVICE.MIX}")

        if discover_flag & DISCOVER_PARAMS:
            self._gwy.send_cmd(Command.get_mix_valve_params(self._ctl.id, self.idx))

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "1030" and msg.verb == I_:
            self._mix_config = msg

    @property
    def mix_config(self) -> dict:
        return self._msg_payload(self._mix_config)

    @property
    def params(self) -> dict:
        return {**super().status, "mix_config": self.mix_config}


class RadZone(Zone):  # HR92/HR80
    """For radiators controlled by HR92s or HR80s (will also call for heat)."""

    __zon_class__ = ZONE_CLASS.RAD

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # NOTE: we create, then promote, so shouldn't super()
        # super()._discover(discover_flag=discover_flag)
        if False and discover_flag & DISCOVER_SCHEMA:
            self._send_cmd("000C", payload=f"{self.idx}{_000C_DEVICE.RAD}")


class UfhZone(Zone):  # HCC80/HCE80  # TODO: needs checking
    """For underfloor heating controlled by an HCE80/HCC80 (will also call for heat)."""

    __zon_class__ = ZONE_CLASS.UFH

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # NOTE: we create, then promote, so shouldn't super()
        # super()._discover(discover_flag=discover_flag)
        if False and discover_flag & DISCOVER_SCHEMA:
            self._send_cmd("000C", payload=f"{self.idx}{_000C_DEVICE.UFH}")

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "22C9" and msg.verb == I_:
            self._ufh_setpoint = msg

    @property
    def ufh_setpoint(self) -> Optional[float]:  # 22C9
        return self._msg_payload(self._ufh_setpoint, ATTR_SETPOINT)

    @property
    def status(self) -> dict:
        return {**super().status, "ufh_setpoint": self.ufh_setpoint}


class ValZone(EleZone):  # BDR91A/T
    """For a motorised valve controlled by a BDR91 (will also call for heat)."""

    __zon_class__ = ZONE_CLASS.VAL

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # NOTE: we create, then promote, so shouldn't super()
        # super()._discover(discover_flag=discover_flag)
        if False and discover_flag & DISCOVER_SCHEMA:
            self._send_cmd("000C", payload=f"{self.idx}{_000C_DEVICE.VAL}")

    @property
    def heat_demand(self) -> Optional[float]:  # 0008 (NOTE: not 3150)
        """Return the zone's heat demand, using relay demand as a proxy."""
        return self.relay_demand


CLASS_ATTR = "__zon_class__"
ZONE_BY_CLASS_ID = {
    getattr(c[1], CLASS_ATTR): c[1]
    for c in getmembers(
        modules[__name__],
        lambda m: isclass(m) and m.__module__ == __name__ and hasattr(m, CLASS_ATTR),
    )
}  # e.g. "RAD": RadZone


def create_zone(evo, zone_idx, profile=None, **kwargs) -> Zone:
    """Create a zone, and optionally perform discovery & start polling."""

    if profile is None:
        profile = ZONE_CLASS.DHW if zone_idx == "HW" else None

    zone = ZONE_BY_CLASS_ID.get(profile, Zone)(evo, zone_idx, **kwargs)

    if not evo._gwy.config.disable_discovery:
        schedule_task(zone._discover, discover_flag=DISCOVER_SCHEMA, delay=1)
        schedule_task(zone._discover, discover_flag=DISCOVER_PARAMS, delay=4)
        schedule_task(zone._discover, discover_flag=DISCOVER_STATUS, delay=7)

    return zone
