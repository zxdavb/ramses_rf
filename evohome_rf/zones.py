#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - The evohome-compatible zones."""

import logging
from abc import ABCMeta, abstractmethod
from asyncio import Task
from datetime import datetime as dt
from datetime import timedelta as td
from typing import Optional

from .command import Command, Schedule
from .const import (
    ATTR_DEVICES,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_HEAT_DEMAND,
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
from .devices import Device, Entity
from .exceptions import CorruptStateError

# from .ramses import RAMSES_ZONES, RAMSES_ZONES_ALL

I_, RQ, RP, W_ = " I", "RQ", "RP", " W"

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class ZoneBase(Entity, metaclass=ABCMeta):
    """The Zone/DHW base class."""

    DHW = "DHW"
    ELE = "ELE"
    MIX = "MIX"
    RAD = "RAD"
    UFH = "UFH"
    VAL = "VAL"

    def __init__(self, evo, zone_idx) -> None:
        _LOGGER.debug("Creating a Zone: %s_%s", evo.id, zone_idx)
        super().__init__(evo._gwy)

        self.id = f"{evo.id}_{zone_idx}"
        self.idx = zone_idx

        self._name = None
        self._zone_type = None

        self._evo = evo
        self._ctl = evo._ctl

    def __repr__(self) -> str:
        return f"{self.id} ({self.heating_type})"

    def __lt__(self, other) -> bool:
        if not hasattr(other, "idx"):
            return NotImplemented
        return self.idx < other.idx

    @abstractmethod
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        raise NotImplementedError

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
    @abstractmethod
    def name(self) -> Optional[str]:
        """Return the name of the zone/DHW."""
        raise NotImplementedError

    @property
    @abstractmethod
    def config(self) -> Optional[dict]:
        """Return the configuration (parameters) of the zone/DHW."""
        raise NotImplementedError

    @property
    @abstractmethod
    def mode(self) -> Optional[dict]:
        """Return the operating mode of the zone/DHW (mode, setpoint/active, until)."""
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
        """Return the measured temperature of the zone/DHW."""
        raise NotImplementedError

    @property
    def heating_type(self) -> str:
        """Return the type of the zone/DHW (e.g. electric_zone, stored_dhw)."""
        return self._zone_type

    # @abstractmethod
    # def ._set_zone_type(self, value: str) -> None:
    #     """Set the type of the zone/DHW (e.g. electric_zone, stored_dhw)."""
    #     raise NotImplementedError

    @property
    @abstractmethod
    def heat_demand(self) -> Optional[float]:
        """Return the (estimated) heat_demand of the zone/DHW."""
        raise NotImplementedError


class DhwZone(ZoneBase):
    """The DHW class."""

    def __init__(self, ctl, sensor=None, dhw_valve=None, htg_valve=None) -> None:
        super().__init__(ctl, "HW")

        ctl._set_dhw(self)

        self._dhw_sensor = None
        self._dhw_valve = None
        self._htg_valve = None

        self._zone_type = Zone.DHW

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

    def _discover(self, discover_flags=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)

        # if False and __dev_mode__ and self.idx == "FA":  # dev/test code
        #     self.async_set_override(state="On")

        if discover_flags & DISCOVER_SCHEMA:
            [  # 000C: find the DHW relay(s), if any, see: CODE_000C_DEVICE_TYPE
                self._send_cmd("000C", payload=dev_type)
                for dev_type in ("000D", "000E", "010E")  # for DHW sensor, relay(s)
            ]

        if discover_flags & DISCOVER_PARAMS:
            for code in ("10A0",):
                self._send_cmd(code, payload="00")  # payload="00" (or "0000"), not "FA"

        if discover_flags & DISCOVER_STATUS:
            for code in ("1260", "1F41"):
                self._send_cmd(code, payload="00")  # payload="00" or "0000", not "FA"

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

    def _set_sensor(self, device: Device) -> None:
        """Set the temp sensor for this DHW system (07: only)."""

        if self._dhw_sensor is device:
            return
        elif self._dhw_sensor is not None:
            raise CorruptStateError(
                f"{ATTR_ZONE_SENSOR} shouldn't change: {self._dhw_sensor} to {device}"
            )

        if not isinstance(device, Device) or device.type != "07":
            raise TypeError(f"{ATTR_ZONE_SENSOR} can't be: {device}")

        if self._dhw_sensor is None:
            self._dhw_sensor = device
            device._set_parent(self, domain="FA")

    @property
    def sensor(self) -> Device:  # self._dhw_sensor
        return self._dhw_sensor

    def _set_dhw_valve(self, device: Device) -> None:
        """Set the hotwater valve relay for this DHW system (13: only)."""

        """Blah it now.

        Check and Verb the DHW sensor (07:) of this system/CTL (if there is one).

        There is only 1 way to eavesdrop a controller's DHW sensor:
        1.  The 10A0 RQ/RP *from/to a 07:* (1x/4h)

        The RQ is initiated by the DHW, so is not authorative (the CTL will RP any RQ).
        The I/1260 is not to/from a controller, so is not useful.
        """  # noqa: D402

        # 07:38:39.124 047 RQ --- 07:030741 01:102458 --:------ 10A0 006 00181F0003E4
        # 07:38:39.140 062 RP --- 01:102458 07:030741 --:------ 10A0 006 0018380003E8

        # if "10A0" in self._msgs:
        #     return self._msgs["10A0"].dst.addr
        if not isinstance(device, Device) or device.type != "13":
            raise TypeError(f"{ATTR_DHW_VALVE} can't be: {device}")

        if self._dhw_valve is not None:
            if self._dhw_valve is device:
                return
            raise CorruptStateError(
                f"{ATTR_DHW_VALVE} shouldn't change: {self._dhw_valve} to {device}"
            )

        if self._dhw_valve is None:
            self._dhw_valve = device
            device._set_parent(self, domain="FA")

    @property
    def hotwater_valve(self) -> Device:  # self._dhw_valve
        return self._dhw_valve

    def _set_htg_valve(self, device: Device) -> None:  # self._htg_valve
        """Set the heating valve relay for this DHW system (13: only)."""

        if not isinstance(device, Device) or device.type != "13":
            raise TypeError(f"{ATTR_DHW_VALVE_HTG} can't be: {device}")

        if self._htg_valve is not None:
            if self._htg_valve is device:
                return
            raise CorruptStateError(
                f"{ATTR_DHW_VALVE_HTG} shouldn't change: {self._htg_valve} to {device}"
            )

        if self._htg_valve is None:
            self._htg_valve = device
            device._set_parent(self, domain="F9")

    @property
    def heating_valve(self) -> Device:  # self._htg_valve
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


class ZoneSchedule:  # 0404
    """Evohome zones have a schedule."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._schedule = Schedule(self)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:

        if False and discover_flag & DISCOVER_STATUS:  # TODO: add back in
            self._loop.create_task(self.get_schedule())  # 0404

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


class Zone(ZoneSchedule, ZoneBase):
    """The Zone class."""

    def __init__(self, ctl, zone_idx, sensor=None, actuators=None) -> None:
        """Create a zone.

        The type of zone may not be known at instantiation. Even when it is known, zones
        are still created without a type before they are subsequently promoted, so that
        both schemes (e.g. eavesdropping, vs probing) are the same.

        In addition, an electric zone may subsequently turn out to be a zone valve zone.
        """
        # _LOGGER.debug("Creating a Zone: %s (%s)", zone_idx, self.__class__)
        super().__init__(ctl, zone_idx)

        # self.id = f"{ctl.id}_{zone_idx}"
        ctl.zones.append(self)
        ctl.zone_by_idx[zone_idx] = self
        # ctl.zone_by_name[self.name] = self

        self.devices = []
        self.device_by_id = {}
        self._sensor = None

        self._heat_demand = None  # Not used by ELE
        self._mode = None
        # self._name = None  # from super()
        self._setpoint = None
        self._temperature = None
        self._zone_config = None

        # these needed here, as we can't use __init__
        self._mix_config = None  # MIX
        self._ufh_setpoint = None  # UFH
        self._window_open = None  # RAD (or: ALL)
        self._actuator_state = None  # ELE, ZON

        self._schedule = Schedule(self)

        if sensor:
            self._set_sensor(sensor)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        # TODO: add code to determine zone type if it doesn't have one, using 0005s
        if discover_flag & DISCOVER_SCHEMA:
            [  # 000C: find the sensor and the actuators, if any
                self._send_cmd("000C", payload=f"{self.idx}{dev_type}")
                for dev_type in ("00", "04")  # CODE_000C_ZONE_TYPE
            ]

        if discover_flag & DISCOVER_PARAMS:
            self._gwy.send_cmd(Command.get_zone_config(self._ctl.id, self.idx))  # 000A
            self._gwy.send_cmd(Command.get_zone_name(self._ctl.id, self.idx))  # 0004

        if discover_flag & DISCOVER_STATUS:
            self._gwy.send_cmd(Command.get_zone_mode(self._ctl.id, self.idx))  # 2349
            for code in ("12B0", "30C9"):  # sadly, no 3150
                self._send_cmd(code)  # , payload=self.idx)

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

    def _set_sensor(self, device: Device):  # self._sensor
        """Set the temp sensor for this zone (one of: 01:, 03:, 04:, 12:, 22:, 34:)."""

        if self._sensor is device:
            return
        elif self._sensor is not None:
            raise CorruptStateError(
                f"{ATTR_ZONE_SENSOR} shouldn't change: {self._sensor} to {device}"
            )

        sensor_types = ("00", "01", "03", "04", "12", "22", "34")
        if not isinstance(device, Device) or device.type not in sensor_types:
            raise TypeError(f"{ATTR_ZONE_SENSOR} can't be: {device}")

        if self._sensor is None:
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
        if _type not in ZONE_CLASSES:
            raise ValueError(f"Not a known zone type: {zone_type}")

        if (
            self._zone_type is not None
            and self._zone_type != _type
            and (self._zone_type != "ELE" and _type != "VAL")
        ):
            raise CorruptStateError(
                f"Zone {self} has a mismatched type: "
                f"old={self._zone_type}, new={_type}"
            )

        self._zone_type = _type
        self.__class__ = ZONE_CLASSES[_type]
        _LOGGER.debug("Zone %s: type now set to %s", self.id, self._zone_type)

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
        #     if self.sensor and self.sensor.temperature:
        #         self._temperature = self.sensor._temp

        if not self._temperature or self._temperature.is_expired:
            return

        elif isinstance(self._temperature.payload, dict):
            return self._msg_payload(self._temperature, ATTR_TEMP)

        elif isinstance(self._temperature.payload, list):
            tmp = [z for z in self._temperature.payload if z["zone_idx"] == self.idx]
            return tmp[0][ATTR_TEMP]

    @property
    def heat_demand(self) -> Optional[float]:
        """Return an estimate of the zone's current heat demand."""
        demands = [
            d.heat_demand
            for d in self.devices
            if hasattr(d, ATTR_HEAT_DEMAND) and d.heat_demand is not None
        ]
        # return max(demands) if demands else None
        return round(sum(demands) / len(demands), 1) if demands else None

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
        return {
            ATTR_ZONE_TYPE: self.heating_type,
            ATTR_ZONE_SENSOR: self._sensor.id if self._sensor else None,
            ATTR_DEVICES: [d.id for d in self.devices],
        }

    @property  # TODO: setpoint
    def params(self) -> dict:
        """Return the zone's configuration (excl. schedule)."""
        return {a: getattr(self, a) for a in ("config", "mode", "name")}

    @property
    def status(self) -> dict:
        """Return the zone's current state."""
        return {a: getattr(self, a) for a in (ATTR_SETPOINT, ATTR_TEMP)}


class ZoneDemand:  # not all zone types call for heat
    """Not all zones call for heat."""

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:  # controller will not respond to this
            self._send_cmd("3150")  # , payload=self.idx

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        demands = [
            d.heat_demand
            for d in self.devices
            if hasattr(d, ATTR_HEAT_DEMAND) and d.heat_demand is not None
        ]
        return max(demands + [0]) if demands else None

    @property
    def status(self) -> dict:
        return {**super().status, ATTR_HEAT_DEMAND: self.heat_demand}


class EleZone(Zone):  # Electric zones (do *not* call for heat)
    """For a small electric load controlled by a relay (never calls for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}11")

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        # if msg.code == "0008":  # ZON zones are ELE zones that also call for heat
        #     self._set_zone_type("VAL")
        if msg.code == "3150":
            raise TypeError("WHAT 1")
        elif msg.code == "3EF0":
            raise TypeError("WHAT 2")


class ValZone(EleZone):  # ZoneDemand
    """For a motorised valve controlled by a BDR91 (will also call for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}0A")

    @property
    def heat_demand(self) -> Optional[float]:  # 0008 (NOTE: not 3150)
        if "0008" in self._msgs:
            return self._msgs["0008"].payload["relay_demand"]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            ATTR_HEAT_DEMAND: self.heat_demand,
        }


class RadZone(ZoneDemand, Zone):
    """For radiators controlled by HR92s or HR80s (will also call for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}08")


class UfhZone(ZoneDemand, Zone):
    """For underfloor heating controlled by an HCE80/HCC80 (will also call for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}09")

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


class MixZone(Zone):
    """For a modulating valve controlled by a HM80 (will also call for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}0B")

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


ZONE_CLASSES = {
    Zone.RAD: RadZone,
    Zone.ELE: EleZone,
    Zone.VAL: ValZone,
    Zone.UFH: UfhZone,
    Zone.MIX: MixZone,
    Zone.DHW: DhwZone,
}
