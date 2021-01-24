#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - The evohome-compatible zones."""

from abc import ABCMeta, abstractmethod
import asyncio
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
    _dev_mode_,
)
from .devices import Device, Entity, _payload
from .exceptions import CorruptStateError
from .helpers import dtm_to_hex

DEV_MODE = _dev_mode_

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


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

    def __init__(self, evo, zone_idx) -> None:
        _LOGGER.debug("Creating a Zone: %s_%s (%s)", evo.id, zone_idx, self.__class__)
        super().__init__(evo._gwy)

        self.id = f"{evo.id}_{zone_idx}"
        self.idx = zone_idx

        self._name = None
        self._zone_type = None

        self._evo = evo
        self._ctl = evo._ctl

    # def __repr__(self) -> str:
    #     return json.dumps(self.schema, indent=2)

    def __str__(self) -> str:
        return f"{self.id} ({self._zone_type})"

    @abstractmethod
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        raise NotImplementedError

    def _handle_msg(self, msg) -> bool:
        # super()._handle_msg(msg)
        pass

        # else:
        #     assert False, f"Unknown packet ({msg.verb}/{msg.code}) for {self.id}"

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
    # def ._set_zone_type(self, value: str) -> None:
    #     """Set the type of the zone/DHW (e.g. electric_zone, stored_dhw)."""
    #     raise NotImplementedError


class HeatDemand:  # 3150
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._heat_demand = None

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "3150" and msg.verb == " I":
            self._heat_demand = msg

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return _payload(self._heat_demand, "heat_demand")

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "heat_demand": self.heat_demand,
        }


class DhwZone(ZoneBase, HeatDemand):
    """The DHW class."""

    def __init__(self, ctl, sensor=None, dhw_valve=None, htg_valve=None) -> None:
        super().__init__(ctl, "HW")

        ctl._set_dhw(self)

        self._sensor = None
        # self._dhw_valve = None
        # self._htg_valve = None

        self.heating_type = "DHW"

        self._dhw_mode = None
        self._dhw_params = None
        self._relay_demand = None
        self._relay_failsafe = None
        self._temp = None

        if sensor:
            self._set_sensor(sensor)
        if dhw_valve:
            self._set_dhw_valve(dhw_valve)
        if htg_valve:
            self._set_htg_valve(htg_valve)

    def _discover(self, discover_flags=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)

        # if False and _dev_mode_ and self.idx == "FA":  # dev/test code
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
            self._temp = msg

        elif msg.code == "1F41":
            self._setpoint_status = msg

        # elif msg.code in ("1100", "3150", "3B00"):
        #     pass

    @property
    def sensor(self) -> Device:
        return self._sensor

    def _set_sensor(self, device: Device) -> None:  # self._sensor
        """Set the temp sensor for this DHW system (07: only)."""

        if self._sensor != device and self._sensor is not None:
            raise CorruptStateError(
                f"{ATTR_ZONE_SENSOR} shouldn't change: {self._sensor} to {device}"
            )

        if not isinstance(device, Device) or device.type != "07":
            raise TypeError(f"{ATTR_ZONE_SENSOR} can't be: {device}")

        if self._sensor is None:
            self._sensor = device
            device._set_parent(self, domain="FA")

    @property
    def hotwater_valve(self) -> Device:
        return self._evo._dhw_valve

    @property
    def heating_valve(self) -> Device:
        return self._evo._htg_valve

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return _payload(self._relay_demand, "relay_demand")

    @property  # only seen with FC, but seems should pair with 0008?
    def relay_failsafe(self) -> Optional[float]:  # 0009
        return _payload(self._relay_failsafe, "relay_failsafe")

    @property
    def dhw_config(self) -> Optional[dict]:  # 10A0
        return _payload(self._dhw_params)

    @property
    def mode(self) -> Optional[dict]:  # 1F41
        return _payload(self._dhw_mode)

    @property
    def name(self) -> str:
        return "Stored HW"

    @property
    def setpoint(self) -> Optional[float]:  # 1F41
        return _payload(self._dhw_mode, "setpoint")

    @property
    def temperature(self) -> Optional[float]:  # 1260
        return _payload(self._temp, "temperature")

    @property
    def schema(self) -> dict:
        """Return the stored HW's schema."""

        return {
            ATTR_DHW_SENSOR: self.sensor.id if self.sensor else None,
            ATTR_DHW_VALVE: self.hotwater_valve.id if self.hotwater_valve else None,
            ATTR_DHW_VALVE_HTG: self.heating_valve.id if self.heating_valve else None,
        }

    @property  # setpoint, config, mode (not schedule)
    def params(self) -> dict:
        return {
            "dhw_params": self._dhw_params,
        }

    @property  # temp, open_windows
    def status(self) -> dict:
        return {
            "temperature": self._temp,
            "dhw_mode": self._dhw_mode,
        }

    async def cancel_override(self) -> bool:  # 1F41
        """Reset the DHW to follow its schedule."""
        raise NotImplementedError

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
            payload = f"00{state}{mode}FFFFFF{dtm_to_hex(until)}"

        self._send_cmd("1F41", verb=" W", payload=payload)
        return False

    async def reset_config(self) -> bool:  # 10A0
        """Reset the DHW parameters to their default values."""
        raise NotImplementedError

    async def set_config(self, setpoint, overrun=None, differential=None) -> bool:
        """Set the DHW parameters."""
        raise NotImplementedError


class ZoneSchedule:
    """Evohome zones have a schedule."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._schedule = Schedule(self)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:

        if discover_flag & DISCOVER_STATUS:
            # asyncio.create_task(self.get_schedule())  # 0404
            pass

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "0404" and msg.verb == "RP":
            _LOGGER.debug("Zone(%s).update: Received RP/0404 (schedule)", self.id)

    async def get_schedule(self, force_refresh=None) -> Optional[dict]:
        schedule = await self._schedule.get_schedule(force_refresh=force_refresh)
        if schedule:
            return schedule["schedule"]

    async def set_schedule(self, schedule) -> None:
        schedule = {"zone_idx": self.idx, "schedule": schedule}
        await self._schedule.set_schedule(schedule)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "schedule": self._schedule.schedule.get("schedule"),
        }


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

        self._mode = None
        # self._name = None  # from super()
        self._setpoint = None
        self._temp = None
        self._zone_config = None

        # these needed here, as we can't use __init__
        self._mix_config = None
        self._ufh_setpoint = None
        self._window_open = None

        self._schedule = Schedule(self)

        if sensor:
            self._set_sensor(sensor)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if DEV_MODE and self.idx == "99":  # dev/test code
            asyncio.create_task(  # TODO: test/dev only
                self.async_cancel_override()
                # self.async_set_override(
                #     setpoint=15.9,
                #     mode="AdvancedOverride",
                #     # until=dt_now() + td(minutes=120)
                # )
            )

        # TODO: add code to determine zone type if it doesn't have one, using 0005s

        [  # 000C: find the sensor and the actuators, if any
            self._send_cmd("000C", payload=f"{self.idx}{dev_type}")
            for dev_type in ("00", "04")  # CODE_000C_ZONE_TYPE
        ]  # TODO: use 08, not 00

        # start collecting the schedule
        # self._schedule.req_schedule()  # , restart=True) start collecting schedule

        for code in ("0004", "000A", "2349", "30C9"):  # sadly, no 3150
            self._send_cmd(code)  # , payload=self.idx)

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if isinstance(msg.payload, list):
            assert self.idx in [d["zone_idx"] for d in msg.payload]

        if msg.code == "0004":
            self._name = msg

        # not UFH (it seems), but ELE or VAL; and possibly a MIX support 0008 too
        elif msg.code in ("0008", "0009"):  # TODO: how to determine is/isn't MIX?
            assert msg.src.type in ("01", "13"), msg.src.type  # 01 as a stat
            assert self._zone_type in (None, "ELE", "VAL"), self._zone_type

            if self._zone_type is None:
                self._set_zone_type("ELE")  # might eventually be: "VAL"

        elif msg.code == "000A":
            self._zone_config = msg

        elif msg.code == "2309" and msg.verb in (" I", "RP"):  # setpoint
            assert msg.src.type == "01", "coding error"
            self._setpoint = msg

        elif msg.code == "2349" and msg.verb in (" I", "RP"):  # mode, setpoint
            assert msg.src.type == "01", "coding error"
            self._mode = msg
            self._setpoint = msg

        elif msg.code == "30C9" and msg.verb in (" I", "RP"):  # used by sensor matching
            assert msg.src.type in DEVICE_HAS_ZONE_SENSOR + ("01",), "coding error"
            self._temp = msg

        elif msg.code == "3150":  # TODO: and msg.verb in (" I", "RP")?
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

        if self._sensor != device and self._sensor is not None:
            raise CorruptStateError(
                f"{ATTR_ZONE_SENSOR} shouldn't change: {self._sensor} to {device}"
            )

        sensor_types = ("00", "01", "03", "04", "12", "22", "34")
        if not isinstance(device, Device) or device.type not in sensor_types:
            raise TypeError(f"{ATTR_ZONE_SENSOR} can't be: {device}")

        if self._sensor is None:
            self._sensor = device
            device._set_parent(self)

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

        if self._zone_type is not None:
            if self._zone_type != _type and (
                self._zone_type != "ELE" and _type != "VAL"
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
    def heat_demand(self) -> Optional[float]:
        demands = [
            d.heat_demand
            for d in self.devices
            if hasattr(d, "heat_demand") and d.heat_demand is not None
        ]
        # return max(demands) if demands else None
        return round(sum(demands) / len(demands), 1) if demands else None

    @property
    def mode(self) -> Optional[dict]:  # 2349
        if not self._mode or self._mode.is_expired:
            return

        elif isinstance(self._mode.payload, dict):
            return _payload(self._mode)

        elif isinstance(self._mode.payload, list):
            tmp = [z for z in self._mode.payload if z["zone_idx"] == self.idx]
            return {k: v for k, v in tmp[0].items() if k[:1] != "_" and k != "zone_idx"}

    # async def get_name(self, force_refresh=None) -> Optional[str]:
    #     """Return the name of the zone."""
    #     if not force_refresh and self._name is not None:
    #         return _payload(self._name, "name")

    #     self._name = None
    #     self._send_cmd("0004", payload=f"{self.idx}00")
    #     while self._name is None:
    #         await asyncio.sleep(0.05)

    #     return _payload(self._name, "name")

    @property
    def name(self) -> Optional[str]:
        """Return the name of the zone."""
        return _payload(self._name, "name")

    # @name.setter
    # def name(self, value) -> Optional[str]:
    #     """Set the name of the zone."""
    #     return

    @property
    def setpoint(self) -> Optional[float]:  # 2309 (2349 is a superset of 2309)
        if not self._setpoint or self._setpoint.is_expired:
            return

        elif isinstance(self._setpoint.payload, dict):
            return _payload(self._setpoint, "setpoint")

        elif isinstance(self._setpoint.payload, list):
            _zone = [z for z in self._setpoint.payload if z["zone_idx"] == self.idx]
            return _zone[0]["setpoint"]

    @setpoint.setter
    def setpoint(self, value) -> None:
        """Set the target temperature, until the next scheduled setpoint."""
        if value is None:
            self.cancel_override()
        else:
            self.set_override(mode="advanced_override", setpoint=value)

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        if not self._temp or self._temp.is_expired:
            if self.sensor and self.sensor.temperature:
                self._temp = self.sensor._temp

        if not self._temp or self._temp.is_expired:
            return

        elif isinstance(self._temp.payload, dict):
            return _payload(self._temp, "temperature")

        elif isinstance(self._temp.payload, list):
            tmp = [z for z in self._temp.payload if z["zone_idx"] == self.idx]
            return tmp[0]["temperature"]

    @property
    def zone_config(self) -> Optional[dict]:  # 000A
        if not self._zone_config or self._zone_config.is_expired:
            return

        elif isinstance(self._zone_config.payload, dict):
            return _payload(self._zone_config)

        elif isinstance(self._zone_config.payload, list):
            tmp = [z for z in self._zone_config.payload if z["zone_idx"] == self.idx]
            return {k: v for k, v in tmp[0].items() if k[:1] != "_" and k != "zone_idx"}

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
            payload = f"{self.idx}{setpoint}{mode}FFFFFF{dtm_to_hex(until)}"

        self._send_cmd("2349", verb=" W", payload=payload)

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

        ATTR_NAME = "name"  # TODO
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


class ZoneDemand:  # not all zone types call for heat
    """Not all zones call for heat."""

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

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
        return {
            **super().status,
            ATTR_HEAT_DEMAND: self.heat_demand,
        }


class EleZone(Zone):  # Electric zones (do *not* call for heat)
    """For a small electric load controlled by a relay (never calls for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}11")

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "3150":  # ZV zones are Elec zones that also call for heat
            self._set_zone_type("VAL")

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


class ValZone(ZoneDemand, EleZone):
    """For a motorised valve controlled by a BDR91 (will also call for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}0A")


class RadZone(ZoneDemand, Zone):
    """For radiators controlled by HR92s or HR80s (will also call for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}08")

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "12B0":
            self._window_open = msg

    @property
    def window_open(self) -> Optional[bool]:  # 12B0
        return _payload(self._window_open, "window_open")  # TODO: doesn't work >1 TRV

    @property
    def status(self) -> dict:
        return {
            **super().status,
            ATTR_OPEN_WINDOW: self.window_open,
        }


class UfhZone(ZoneDemand, Zone):
    """For underfloor heating controlled by an HCE80/HCC80 (will also call for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}09")

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "22C9" and msg.verb == " I":
            self._ufh_setpoint = msg

    @property
    def ufh_setpoint(self) -> Optional[float]:  # 22C9
        return _payload(self._ufh_setpoint, "setpoint")

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "ufh_setpoint": self.ufh_setpoint,
        }


class MixZone(Zone):
    """For a modulating valve controlled by a HM80 (will also call for heat)."""

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)
        self._send_cmd("000C", payload=f"{self.idx}0B")

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "1030" and msg.verb == " I":
            self._mix_config = msg

    @property
    def mix_config(self) -> dict:
        return _payload(self._mix_config)

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
