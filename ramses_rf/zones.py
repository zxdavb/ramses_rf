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

from .const import Discover, __dev_mode__
from .devices import (
    BdrSwitch,
    Controller,
    Device,
    DhwSensor,
    Temperature,
    TrvActuator,
    UfhController,
)
from .entities import Entity, discover_decorator
from .protocol import CODE_API_MAP, Command, Schedule
from .protocol.const import (
    _000C_DEVICE,
    ATTR_DEVICES,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_HEAT_DEMAND,
    ATTR_NAME,
    ATTR_RELAY_DEMAND,
    ATTR_RELAY_FAILSAFE,
    ATTR_SETPOINT,
    ATTR_TEMP,
    ATTR_WINDOW_OPEN,
    ATTR_ZONE_SENSOR,
    ATTR_ZONE_TYPE,
    ZONE_MODE,
    ZONE_TYPE_MAP,
    ZONE_TYPE_SLUGS,
)
from .protocol.exceptions import CorruptStateError
from .protocol.transport import PacketProtocolPort

# from .ramses import RAMSES_ZONES, RAMSES_ZONES_ALL
from .protocol import I_, RP, RQ, W_  # noqa: F401, isort: skip
from .protocol import (  # noqa: F401, isort: skip
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
    _0B04,
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

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


ZONE_TYPE = SimpleNamespace(
    DHW="DHW",  # Stored HW (not a zone)
    ELE="ELE",  # Electric
    MIX="MIX",  # Mix valve
    RAD="RAD",  # Radiator
    UFH="UFH",  # Underfloor heating
    VAL="VAL",  # Zone valve
)


class ZoneBase(Entity):
    """The Zone/DHW base class."""

    # _TYPE = None  # NOTE: this would cause problems

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
        if not isinstance(other, ZoneBase):
            return NotImplemented
        return self.idx < other.idx

    def _start_discovery(self) -> None:

        self._gwy._add_task(  # 0005/000C pkts
            self._discover, discover_flag=Discover.SCHEMA, delay=1, period=3600 * 24
        )
        self._gwy._add_task(
            self._discover, discover_flag=Discover.PARAMS, delay=3, period=3600 * 6
        )
        self._gwy._add_task(
            self._discover, discover_flag=Discover.STATUS, delay=5, period=60 * 15
        )

    def _set_system(self, parent, zone_idx):
        """Set the zone's parent system, after validating it."""

        from .systems import System  # to prevent circular references

        try:
            if zone_idx != "HW" and int(zone_idx, 16) >= parent.max_zones:
                raise ValueError(f"{self}: invalid zone_idx {zone_idx} (> max_zones")
        except (TypeError, ValueError):
            raise TypeError(f"{self}: invalid zone_idx {zone_idx}")

        if not isinstance(parent, System):
            raise TypeError(f"{self}: parent must be a System, not {parent}")

        if zone_idx != "HW":  # or: FA?
            if self.idx in parent.zone_by_idx:
                raise LookupError(f"{self}: duplicate zone_idx: {zone_idx}")
            parent.zone_by_idx[zone_idx] = self
            parent.zones.append(self)

        self._ctl = parent._ctl

        return parent, parent._ctl

    def _make_cmd(self, code, **kwargs) -> None:
        payload = kwargs.pop("payload", f"{self.idx}00")
        super()._make_cmd(code, self._ctl.id, payload, **kwargs)

    @property
    def heating_type(self) -> Optional[str]:
        """Return the type of the zone/DHW (e.g. electric_zone, stored_dhw)."""
        return self._TYPE


class ZoneSchedule:  # 0404  # TODO: add for DHW
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._schedule = None

    # def _discover(self, discover_flag=Discover.ALL) -> None:
    #    super()._discover(discover_flag=discover_flag)

    #     if discover_flag & Discover.STATUS:  # TODO: add back in
    #         self._loop.create_task(self.get_schedule())  # 0404

    #     def _handle_msg(self, msg) -> None:
    #     super()._handle_msg(msg)

    #     if msg.code == _0404 and msg.verb != RQ:
    #         _LOGGER.debug("Zone(%s): Received RP/0404 (schedule) pkt", self)

    async def get_schedule(self, force_refresh=None) -> Optional[dict]:
        await self._schedule.get_schedule(force_refresh=force_refresh)
        return self.schedule

    async def set_schedule(self, schedule) -> None:
        schedule = {"zone_idx": self.idx, "schedule": schedule}
        await self._schedule.set_schedule(schedule)

    @property
    def schedule(self) -> dict:
        if self._schedule is None:
            try:
                if packets := self._msgz[_0404][RP]:
                    self._schedule = Schedule.create_from_pkts(self, packets.values())
            except KeyError:
                self._schedule = Schedule(self)

        if self._schedule.schedule:
            return self._schedule.schedule.get("schedule")

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "schedule": self.schedule,
        }


class RelayDemand:  # 0008
    """Not all zones call for heat."""

    def _discover(self, discover_flag=Discover.ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & Discover.STATUS:
            self._send_cmd(Command.get_relay_demand(self._ctl.id, zone_idx=self.idx))

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        # if _0008 in self._msgs:
        #     return self._msgs[_0008].payload[ATTR_RELAY_DEMAND]
        return self._msg_value(_0008, key=ATTR_RELAY_DEMAND)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            ATTR_RELAY_DEMAND: self.relay_demand,
        }


class DhwZone(ZoneSchedule, ZoneBase):  # CS92A  # TODO: add Schedule
    """The DHW class."""

    _TYPE = ZONE_TYPE.DHW

    def __init__(
        self, ctl, zone_idx="HW", sensor=None, dhw_valve=None, htg_valve=None
    ) -> None:
        super().__init__(ctl, zone_idx)

        ctl._set_dhw(self)
        # if profile == ZONE_TYPE.DHW and evo.dhw is None:
        #     evo.dhw = zone

        self._dhw_sensor = None
        self._dhw_valve = None
        self._htg_valve = None

        self._zone_type = ZONE_TYPE.DHW

        if sensor:
            self._set_sensor(sensor)
        if dhw_valve:
            self._set_dhw_valve(dhw_valve)
        if htg_valve:
            self._set_htg_valve(htg_valve)

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        def send_code(code, minutes=2) -> None:
            """Don't send an api if there is a recent msg in the database.

            Primarily for HA startup (restore_cache) to avoid exceeding RF duty cycles.
            """

            if (
                not (msg := self._msgs.get(code))
                or msg._pkt.dtm + td(minutes=minutes) < dt.now()
            ):
                self._send_cmd(CODE_API_MAP[f"{RQ}/{code}"](self._ctl.id))

        if discover_flag & Discover.SCHEMA:
            for dev_type in (
                f"00{_000C_DEVICE.DHW_SENSOR}",
                f"00{_000C_DEVICE.DHW}",
                f"01{_000C_DEVICE.DHW}",
            ):
                try:
                    _ = self._msgz[_000C][RP][dev_type]
                except KeyError:
                    self._make_cmd(_000C, payload=dev_type)

        if discover_flag & Discover.PARAMS:
            # self._send_cmd(Command.get_dhw_params(self._ctl.id))
            [send_code(code, 15) for code in (_10A0,)]

        if discover_flag & Discover.STATUS:
            # self._send_cmd(Command.get_dhw_mode(self._ctl.id))
            # self._send_cmd(Command.get_dhw_temp(self._ctl.id))
            [send_code(code) for code in (_1260, _1F41)]

        # start collecting the schedule
        # self._schedule.req_schedule()  # , restart=True) start collecting schedule

    def _handle_msg(self, msg) -> None:
        assert msg.src is self._ctl, f"msg inappropriately routed to {self}"
        super()._handle_msg(msg)

        if msg.code == _000C and msg.payload["devices"]:
            LOOKUP = {
                ATTR_DHW_SENSOR: self._set_sensor,
                ATTR_DHW_VALVE: self._set_dhw_valve,
                ATTR_DHW_VALVE_HTG: self._set_htg_valve,
            }
            devices = [
                # self._gwy._get_device(d, ctl_id=msg.src.id, domain_id=...)
                self._gwy._get_device(d)  # ctl_id=self._ctl.id, domain_id=self.idx)
                for d in msg.payload["devices"]
            ]

            LOOKUP[msg.payload["device_class"]](devices[0])

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
        return self._msg_value(_10A0)

    @property
    def mode(self) -> Optional[dict]:  # 1F41
        return self._msg_value(_1F41)

    @property
    def setpoint(self) -> Optional[float]:  # 10A0
        return self._msg_value(_10A0, key=ATTR_SETPOINT)

    @setpoint.setter
    def setpoint(self, value) -> None:  # 10A0
        return self.set_config(setpoint=value)

    @property
    def temperature(self) -> Optional[float]:  # 1260
        return self._msg_value(_1260, key=ATTR_TEMP)

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._msg_value(_3150, key=ATTR_HEAT_DEMAND)

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return self._msg_value(_0008, key=ATTR_RELAY_DEMAND)

    @property  # only seen with FC, but seems should pair with 0008?
    def relay_failsafe(self) -> Optional[float]:  # 0009
        return self._msg_value(_0009, key=ATTR_RELAY_FAILSAFE)

    def set_mode(self, mode=None, active=None, until=None) -> Task:
        """Set the DHW mode (mode, active, until)."""
        return self._send_cmd(
            Command.set_dhw_mode(self._ctl.id, mode=mode, active=active, until=until)
        )

    def set_boost_mode(self) -> Task:
        """Enable DHW for an hour, despite any schedule."""
        return self.set_mode(
            mode=ZONE_MODE.temporary_override, active=True, until=dt.now() + td(hours=1)
        )

    def reset_mode(self) -> Task:  # 1F41
        """Revert the DHW to following its schedule."""
        return self.set_mode(mode=ZONE_MODE.follow_schedule)

    def set_config(self, setpoint=None, overrun=None, differential=None) -> Task:
        """Set the DHW parameters (setpoint, overrun, differential)."""
        # dhw_params = self._msg_value(_10A0)
        # if setpoint is None:
        #     setpoint = dhw_params[ATTR_SETPOINT]
        # if overrun is None:
        #     overrun = dhw_params["overrun"]
        # if differential is None:
        #     setpoint = dhw_params["differential"]

        return self._send_cmd(
            Command.set_dhw_params(self._ctl.id, setpoint, overrun, differential)
        )

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
    """The Zone class for all zone types (but not DHW)."""

    _TYPE = None  # Unknown

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

        # self._schedule = Schedule(self)  # TODO:

        if sensor:
            self._set_sensor(sensor)

    @discover_decorator  # NOTE: can mean is double-decorated
    def _discover(self, discover_flag=Discover.ALL) -> None:
        def send_code(code, minutes=2) -> None:
            """Don't send an api if there is a recent msg in the database.

            Primarily for HA startup (restore_cache) to avoid exceeding RF duty cycles.
            """

            if (
                not (msg := self._msgs.get(code))
                or msg._pkt.dtm + td(minutes=minutes) < dt.now()
            ):
                self._send_cmd(CODE_API_MAP[f"{RQ}/{code}"](self._ctl.id, self.idx))

        # TODO: add code to determine zone type if it doesn't have one, using 0005s
        if discover_flag & Discover.SCHEMA:
            for dev_type in (_000C_DEVICE.ALL, _000C_DEVICE.ALL_SENSOR):
                try:
                    _ = self._msgz[_000C][RP][f"{self.idx}{dev_type}"]
                except KeyError:
                    self._make_cmd(_000C, payload=f"{self.idx}{dev_type}")

        if discover_flag & Discover.PARAMS:
            # self._send_cmd(Command.get_zone_config(self._ctl.id, self.idx))
            # self._send_cmd(Command.get_zone_name(self._ctl.id, self.idx))
            [send_code(code, 15) for code in (_0004, _000A)]

        if discover_flag & Discover.STATUS:  # every 1h, CTL will not respond to a 3150
            # self._send_cmd(Command.get_zone_mode(self._ctl.id, self.idx))
            # self._send_cmd(Command.get_zone_temp(self._ctl.id, self.idx))
            # self._send_cmd(Command.get_zone_window_state(self._ctl.id, self.idx))
            [send_code(code) for code in (_12B0, _2349, _30C9)]

        # start collecting the schedule
        # self._schedule.req_schedule()  # , restart=True) start collecting schedule

    def _handle_msg(self, msg) -> None:
        # if msg.code in _000C and msg.src.type == "02":  # DEX
        #     if self._ufc is None
        #         self._ufc = msg.src
        #     else:
        #         raise()

        assert (msg.src is self._ctl or msg.src.type == "02") and (  # DEX
            isinstance(msg.payload, dict)
            or [d for d in msg.payload if d["zone_idx"] == self.idx]
        ), f"msg inappropriately routed to {self}"

        assert (msg.src is self._ctl or msg.src.type == "02") and (  # DEX
            isinstance(msg.payload, list) or msg.payload["zone_idx"] == self.idx
        ), f"msg inappropriately routed to {self}"

        super()._handle_msg(msg)

        if msg.code == _000C and msg.payload["devices"]:

            # TODO: testing this concept, hoping to learn device_id of UFC
            if msg.payload["_device_class"] == _000C_DEVICE.UFH:
                self._make_cmd(_000C, payload=f"{self.idx}{_000C_DEVICE.UFH}")

            devices = [
                # self._gwy._get_device(d, ctl_id=msg.src.id, domain_id=...)
                self._gwy._get_device(d)  # ctl_id=self._ctl.id, domain_id=self.idx)
                for d in msg.payload["devices"]
            ]

            if msg.payload["_device_class"] == _000C_DEVICE.ALL_SENSOR:
                self._set_sensor(devices[0])  # incl. devices[0]._set_parent(self)

            elif msg.payload["_device_class"] == _000C_DEVICE.ALL:
                [d._set_parent(self) for d in devices]  # if d is not None]

        if msg._gwy.config.enable_eavesdrop and self._zone_type in (None, "ELE"):
            self._eavesdrop_zone_type(msg)

    def _eavesdrop_zone_type(self, msg, prev=None) -> None:
        """TODO.

        There are three ways to determine the type of a zone:
        1. Use a 0005 packet (deterministic)
        2. Eavesdrop (non-deterministic, slow to converge)
        3. via a config file (a schema)
        """
        # ELE/VAL, but not UFH (it seems)
        if msg.code in (_0008, _0009):
            assert self._zone_type in (None, "ELE", "VAL", "MIX"), self._zone_type

            if self._zone_type is None:
                self._set_zone_type("ELE")  # might eventually be: "VAL"

        elif msg.code == _3150:  # TODO: and msg.verb in (I_, RP)?
            # MIX/ELE don't 3150
            assert self._zone_type in (None, "RAD", "UFH", "VAL"), self._zone_type

            if isinstance(msg.src, TrvActuator):
                self._set_zone_type("RAD")
            elif isinstance(msg.src, BdrSwitch):
                self._set_zone_type("VAL")
            elif isinstance(msg.src, UfhController):
                self._set_zone_type("UFH")

    def _msg_value(self, *args, **kwargs):
        return super()._msg_value(*args, **kwargs, zone_idx=self.idx)

    @property  # TODO:
    def actuators(self) -> Device:
        try:
            return self._msgz["000C"]["RP"][f"{self.idx}00"].payload["devices"]
        except LookupError:
            pass

    @property
    def sensor(self) -> Device:
        try:
            return self._gwy.device_by_id[
                self._msgz["000C"]["RP"][f"{self.idx}04"].payload["devices"][0]
            ]
        except LookupError:
            return self._sensor

    def _set_sensor(self, device: Device) -> None:  # self._sensor
        """Set the temp sensor for this zone (one of: 01:, 03:, 04:, 12:, 22:, 34:)."""

        if self._sensor is device:
            return
        if self._sensor is not None:
            raise CorruptStateError(
                f"{self} changed {ATTR_ZONE_SENSOR}: {self._sensor} to {device}"
            )

        if not isinstance(device, (Controller, Temperature)):
            # TODO: or not hasattr(device, "temperature")
            raise TypeError(f"{self}: {ATTR_ZONE_SENSOR} can't be: {device}")

        self._sensor = device
        device._set_parent(self)  # , domain=self.idx)

    @property
    def heating_type(self) -> Optional[str]:

        if self._zone_type is not None:  # isinstance(self, ???)
            return ZONE_TYPE_MAP.get(self._zone_type)

    def _set_zone_type(self, zone_type: str):  # self._zone_type
        """Set the zone's type, after validating it.

        There are two possible sources for the type of a zone:
        1. eavesdropping packet codes
        2. analyzing child devices

        Both will execute a zone.type = type (i.e. via this setter).
        """

        _type = ZONE_TYPE_SLUGS.get(zone_type, zone_type)
        if _type not in ZONE_BY_TYPE:
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
        self.__class__ = ZONE_BY_TYPE[_type]
        self._discover(discover_flag=Discover.ALL)  # TODO: needs tidyup (ref #67)

    @property
    def name(self) -> Optional[str]:  # 0004
        """Return the name of the zone."""
        return self._msg_value(_0004, key=ATTR_NAME)

    @name.setter
    def name(self, value) -> Optional[str]:
        """Set the name of the zone."""
        self._send_cmd(Command.set_zone_name(self._ctl.id, self.idx, value))

    @property
    def config(self) -> Optional[dict]:  # 000A
        return self._msg_value(_000A)

    @property
    def mode(self) -> Optional[dict]:  # 2349
        return self._msg_value(_2349)

    @property
    def setpoint(self) -> Optional[float]:  # 2309 (2349 is a superset of 2309)
        return self._msg_value((_2309, _2349), key=ATTR_SETPOINT)

    @setpoint.setter
    def setpoint(self, value) -> None:  # 000A/2309
        """Set the target temperature, until the next scheduled setpoint."""
        if value is None:
            self.reset_mode()
        else:
            self._send_cmd(Command.set_zone_setpoint(self._ctl.id, self.idx, value))

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        return self._msg_value(_30C9, key=ATTR_TEMP)

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

    def _get_temp(self) -> Task:  # TODO: messy - needs tidy up
        """Get the zone's latest temp from the Controller."""
        return self._send_cmd(Command.get_zone_temp(self._ctl.id, self.idx))

    def reset_config(self) -> Task:  # 000A
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
        return self._send_cmd(cmd)

    def reset_mode(self) -> Task:  # 2349
        """Revert the zone to following its schedule."""
        return self.set_mode(mode=ZONE_MODE.follow_schedule)

    def set_frost_mode(self) -> Task:  # 2349
        """Set the zone to the lowest possible setpoint, indefinitely."""
        return self.set_mode(mode=ZONE_MODE.permanent_override, setpoint=5)  # TODO

    def set_mode(self, mode=None, setpoint=None, until=None) -> Task:  # 2309/2349
        """Override the zone's setpoint for a specified duration, or indefinitely."""
        if mode is None and until is None:  # Hometronics doesn't support 2349
            cmd = Command.set_zone_setpoint(self._ctl.id, self.idx, setpoint)
        else:
            cmd = Command.set_zone_mode(self._ctl.id, self.idx, mode, setpoint, until)
        return self._send_cmd(cmd)

    def set_name(self, name) -> Task:
        """Set the zone's name."""
        return self._send_cmd(Command.set_zone_name(self._ctl.id, self.idx, name))

    @property
    def schema(self) -> dict:
        """Return the zone's schema (type, devices)."""
        if not self._sensor:
            sensor_schema = None
        elif getattr(self._sensor, "_fake_30C9", None) is None:
            # NOTE: CTL (as sensor) won't have this attr...
            sensor_schema = self._sensor.id
        else:
            sensor_schema = {
                "device_id": self._sensor.id,
                "is_faked": self._sensor._fake_30C9,
            }

        return {
            "_name": self.name,
            ATTR_ZONE_TYPE: self.heating_type,
            ATTR_ZONE_SENSOR: sensor_schema,
            ATTR_DEVICES: [d.id for d in self.devices],
            "_sensor": self.sensor.id if self.sensor else None,
            "_actuators": self.actuators,
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

    _TYPE = ZONE_TYPE.ELE

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        # NOTE: we create, then promote, so shouldn't (can't) super() initially
        super()._discover(discover_flag=discover_flag)

        if discover_flag & Discover.SCHEMA:
            try:
                _ = self._msgz[_000C][RP][f"{self.idx}{_000C_DEVICE.ELE}"]
            except KeyError:
                self._make_cmd(_000C, payload=f"{self.idx}{_000C_DEVICE.ELE}")

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        # if msg.code == _0008:  # ZON zones are ELE zones that also call for heat
        #     self._set_zone_type("VAL")
        if msg.code == _3150:
            raise TypeError("WHAT 1")
        elif msg.code == _3EF0:
            raise TypeError("WHAT 2")

    @property
    def heat_demand(self) -> None:  # Electric zones (do *not* call for heat)
        """Return None as the zone's heat demand, electric zones don't call for heat."""
        return


class MixZone(Zone):  # HM80  # TODO: 0008/0009/3150
    """For a modulating valve controlled by a HM80 (will also call for heat).

    Note that HM80s are listen-only devices.
    """

    _TYPE = ZONE_TYPE.MIX

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        # NOTE: we create, then promote, so shouldn't (can't) super() initially
        super()._discover(discover_flag=discover_flag)

        if discover_flag & Discover.SCHEMA:
            try:
                _ = self._msgz[_000C][RP][f"{self.idx}{_000C_DEVICE.MIX}"]
            except KeyError:
                self._make_cmd(_000C, payload=f"{self.idx}{_000C_DEVICE.MIX}")

        if discover_flag & Discover.PARAMS:
            self._send_cmd(Command.get_mix_valve_params(self._ctl.id, self.idx))

    @property
    def mix_config(self) -> dict:  # 1030
        return self._msg_value(_1030)

    @property
    def params(self) -> dict:
        return {
            **super().status,
            "mix_config": self.mix_config,
        }


class RadZone(Zone):  # HR92/HR80
    """For radiators controlled by HR92s or HR80s (will also call for heat)."""

    _TYPE = ZONE_TYPE.RAD

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        # NOTE: we create, then promote, so shouldn't (can't) super() initially
        super()._discover(discover_flag=discover_flag)

        if discover_flag & Discover.SCHEMA:
            try:
                _ = self._msgz[_000C][RP][f"{self.idx}{_000C_DEVICE.RAD}"]
            except KeyError:
                self._make_cmd(_000C, payload=f"{self.idx}{_000C_DEVICE.RAD}")


class UfhZone(Zone):  # HCC80/HCE80  # TODO: needs checking
    """For underfloor heating controlled by an HCE80/HCC80 (will also call for heat)."""

    _TYPE = ZONE_TYPE.UFH

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        # NOTE: we create, then promote, so shouldn't (can't) super() initially
        super()._discover(discover_flag=discover_flag)

        if discover_flag & Discover.SCHEMA:
            try:
                _ = self._msgz[_000C][RP][f"{self.idx}{_000C_DEVICE.UFH}"]
            except KeyError:
                self._make_cmd(_000C, payload=f"{self.idx}{_000C_DEVICE.UFH}")

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        """Return the zone's heat demand, estimated from its devices' heat demand."""
        return self._msg_value(_3150, key=ATTR_HEAT_DEMAND)

    @property
    def ufh_setpoint(self) -> Optional[float]:  # 22C9
        return self._msg_value(_22C9, key=ATTR_SETPOINT)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "ufh_setpoint": self.ufh_setpoint,
        }


class ValZone(EleZone):  # BDR91A/T
    """For a motorised valve controlled by a BDR91 (will also call for heat)."""

    _TYPE = ZONE_TYPE.VAL

    # def __init__(self, *args, **kwargs) -> None:  # can't use this here

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        # NOTE: we create, then promote, so shouldn't (can't) super() initially
        super()._discover(discover_flag=discover_flag)

        if discover_flag & Discover.SCHEMA:
            try:
                _ = self._msgz[_000C][RP][f"{self.idx}{_000C_DEVICE.VAL}"]
            except KeyError:
                self._make_cmd(_000C, payload=f"{self.idx}{_000C_DEVICE.VAL}")

    @property
    def heat_demand(self) -> Optional[float]:  # 0008 (NOTE: not 3150)
        """Return the zone's heat demand, using relay demand as a proxy."""
        return self.relay_demand


_TYPE = "_TYPE"
ZONE_BY_TYPE = {
    getattr(c[1], _TYPE): c[1]
    for c in getmembers(
        modules[__name__],
        lambda m: isclass(m) and m.__module__ == __name__ and hasattr(m, _TYPE),
    )
}  # e.g. "RAD": RadZone


def create_zone(evo, zone_idx, profile=None, **kwargs) -> Zone:
    """Create a zone, and optionally perform discovery & start polling."""

    if profile is None:
        profile = ZONE_TYPE.DHW if zone_idx == "HW" else None

    zone = ZONE_BY_TYPE.get(profile, Zone)(evo, zone_idx, **kwargs)

    if isinstance(evo._gwy.pkt_protocol, PacketProtocolPort):
        zone._start_discovery()

    return zone
