#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - The evohome-compatible system."""

# TODO: refactor packet routing (filter *before* routing)

import asyncio
import logging
from datetime import datetime as dt
from datetime import timedelta as td
from symtable import Class
from threading import Lock
from types import SimpleNamespace
from typing import Optional, Tuple

from .const import (
    SYS_MODE_MAP,
    SZ_ACTUATORS,
    SZ_CHANGE_COUNTER,
    SZ_DATETIME,
    SZ_DEVICES,
    SZ_DHW_IDX,
    SZ_DOMAIN_ID,
    SZ_HEAT_DEMAND,
    SZ_LANGUAGE,
    SZ_SENSOR,
    SZ_SYSTEM_MODE,
    SZ_TEMPERATURE,
    SZ_ZONE_IDX,
    SZ_ZONE_MASK,
    SZ_ZONE_TYPE,
    SZ_ZONES,
    __dev_mode__,
)
from .devices import (
    BdrSwitch,
    Controller,
    Device,
    DeviceHeat,
    OtbGateway,
    Temperature,
    UfhController,
)
from .entity_base import Entity, Parent, class_by_attr
from .helpers import shrink
from .protocol import (
    DEV_ROLE_MAP,
    DEV_TYPE_MAP,
    ZON_ROLE_MAP,
    Address,
    Command,
    ExpiredCallbackError,
    Message,
    Priority,
)
from .schema import (
    SCHEMA_DHW,
    SCHEMA_SYS,
    SCHEMA_ZON,
    SZ_APPLIANCE_CONTROL,
    SZ_CLASS,
    SZ_CONTROLLER,
    SZ_DHW_SYSTEM,
    SZ_ORPHANS,
    SZ_TCS_SYSTEM,
    SZ_UFH_SYSTEM,
)
from .zones import DhwZone, Zone

# skipcq: PY-W2000
from .protocol import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    F9,
    FA,
    FC,
    FF,
)

# skipcq: PY-W2000
from .protocol import (  # noqa: F401, isort: skip, pylint: disable=unused-import
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
    _0150,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _0B04,
    _1030,
    _1060,
    _1081,
    _1090,
    _1098,
    _10A0,
    _10B0,
    _10E0,
    _10E1,
    _1100,
    _11F0,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _12F0,
    _1300,
    _1F09,
    _1F41,
    _1FC9,
    _1FCA,
    _1FD0,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2389,
    _2400,
    _2401,
    _2410,
    _2420,
    _2D49,
    _2E04,
    _2E10,
    _30C9,
    _3110,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3200,
    _3210,
    _3220,
    _3221,
    _3223,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)

DEV_MODE = __dev_mode__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


SYS_KLASS = SimpleNamespace(
    SYS="system",  # Generic (promotable?) system
    TCS="evohome",
    PRG="programmer",
)


class SystemBase(Parent, Entity):  # 3B00 (multi-relay)
    """The TCS base class."""

    _SLUG: str = None

    def __init__(self, ctl) -> None:
        _LOGGER.debug("Creating a TCS for CTL: %s (%s)", ctl.id, self.__class__)

        if ctl.id in ctl._gwy.system_by_id:
            raise LookupError(f"Duplicate TCS for CTL: {ctl.id}")
        if not isinstance(ctl, Controller):  # TODO
            raise ValueError(f"Invalid CTL: {ctl} (is not a controller)")

        super().__init__(ctl._gwy)

        self.id: str = ctl.id

        self.ctl = ctl
        self.tcs = self
        self._child_id = FF  # NOTE: domain_id

        self._app_cntrl: DeviceHeat = None  # schema attr
        self._heat_demand = None  # state attr

    def _update_schema(self, **schema):
        """Update a CH/DHW system with new schema attrs.

        Raise an exception if the new schema is not a superset of the existing schema.
        """

        schema = shrink(SCHEMA_SYS(schema))

        if schema.get(SZ_TCS_SYSTEM) and (
            dev_id := schema[SZ_TCS_SYSTEM].get(SZ_APPLIANCE_CONTROL)
        ):
            self._app_cntrl = self._gwy.get_device(dev_id, parent=self, child_id=FC)

        if _schema := (schema.get(SZ_DHW_SYSTEM)):
            self.get_dhw_zone(**_schema)  # self._dhw = ...

        if _schema := (schema.get(SZ_ZONES)):
            [self.get_htg_zone(idx, **s) for idx, s in _schema.items()]

    @classmethod
    def create_from_schema(cls, ctl: Device, **schema):
        """Create a CH/DHW system for a CTL and set its schema attrs.

        The appropriate System class should have been determined by a factory.
        Schema attrs include: class (klass) & others.
        """

        tcs = cls(ctl)
        tcs._update_schema(**schema)
        return tcs

    def __repr__(self) -> str:
        return f"{self.ctl.id} ({self._SLUG})"

    def _setup_discovery_tasks(self) -> None:
        # super()._setup_discovery_tasks()

        self._add_discovery_task(
            Command(RQ, _000C, f"00{DEV_ROLE_MAP.HTG}", self.id), 60 * 60 * 24, delay=0
        )
        self._add_discovery_task(Command.get_tpi_params(self.id), 60 * 60 * 6, delay=5)

    def _handle_msg(self, msg: Message) -> None:
        def eavesdrop_appliance_control(this, *, prev=None) -> None:
            """Discover the heat relay (10: or 13:) for this system.

            There's' 3 ways to find a controller's heat relay (in order of reliability):
            1.  The 3220 RQ/RP *to/from a 10:* (1x/5min)
            2a. The 3EF0 RQ/RP *to/from a 10:* (1x/1min)
            2b. The 3EF0 RQ (no RP) *to a 13:* (3x/60min)
            3.  The 3B00 I/I exchange between a CTL & a 13: (TPI cycle rate, usu. 6x/hr)

            Data from the CTL is considered 'authorative'. The 1FC9 RQ/RP exchange
            to/from a CTL is too rare to be useful.
            """

            # 18:14:14.025 066 RQ --- 01:078710 10:067219 --:------ 3220 005 0000050000
            # 18:14:14.446 065 RP --- 10:067219 01:078710 --:------ 3220 005 00C00500FF
            # 14:41:46.599 064 RQ --- 01:078710 10:067219 --:------ 3EF0 001 00
            # 14:41:46.631 063 RP --- 10:067219 01:078710 --:------ 3EF0 006 0000100000FF

            # 06:49:03.465 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
            # 06:49:05.467 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
            # 06:49:07.468 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
            # 09:03:59.693 051  I --- 13:237335 --:------ 13:237335 3B00 002 00C8
            # 09:04:02.667 045  I --- 01:145038 --:------ 01:145038 3B00 002 FCC8

            if this.code not in (_22D9, _3220, _3B00, _3EF0):
                return

            # note the order: most to least reliable
            app_cntrl = None

            if this.code in (_22D9, _3220) and this.verb == RQ:  # TODO: RPs too?
                if this.src is self.ctl and isinstance(this.dst, OtbGateway):
                    app_cntrl = this.dst

            elif this.code == _3EF0 and this.verb == RQ:
                if this.src is self.ctl and isinstance(
                    this.dst, (BdrSwitch, OtbGateway)
                ):
                    app_cntrl = this.dst

            elif this.code == _3B00 and this.verb == I_ and prev is not None:
                if this.src is self.ctl and isinstance(prev.src, BdrSwitch):
                    if prev.code == this.code and prev.verb == this.verb:
                        app_cntrl = prev.src

            if app_cntrl is not None:
                app_cntrl.set_parent(self, child_id=FC)  # sets self._app_cntrl

        assert msg.src is self.ctl, f"msg inappropriately routed to {self}"

        super()._handle_msg(msg)

        if (
            msg.code == _000C
            and msg.payload[SZ_ZONE_TYPE] == DEV_ROLE_MAP.APP
            and (msg.payload[SZ_DEVICES])
        ):
            self._gwy.get_device(
                msg.payload[SZ_DEVICES][0], parent=self, child_id=FC
            )  # sets self._app_cntrl
            return

        if msg.code == _0008:
            if (domain_id := msg.payload.get(SZ_DOMAIN_ID)) and msg.verb in (I_, RP):
                self._relay_demands[domain_id] = msg
                if domain_id == F9:
                    device = self.dhw.heating_valve if self.dhw else None
                elif domain_id == "xFA":  # TODO, FIXME
                    device = self.dhw.hotwater_valve if self.dhw else None
                elif domain_id == FC:
                    device = self.appliance_control
                else:
                    device = None

                if False and device is not None:  # TODO: FIXME
                    qos = {"priority": Priority.LOW, "retries": 2}
                    for code in (_0008, _3EF1):
                        device._make_cmd(code, qos)

        elif msg.code == _3150:
            if msg.payload.get(SZ_DOMAIN_ID) == FC and msg.verb in (I_, RP):
                self._heat_demand = msg.payload

        if self._gwy.config.enable_eavesdrop and not self.appliance_control:
            eavesdrop_appliance_control(msg)

    def _make_cmd(self, code, payload="00", **kwargs) -> None:  # skipcq: PYL-W0221
        super()._make_cmd(code, self.ctl.id, payload=payload, **kwargs)

    @property
    def appliance_control(self) -> Device:
        """The TCS relay, aka 'appliance control' (BDR or OTB)."""
        if self._app_cntrl:
            return self._app_cntrl
        app_cntrl = [d for d in self.childs if d._child_id == FC]
        return app_cntrl[0] if len(app_cntrl) == 1 else None  # HACK for 10:

    @property
    def tpi_params(self) -> Optional[dict]:  # 1100
        return self._msg_value(_1100)

    @property
    def heat_demand(self) -> Optional[float]:  # 3150/FC
        return self._msg_value(_3150, domain_id=FC, key=SZ_HEAT_DEMAND)

    @property
    def is_calling_for_heat(self) -> Optional[bool]:
        """Return True is the system is currently calling for heat."""
        return self._app_cntrl and self._app_cntrl.actuator_state

    @property
    def schema(self) -> dict:
        """Return the system's schema."""

        schema = {SZ_TCS_SYSTEM: {}}
        # hema = {SZ_CONTROLLER: self.ctl.id, SZ_TCS_SYSTEM: {}}

        schema[SZ_TCS_SYSTEM][SZ_APPLIANCE_CONTROL] = (
            self.appliance_control.id if self.appliance_control else None
        )

        schema[SZ_ORPHANS] = sorted(
            [
                d.id
                for d in self.childs  # HACK: UFC
                if not d._child_id and d._is_present  # TODO: and d is not self.ctl
            ]  # and not isinstance(d, UfhController)
        )  # devices without a parent zone, NB: CTL can be a sensor for a zone

        return schema

    @property
    def _schema_min(self) -> dict:
        """Return the global schema."""

        schema = self.schema
        result = {SZ_CONTROLLER: self.id}

        try:
            if (
                schema[SZ_TCS_SYSTEM][SZ_APPLIANCE_CONTROL][:2] == DEV_TYPE_MAP.OTB
            ):  # DEX
                result[SZ_TCS_SYSTEM] = {
                    SZ_APPLIANCE_CONTROL: schema[SZ_TCS_SYSTEM][SZ_APPLIANCE_CONTROL]
                }
        except (IndexError, TypeError):
            result[SZ_TCS_SYSTEM] = {SZ_APPLIANCE_CONTROL: None}

        zones = {}
        for idx, zone in schema[SZ_ZONES].items():
            _zone = {}
            if zone[SZ_SENSOR] and zone[SZ_SENSOR][:2] == DEV_TYPE_MAP.CTL:  # DEX
                _zone = {SZ_SENSOR: zone[SZ_SENSOR]}
            if devices := [
                d for d in zone[SZ_ACTUATORS] if d[:2] == DEV_TYPE_MAP.TR0
            ]:  # DEX
                _zone.update({SZ_ACTUATORS: devices})
            if _zone:
                zones[idx] = _zone
        if zones:
            result[SZ_ZONES] = zones

        return result

    @property
    def params(self) -> dict:
        """Return the system's configuration."""

        params = {SZ_TCS_SYSTEM: {}}
        params[SZ_TCS_SYSTEM]["tpi_params"] = self._msg_value(_1100)
        return params

    @property
    def status(self) -> dict:
        """Return the system's current state."""

        status = {SZ_TCS_SYSTEM: {}}
        status[SZ_TCS_SYSTEM]["heat_demand"] = self.heat_demand

        status[SZ_DEVICES] = {d.id: d.status for d in sorted(self.childs)}

        return status


class MultiZone(SystemBase):  # 0005 (+/- 000C?)
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.zones = []
        self.zone_by_idx = {}
        self.max_zones = self._gwy.config.max_zones

        self._prev_30c9 = None  # used to eavesdrop zone sensors

    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        for zone_type in list(ZON_ROLE_MAP.HEAT_ZONES) + [ZON_ROLE_MAP.SEN]:
            self._add_discovery_task(
                Command(RQ, _0005, f"00{zone_type}", self.id), 60 * 60 * 24, delay=0
            )

    def _handle_msg(self, msg: Message) -> None:
        """Process any relevant message.

        If `zone_idx` in payload, route any messages to the corresponding zone.
        """

        def eavesdrop_zones(this, *, prev=None) -> None:
            [
                self.get_htg_zone(v)
                for d in msg.payload
                for k, v in d.items()
                if k == SZ_ZONE_IDX
            ]

        def eavesdrop_zone_sensors(this, *, prev=None) -> None:
            """Determine each zone's sensor by matching zone/sensor temperatures.

            The temperature of each zone is reliably known (30C9 array), but the sensor
            for each zone is not. In particular, the controller may be a sensor for a
            zone, but unfortunately it does not announce its sensor temperatures.

            In addition, there may be 'orphan' (e.g. from a neighbour) sensors
            announcing temperatures with the same value.

            This leaves only a process of exclusion as a means to determine which zone
            uses the controller as a sensor.
            """

            def match_sensors(testable_sensors, zone_idx, zone_temp) -> list:
                return [
                    s
                    for s in testable_sensors
                    if s.temperature == zone_temp
                    and (s.zone is None or s.zone.idx == zone_idx)
                ]

            def _testable_zones(changed_zones) -> dict:
                return {
                    z: t
                    for z, t in changed_zones.items()
                    if self.zone_by_idx[z].sensor is None
                    # and t is not None  # done in changed_zones = {}
                    and t not in [t2 for z2, t2 in changed_zones.items() if z2 != z]
                }  # zones with unique (non-null) temps, and no sensor

            assert isinstance(this.payload, list), "payload is not a list"

            self._prev_30c9, prev = this, self._prev_30c9
            if prev is None:
                return

            # TODO: use msgz/I, not RP
            secs = self._msg_value(_1F09, key="remaining_seconds")
            if secs is None or this.dtm > prev.dtm + td(seconds=secs + 5):
                return  # can only compare against 30C9 pkt from the last cycle

            _LOGGER.debug("System state (before): %s", self.schema)

            changed_zones = {
                z[SZ_ZONE_IDX]: z[SZ_TEMPERATURE]
                for z in this.payload
                if z not in prev.payload and z[SZ_TEMPERATURE] is not None
            }  # zones with changed temps
            _LOGGER.debug("Changed zones (from 30C9): %s", changed_zones)
            if not changed_zones:
                return  # ctl's 30C9 says no zones have changed temps during this cycle

            testable_zones = _testable_zones(changed_zones)
            _LOGGER.debug(
                " - has unique/non-null temps (from 30C9) & no sensor (from state): %s",
                testable_zones,
            )
            if not testable_zones:
                return  # no testable zones

            testable_sensors = [
                d
                for d in self._gwy.devices  # NOTE: *not* self.childs
                if isinstance(d, Temperature)  # d.addr.type in DEVICE_HAS_ZONE_SENSOR
                and d.ctl in (self.ctl, None)
                and d.temperature is not None
                and d._msgs[_30C9].dtm > prev.dtm  # changed during last cycle
            ]

            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug(
                    "Testable zones: %s (unique/non-null temps & sensorless)",
                    testable_zones,
                )
                _LOGGER.debug(
                    "Testable sensors: %s (non-null temps & parentless)",
                    {d.id: d.temperature for d in testable_sensors},
                )

            if testable_sensors:  # the main matching algorithm...
                for zone_idx, temp in testable_zones.items():
                    # TODO: when sensors announce temp, ?also includes its parent zone
                    matching_sensors = match_sensors(testable_sensors, zone_idx, temp)
                    _LOGGER.debug("Testing zone %s, temp: %s", zone_idx, temp)
                    _LOGGER.debug(
                        " - matching sensor(s): %s (same temp & not from another zone)",
                        [s.id for s in matching_sensors],
                    )

                    if len(matching_sensors) == 1:
                        _LOGGER.debug(
                            "   - matched sensor: %s (%s) to zone: %s (%s)",
                            matching_sensors[0].id,
                            matching_sensors[0].temperature,
                            zone_idx,
                            temp,
                        )
                        zone = self.zone_by_idx[zone_idx]
                        self._gwy.get_device(
                            matching_sensors[0].id, parent=zone, is_sensor=True
                        )
                    elif len(matching_sensors) == 0:
                        _LOGGER.debug("   - no matching sensor (uses CTL?)")
                    else:
                        _LOGGER.debug("   - multiple sensors: %s", matching_sensors)

                _LOGGER.debug("System state (after): %s", self.schema)

            # now see if we can allocate the controller as a sensor...
            if any(z for z in self.zones if z.sensor is self.ctl):
                return  # the controller is already a sensor
            if len([z for z in self.zones if z.sensor is None]) != 1:
                return  # no single zone without a sensor

            remaining_zones = _testable_zones(changed_zones)
            if not remaining_zones:
                return  # no testable zones

            zone_idx, temp = list(remaining_zones.items())[0]
            _LOGGER.debug("Testing (sole remaining) zone %s, temp: %s", zone_idx, temp)
            # want to avoid complexity of z._temp
            # zone = self.zone_by_idx[zone_idx]
            # if zone._temp is None:
            #     return  # TODO: should have a (not-None) temperature

            matching_sensors = match_sensors(testable_sensors, zone_idx, temp)
            _LOGGER.debug(
                " - matching sensor(s): %s (excl. controller)",
                [s.id for s in matching_sensors],
            )

            # can safely(?) assume this zone is using the CTL as a sensor...
            if len(matching_sensors) == 0:
                _LOGGER.debug("   - assumed sensor: %s (by exclusion)", self.ctl.id)
                zone = self.zone_by_idx[zone_idx]
                self._gwy.get_device(self.ctl.id, parent=zone, is_sensor=True)

            _LOGGER.debug("System state (finally): %s", self.schema)

        def handle_msg_by_zone_idx(zone_idx: str, msg):
            if zone := self.zone_by_idx.get(zone_idx):
                zone._handle_msg(msg)
            # elif self._gwy.config.enable_eavesdrop:
            #     self.get_htg_zone(zone_idx)._handle_msg(msg)
            pass

        super()._handle_msg(msg)

        if msg.code not in (_0005, _000A, _2309, _30C9) and (
            SZ_ZONE_IDX not in msg.payload  # 0004,0008,0009,000C,0404,12B0,2349,3150
        ):
            return

        # TODO: a I/0005 may have changed zones & may need a restart (del) or not (add)
        if msg.code == _0005:
            if (zone_type := msg.payload[SZ_ZONE_TYPE]) in ZON_ROLE_MAP.HEAT_ZONES:
                [
                    self.get_htg_zone(
                        f"{idx:02X}", **{SZ_CLASS: ZON_ROLE_MAP[zone_type]}
                    )
                    for idx, flag in enumerate(msg.payload[SZ_ZONE_MASK])
                    if flag == 1
                ]
            elif zone_type in DEV_ROLE_MAP.HEAT_DEVICES:
                [
                    self.get_htg_zone(f"{idx:02X}", msg=msg)
                    for idx, flag in enumerate(msg.payload[SZ_ZONE_MASK])
                    if flag == 1
                ]
            return

        if msg.code == _000C and msg.payload[SZ_ZONE_TYPE] in DEV_ROLE_MAP.HEAT_DEVICES:
            if msg.payload[SZ_DEVICES]:
                self.get_htg_zone(msg.payload[SZ_ZONE_IDX], msg=msg)
            elif zon := self.zone_by_idx.get(msg.payload[SZ_ZONE_IDX]):
                zon._handle_msg(msg)  # tell existing zone: no device
            return

        # If some zones still don't have a sensor, maybe eavesdrop?
        if self._gwy.config.enable_eavesdrop and (
            msg.code in (_000A, _2309, _30C9) and msg._has_array
        ):  # could do _000A, but only 1/hr
            eavesdrop_zones(msg)

        # Route all messages to their zones, incl. 000C, 0404, others
        if isinstance(msg.payload, dict):
            if zone_idx := msg.payload.get(SZ_ZONE_IDX):
                handle_msg_by_zone_idx(zone_idx, msg)
            # TODO: elif msg.payload.get(SZ_DOMAIN_ID) == FA:  # DHW

        elif isinstance(msg.payload, list) and len(msg.payload):
            # TODO: elif msg.payload.get(SZ_DOMAIN_ID) == FA:  # DHW
            if isinstance(msg.payload[0], dict):  # e.g. 1FC9 is a list of lists:
                [handle_msg_by_zone_idx(z.get(SZ_ZONE_IDX), msg) for z in msg.payload]

        # If some zones still don't have a sensor, maybe eavesdrop?
        if (  # TODO: edge case: 1 zone with CTL as SEN
            self._gwy.config.enable_eavesdrop
            and msg.code == _30C9
            and (msg._has_array or len(self.zones) == 1)
            and any(z for z in self.zones if not z.sensor)
        ):
            eavesdrop_zone_sensors(msg)

    def get_htg_zone(self, zone_idx, *, msg=None, **schema) -> Zone:
        """Return a heating zone, create it if required.

        First, use the schema to create/update it, then pass it any msg to handle.

        Heating zones are uniquely identified by a tcs_id|zone_idx pair.
        If a zone is created, attach it to this TCS.
        """

        from .zones import zx_zone_factory

        schema = shrink(SCHEMA_ZON(schema))

        zon = self.zone_by_idx.get(zone_idx)
        if not zon:
            zon = zx_zone_factory(self, zone_idx, msg=msg, **schema)
            self.zone_by_idx[zon.idx] = zon
            self.zones.append(zon)

        elif schema:
            zon._update_schema(**schema)

        if msg:
            zon._handle_msg(msg)
        return zon

    @property
    def schema(self) -> dict:
        return {
            **super().schema,
            SZ_ZONES: {z.idx: z.schema for z in sorted(self.zones)},
        }

    @property
    def params(self) -> dict:
        return {
            **super().params,
            SZ_ZONES: {z.idx: z.params for z in sorted(self.zones)},
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            SZ_ZONES: {z.idx: z.status for z in sorted(self.zones)},
        }


class ScheduleSync(SystemBase):  # 0006 (+/- 0404?)
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._msg_0006: Message = None

        self.zone_lock = Lock()  # used to stop concurrent get_schedules
        self.zone_lock_idx = None

    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        self._add_discovery_task(Command(RQ, _0006, "00", self.id), 60 * 5, delay=5)

    def _handle_msg(self, msg: Message) -> None:  # NOTE: active
        """Periodically retreive the latest global change counter."""
        super()._handle_msg(msg)

        if msg.code == _0006:
            self._msg_0006 = msg

    async def _schedule_version(self, *, force_io: bool = False) -> Tuple[int, bool]:
        """Return the global schedule version number, and an indication if I/O was done.

        If `force_io`, then RQ the latest change counter from the TCS rather than
        rely upon a recent (cached) value.
        """

        # RQ --- 30:185469 01:037519 --:------ 0006 001 00
        # RP --- 01:037519 30:185469 --:------ 0006 004 000500E6

        if (
            not force_io
            and self._msg_0006
            and self._msg_0006.dtm > dt.now() - td(minutes=3)
        ):
            return (
                self._msg_0006.payload[SZ_CHANGE_COUNTER],
                False,
            )  # global_ver, did_io

        self._msg_0006 = await self._gwy.async_send_cmd(
            Command.get_schedule_version(self.ctl.id)
        )

        assert isinstance(  # TODO: remove me
            self._msg_0006, Message
        ), f"_schedule_version(): {self._msg_0006} (is not a message)"

        return self._msg_0006.payload[SZ_CHANGE_COUNTER], True  # global_ver, did_io

    def _refresh_schedules(self) -> None:
        if self._gwy.config.disable_sending:
            raise RuntimeError("Sending is disabled")

        # schedules based upon 'active' (not most recent) 0006 pkt
        for zone in getattr(self, SZ_ZONES, []):
            self._gwy._loop.create_task(zone.get_schedule(force_io=True))
        if dhw := getattr(self, "dhw", None):
            self._gwy._loop.create_task(dhw.get_schedule(force_io=True))

    async def _obtain_lock(self, zone_idx) -> None:

        timeout_dtm = dt.now() + td(minutes=3)
        while dt.now() < timeout_dtm:

            self.zone_lock.acquire()
            if self.zone_lock_idx is None:
                self.zone_lock_idx = zone_idx
            self.zone_lock.release()

            if self.zone_lock_idx == zone_idx:
                break
            await asyncio.sleep(0.005)  # gives the other zone enough time

        else:
            raise TimeoutError(
                f"Unable to obtain lock for {zone_idx} (used by {self.zone_lock_idx})"
            )

    def _release_lock(self) -> None:

        self.zone_lock.acquire()
        self.zone_lock_idx = None
        self.zone_lock.release()

    @property
    def params(self) -> dict:
        return {
            **super().params,
            SZ_CHANGE_COUNTER: self._msg_value(_0006, SZ_CHANGE_COUNTER),
        }


class Language(SystemBase):  # 0100
    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        self._add_discovery_task(
            Command.get_system_language(self.id), 60 * 60 * 24, delay=5
        )

    @property
    def language(self) -> Optional[str]:
        return self._msg_value(_0100, key=SZ_LANGUAGE)

    @property
    def params(self) -> dict:
        params = super().params
        params[SZ_TCS_SYSTEM][SZ_LANGUAGE] = self.language
        return params


class Logbook(SystemBase):  # 0418
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._prev_event = None
        self._this_event = None

        self._prev_fault = None
        self._this_fault = None

        self._faultlog = None  # FaultLog(self.ctl)
        self._faultlog_outdated = None  # should be True

    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        self._add_discovery_task(
            Command.get_system_log_entry(self.ctl.id, 0), 60 * 5, delay=5
        )
        # self._gwy.add_task(self._loop.create_task(self.get_faultlog()))

    def _handle_msg(self, msg: Message) -> None:  # NOTE: active
        super()._handle_msg(msg)

        if msg.code != _0418:
            return

        if msg.payload["log_idx"] == "00":
            if not self._this_event or (
                msg.payload["log_entry"] != self._this_event.payload["log_entry"]
            ):
                self._this_event, self._prev_event = msg, self._this_event
            # TODO: self._faultlog_outdated = msg.verb == I_ or self._prev_event and (
            #     msg.payload["log_entry"] != self._prev_event.payload["log_entry"]
            # )

        if msg.payload["log_entry"] and msg.payload["log_entry"][1] == "fault":
            if not self._this_fault or (
                msg.payload["log_entry"] != self._this_fault.payload["log_entry"]
            ):
                self._this_fault, self._prev_fault = msg, self._this_fault

        # if msg.payload["log_entry"][1] == "restore" and not self._this_fault:
        #     self._send_cmd(Command.get_system_log_entry(self.ctl.id, 1))

        # TODO: if self._faultlog_outdated:
        #     if not self._gwy.config.disable_sending:
        #         self._loop.create_task(self.get_faultlog(force_io=True))

    async def get_faultlog(self, *, start=None, limit=None, force_io=None) -> dict:
        if self._gwy.config.disable_sending:
            raise RuntimeError("Sending is disabled")

        try:
            return await self._faultlog.get_faultlog(
                start=start, limit=limit, force_io=force_io
            )
        except (ExpiredCallbackError, RuntimeError):
            return

    # @property
    # def faultlog_outdated(self) -> bool:
    #     return self._this_event.verb == I_ or self._prev_event and (
    #         self._this_event.payload != self._prev_event.payload
    #     )

    # @property
    # def faultlog(self) -> dict:
    #     return self._faultlog.faultlog

    @property
    def active_fault(self) -> Optional[tuple]:
        """Return the most recently logged event, but only if it is a fault."""
        if self.latest_fault == self.latest_event:
            return self.latest_fault

    @property
    def latest_event(self) -> Optional[tuple]:
        """Return the most recently logged event (fault or restore), if any."""
        return self._this_event and self._this_event.payload["log_entry"]

    @property
    def latest_fault(self) -> Optional[tuple]:
        """Return the most recently logged fault, if any."""
        return self._this_fault and self._this_fault.payload["log_entry"]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "latest_event": self.latest_event,
            "active_fault": self.active_fault,
            # "faultlog": self.faultlog,
        }


class StoredHw(SystemBase):  # 10A0, 1260, 1F41
    MIN_SETPOINT = 30.0  # NOTE: these may be removed
    MAX_SETPOINT = 85.0
    DEFAULT_SETPOINT = 50.0

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._dhw = None

    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        self._add_discovery_task(
            Command(RQ, _000C, f"00{DEV_ROLE_MAP.DHW}", self.id), 60 * 60 * 24, delay=0
        )

    def _handle_msg(self, msg: Message) -> None:

        super()._handle_msg(msg)

        if (
            not isinstance(msg.payload, dict)
            or msg.payload.get(SZ_DHW_IDX) is None
            and msg.payload.get(SZ_DOMAIN_ID) not in (F9, FA)
        ):  # _0008, _000C, _0404, _10A0, _1260, _1F41
            return

        # TODO: a I/0005 may have changed zones & may need a restart (del) or not (add)
        if msg.code == _000C and msg.payload[SZ_ZONE_TYPE] in DEV_ROLE_MAP.DHW_DEVICES:
            if msg.payload[SZ_DEVICES]:
                self.get_dhw_zone(msg=msg)  # create DHW zone if required
            elif self._dhw:
                self._dhw._handle_msg(msg)  # tell existing DHW zone: no device
            return

        # RQ --- 18:002563 01:078710 --:------ 10A0 001 00  # every 4h
        # RP --- 01:078710 18:002563 --:------ 10A0 006 00157C0003E8

        # Route all messages to their zones, incl. 000C, 0404, others
        self.get_dhw_zone(msg=msg)

    def get_dhw_zone(self, *, msg=None, **schema) -> DhwZone:
        """Return a DHW zone, create it if required.

        First, use the schema to create/update it, then pass it any msg to handle.

        DHW zones are uniquely identified by a controller ID.
        If a DHW zone is created, attach it to this TCS.
        """

        from .zones import zx_zone_factory

        schema = shrink(SCHEMA_DHW(schema))

        if not self._dhw:
            self._dhw = zx_zone_factory(self, "HW", msg=msg, **schema)

        elif schema:
            self._dhw._update_schema(**schema)

        if msg:
            self._dhw._handle_msg(msg)
        return self._dhw

    @property
    def dhw(self) -> DhwZone:
        return self._dhw

    @property
    def dhw_sensor(self) -> Device:
        return self._dhw.sensor if self._dhw else None

    @property
    def hotwater_valve(self) -> Device:
        return self._dhw.hotwater_valve if self._dhw else None

    @property
    def heating_valve(self) -> Device:
        return self._dhw.heating_valve if self._dhw else None

    @property
    def schema(self) -> dict:
        return {
            **super().schema,
            SZ_DHW_SYSTEM: self._dhw.schema if self._dhw else {},
        }

    @property
    def params(self) -> dict:
        return {
            **super().params,
            SZ_DHW_SYSTEM: self._dhw.params if self._dhw else {},
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            SZ_DHW_SYSTEM: self._dhw.status if self._dhw else {},
        }


class SysMode(SystemBase):  # 2E04
    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        self._add_discovery_task(Command.get_system_mode(self.id), 60 * 5, delay=5)

    @property
    def system_mode(self) -> Optional[dict]:  # 2E04
        return self._msg_value(_2E04)

    def set_mode(self, system_mode, *, until=None) -> asyncio.Task:
        """Set a system mode for a specified duration, or indefinitely."""
        return self._send_cmd(
            Command.set_system_mode(self.id, system_mode=system_mode, until=until)
        )

    def set_auto(self) -> asyncio.Task:
        """Revert system to Auto, set non-PermanentOverride zones to FollowSchedule."""
        return self.set_mode(SYS_MODE_MAP.AUTO)

    def reset_mode(self) -> asyncio.Task:
        """Revert system to Auto, force *all* zones to FollowSchedule."""
        return self.set_mode(SYS_MODE_MAP.AUTO_WITH_RESET)

    @property
    def params(self) -> dict:
        params = super().params
        params[SZ_TCS_SYSTEM][SZ_SYSTEM_MODE] = self.system_mode
        return params


class Datetime(SystemBase):  # 313F
    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        self._add_discovery_task(Command.get_system_time(self.id), 60 * 60, delay=0)

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        if msg.code == _313F and msg.verb in (I_, RP):
            if self._gwy.ser_name and (
                diff := abs(dt.fromisoformat(msg.payload[SZ_DATETIME]) - dt.now())
            ) > td(minutes=5):
                _LOGGER.warning(f"{msg!r} < excessive datetime difference: {diff}")

    async def get_datetime(self) -> Optional[dt]:
        msg = await self._gwy.async_send_cmd(Command.get_system_time(self.id))
        return dt.fromisoformat(msg.payload[SZ_DATETIME])

    async def set_datetime(self, dtm: dt) -> Optional[Message]:
        return await self._gwy.async_send_cmd(Command.set_system_time(self.id, dtm))


class UfHeating(SystemBase):
    def _ufh_ctls(self):
        return sorted([d for d in self.childs if isinstance(d, UfhController)])

    @property
    def schema(self) -> dict:
        return {
            **super().schema,
            SZ_UFH_SYSTEM: {d.id: d.schema for d in self._ufh_ctls()},
        }

    @property
    def params(self) -> dict:
        return {
            **super().params,
            SZ_UFH_SYSTEM: {d.id: d.params for d in self._ufh_ctls()},
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            SZ_UFH_SYSTEM: {d.id: d.status for d in self._ufh_ctls()},
        }


class System(StoredHw, Datetime, Logbook, SystemBase):
    """The Controller class."""

    _SLUG: str = SYS_KLASS.PRG

    def __init__(self, ctl, **kwargs) -> None:
        super().__init__(ctl, **kwargs)

        self._heat_demands = {}
        self._relay_demands = {}
        self._relay_failsafes = {}

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        if SZ_DOMAIN_ID in msg.payload:
            idx = msg.payload[SZ_DOMAIN_ID]
            if msg.code == _0008:
                self._relay_demands[idx] = msg
            elif msg.code == _0009:
                self._relay_failsafes[idx] = msg
            elif msg.code == _3150:
                self._heat_demands[idx] = msg
            elif msg.code not in (_0001, _000C, _0404, _0418, _1100, _3B00):
                assert False, f"Unexpected code with a domain_id: {msg.code}"

    @property
    def heat_demands(self) -> Optional[dict]:  # 3150
        # FC: 00-C8 (no F9, FA), TODO: deprecate as FC only?
        if self._heat_demands:
            return {k: v.payload["heat_demand"] for k, v in self._heat_demands.items()}

    @property
    def relay_demands(self) -> Optional[dict]:  # 0008
        # FC: 00-C8, F9: 00-C8, FA: 00 or C8 only (01: all 3, 02: FC/FA only)
        if self._relay_demands:
            return {
                k: v.payload["relay_demand"] for k, v in self._relay_demands.items()
            }

    @property
    def relay_failsafes(self) -> Optional[dict]:  # 0009
        if self._relay_failsafes:
            return {}  # TODO: failsafe_enabled

    @property
    def status(self) -> dict:
        """Return the system's current state."""

        status = super().status
        # assert SZ_TCS_SYSTEM in status  # TODO: removeme

        status[SZ_TCS_SYSTEM]["heat_demands"] = self.heat_demands
        status[SZ_TCS_SYSTEM]["relay_demands"] = self.relay_demands
        status[SZ_TCS_SYSTEM]["relay_failsafes"] = self.relay_failsafes

        return status


class Evohome(ScheduleSync, Language, SysMode, MultiZone, UfHeating, System):
    """The Evohome system - some controllers are evohome-compatible."""

    # older evohome don't have zone_type=ELE

    _SLUG: str = SYS_KLASS.TCS


class Chronotherm(Evohome):

    _SLUG: str = SYS_KLASS.SYS


class Hometronics(System):
    # These are only ever been seen from a Hometronics controller
    #  I --- 01:023389 --:------ 01:023389 2D49 003 00C800
    #  I --- 01:023389 --:------ 01:023389 2D49 003 01C800
    #  I --- 01:023389 --:------ 01:023389 2D49 003 880000
    #  I --- 01:023389 --:------ 01:023389 2D49 003 FD0000

    # Hometronic does not react to W/2349 but rather requies W/2309

    _SLUG: str = SYS_KLASS.SYS

    #
    # def _setup_discovery_tasks(self) -> None:
    #     # super()._setup_discovery_tasks()

    #     # will RP to: 0005/configured_zones_alt, but not: configured_zones
    #     # will RP to: 0004

    RQ_SUPPORTED = (_0004, _000C, _2E04, _313F)  # TODO: WIP
    RQ_UNSUPPORTED = ("xxxx",)  # 10E0?


class Programmer(Evohome):

    _SLUG: str = SYS_KLASS.PRG


class Sundial(Evohome):

    _SLUG: str = SYS_KLASS.SYS


SYS_CLASS_BY_SLUG = class_by_attr(__name__, "_SLUG")  # e.g. "evohome": Evohome


def zx_system_factory(ctl, *, msg: Message = None, **schema) -> System:
    """Return the system class for a given controller/schema (defaults to evohome)."""

    def best_tcs_class(
        ctl_addr: Address,
        *,
        msg: Message = None,
        eavesdrop: bool = False,
        **schema,
    ) -> Class:
        """Return the system class for a given CTL/schema (defaults to evohome)."""

        # a specified system class always takes precidence (even if it is wrong)...
        if cls := SYS_CLASS_BY_SLUG.get(schema.get(SZ_CLASS)):
            _LOGGER.debug(
                f"Using an explicitly-defined system class for: {ctl_addr} ({cls._SLUG})"
            )
            return cls

        # otherwise, use the default system class...
        _LOGGER.debug(f"Using a generic system class for: {ctl_addr} ({Evohome._SLUG})")
        return Evohome

    return best_tcs_class(
        ctl.addr,
        msg=msg,
        eavesdrop=ctl._gwy.config.enable_eavesdrop,
        **schema,
    ).create_from_schema(ctl, **schema)
