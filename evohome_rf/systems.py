#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - The evohome-compatible system."""

import logging
from asyncio import Task
from datetime import timedelta as td
from threading import Lock
from typing import List, Optional

from .command import Command, FaultLog, Priority
from .const import (
    ATTR_DEVICES,
    DEVICE_HAS_ZONE_SENSOR,
    DISCOVER_ALL,
    DISCOVER_PARAMS,
    DISCOVER_SCHEMA,
    DISCOVER_STATUS,
    SystemMode,
    SystemType,
    __dev_mode__,
)
from .devices import Device, Entity
from .exceptions import CorruptStateError, ExpiredCallbackError
from .schema import (
    ATTR_CONTROLLER,
    ATTR_DHW_SYSTEM,
    ATTR_HTG_CONTROL,
    ATTR_HTG_SYSTEM,
    ATTR_ORPHANS,
    ATTR_UFH_SYSTEM,
    ATTR_ZONES,
    DISABLE_DISCOVERY,
    MAX_ZONES,
)
from .zones import DhwZone, Zone

DEV_MODE = __dev_mode__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class SysFaultLog:  # 0418
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._fault_log = FaultLog(self._ctl)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            self._gwy._tasks.append(self._loop.create_task(self.get_fault_log()))

    async def get_fault_log(self, force_refresh=None) -> Optional[dict]:  # 0418
        try:
            return await self._fault_log.get_fault_log(force_refresh=force_refresh)
        except ExpiredCallbackError:
            return

    @property
    def status(self) -> dict:
        status = super().status
        assert "fault_log" not in status  # TODO: removeme
        status["fault_log"] = self._fault_log.fault_log
        status["last_fault"] = self._msgz[" I"].get("0418")
        return status


class SysDatetime:  # 313F
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._datetime = None

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            self._gwy.send_cmd(Command.get_system_time(self.id))
            # self._send_cmd("313F")

    def _handle_msg(self, msg, prev_msg=None):
        super()._handle_msg(msg)

        if msg.code == "313F" and msg.verb in (" I", "RP"):  # TODO: W
            self._datetime = msg

    @property
    def datetime(self) -> Optional[str]:
        return self._msg_payload(self._datetime, "datetime")  # TODO: make a dt object

    # def wait_for(self, cmd, callback):
    # self._api_lock.acquire()

    # self._send_cmd("313F", verb="RQ", callback=callback)

    #     time_start = dt.now()
    # while not self._schedule_done:
    #     await asyncio.sleep(TIMER_SHORT_SLEEP)
    #     if dt.now() > time_start + TIMER_LONG_TIMEOUT:
    #         self._api_lock.release()
    #         raise ExpiredCallbackError("failed to set schedule")

    # self._api_lock.release()

    # async def get_datetime(self) -> str:  # wait for the RP/313F
    # await self.wait_for(Command("313F", verb="RQ"))
    # return self.datetime

    # async def set_datetime(self, dtm: dt) -> str:  # wait for the I/313F
    # await self.wait_for(Command("313F", verb=" W", payload=f"00{dtm_to_hex(dtm)}"))
    # return self.datetime

    @property
    def status(self) -> dict:
        status = super().status
        assert ATTR_HTG_SYSTEM in status  # TODO: removeme
        assert "datetime" not in status[ATTR_HTG_SYSTEM]  # TODO: removeme
        status[ATTR_HTG_SYSTEM]["datetime"] = self.datetime
        return status


class SysLanguage:  # 0100
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._language = None

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_PARAMS:
            self._send_cmd("0100")  # language

    def _handle_msg(self, msg, prev_msg=None):
        super()._handle_msg(msg)

        if msg.code == "0100" and msg.verb in (" I", "RP"):
            self._language = msg

    @property
    def language(self) -> Optional[str]:  # 0100
        return self._msg_payload(self._language, "language")

    @property
    def params(self) -> dict:
        params = super().params
        assert ATTR_HTG_SYSTEM in params  # TODO: removeme
        assert "language" not in params[ATTR_HTG_SYSTEM]  # TODO: removeme
        params[ATTR_HTG_SYSTEM]["language"] = self.language
        return params


class SysMode:  # 2E04
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._system_mode = None

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            # self._send_cmd("2E04", payload="FF")  # system mode
            self._gwy.send_cmd(Command.get_system_mode(self.id))

    def _handle_msg(self, msg, prev_msg=None):
        super()._handle_msg(msg)

        if msg.code == "2E04" and msg.verb in (" I", "RP"):  # this is a special case
            self._system_mode = msg

    @property
    def system_mode(self) -> Optional[dict]:  # 2E04
        return self._msg_payload(self._system_mode)

    def set_mode(self, system_mode=None, until=None) -> Task:
        """Set a system mode for a specified duration, or indefinitely."""
        cmd = Command.set_system_mode(self.id, system_mode=system_mode, until=until)
        return self._gwy.send_cmd(cmd)

    def set_auto(self) -> Task:
        """Revert system to Auto, set non-PermanentOverride zones to FollowSchedule."""
        return self.set_mode(SystemMode.AUTO)

    def reset_mode(self) -> Task:
        """Revert system to Auto, force *all* zones to FollowSchedule."""
        return self.set_mode(SystemMode.RESET)

    @property
    def params(self) -> dict:
        params = super().params
        assert ATTR_HTG_SYSTEM in params  # TODO: removeme
        assert "system_mode" not in params[ATTR_HTG_SYSTEM]  # TODO: removeme
        params[ATTR_HTG_SYSTEM]["system_mode"] = self.system_mode
        return params


class StoredHw:
    MIN_SETPOINT = 30.0  # NOTE: these may be removed
    MAX_SETPOINT = 85.0
    DEFAULT_SETPOINT = 50.0

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._dhw = None

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            pass

    def _handle_msg(self, msg, prev_msg=None):
        """Eavesdrop packets, or pairs of packets, to maintain the system state."""

        def OUT_find_dhw_sensor(this):
            """Discover the stored HW this system (if any).

            There is only 2 ways to to find a controller's DHW sensor:
            1. The 10A0 RQ/RP *from/to a 07:* (1x/4h) - reliable
            2. Use sensor temp matching - non-deterministic

            Data from the CTL is considered more authorative. The RQ is initiated by the
            DHW, so is not authorative. The I/1260 is not to/from a controller, so is
            not useful.
            """

            # 10A0: RQ/07/01, RP/01/07: can get both parent controller & DHW sensor
            # 047 RQ --- 07:030741 01:102458 --:------ 10A0 006 00181F0003E4
            # 062 RP --- 01:102458 07:030741 --:------ 10A0 006 0018380003E8

            # 1260: I/07: can't get which parent controller - need to match temps
            # 045  I --- 07:045960 --:------ 07:045960 1260 003 000911

            # 1F41: I/01: get parent controller, but not DHW sensor
            # 045  I --- 01:145038 --:------ 01:145038 1F41 012 000004FFFFFF1E060E0507E4
            # 045  I --- 01:145038 --:------ 01:145038 1F41 006 000002FFFFFF

            sensor = None

            if this.code == "10A0" and this.verb == "RP":
                if this.src is self and this.dst.type == "07":
                    sensor = this.dst

            if sensor is not None:
                if self.dhw is None:
                    self._get_zone("FA")
                self.dhw._set_sensor(sensor)

        super()._handle_msg(msg)

        if msg.code in ("10A0", "1260"):  # self.dhw.sensor is None and
            # if self.dhw.sensor is None:
            #     find_dhw_sensor(msg)
            pass

        elif msg.code in ("1F41",):  # dhw_mode
            pass

    def _get_zone(self, zone_idx, sensor=None, **kwargs) -> DhwZone:
        """Return a DHW zone (will create it if required).

        Can also set a DHW zone's sensor & valves?.
        """

        def create_dhw(zone_idx) -> DhwZone:
            if self.dhw:
                raise LookupError(f"Duplicate stored HW: {zone_idx}")

            dhw = self._dhw = DhwZone(self)

            if not self._gwy.config[DISABLE_DISCOVERY]:
                dhw._discover()  # discover_flag=DISCOVER_ALL)

            return dhw

        if zone_idx != "HW":
            return

        zone = self.dhw  # TODO: self.zone_by_idx.get("HW") too?
        if zone is None:
            zone = create_dhw(zone_idx)

        if kwargs.get("dhw_valve"):
            zone._set_dhw_valve(kwargs["dhw_valve"])

        if kwargs.get("htg_valve"):
            zone._set_dhw_valve(kwargs["htg_valve"])

        if sensor is not None:
            zone._set_dhw_sensor(sensor)

        return zone

    @property
    def dhw(self) -> DhwZone:
        return self._dhw

    def _set_dhw(self, dhw: DhwZone) -> None:  # self._dhw
        """Set the DHW zone system."""

        if not isinstance(dhw, DhwZone):
            raise TypeError(f"stored_hw can't be: {dhw}")

        if self._dhw is not None:
            if self._dhw is dhw:
                return
            raise CorruptStateError("DHW shouldn't change: {self._dhw} to {dhw}")

        if self._dhw is None:
            # self._gwy._get_device(xxx)
            # self.add_device(dhw.sensor)
            # self.add_device(dhw.relay)
            self._dhw = dhw

    @property
    def dhw_sensor(self) -> Device:
        return self._dhw._dhw_sensor if self._dhw else None

    @property
    def hotwater_valve(self) -> Device:
        return self._dhw._dhw_valve if self._dhw else None

    @property
    def heating_valve(self) -> Device:
        return self._dhw._htg_valve if self._dhw else None

    @property
    def schema(self) -> dict:
        assert ATTR_DHW_SYSTEM not in super().schema  # TODO: removeme
        return {**super().schema, ATTR_DHW_SYSTEM: self.dhw.schema if self.dhw else {}}

    @property
    def params(self) -> dict:
        assert ATTR_DHW_SYSTEM not in super().params  # TODO: removeme
        return {**super().params, ATTR_DHW_SYSTEM: self.dhw.params if self.dhw else {}}

    @property
    def status(self) -> dict:
        assert ATTR_DHW_SYSTEM not in super().status  # TODO: removeme
        return {**super().status, ATTR_DHW_SYSTEM: self.dhw.status if self.dhw else {}}


class MultiZone:  # 0005 (+/- 000C?)
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.zones = []
        self.zone_by_idx = {}
        # self.zone_by_name = {}

        self.zone_lock = Lock()
        self.zone_lock_idx = None

        # self._prev_30c9 = None  # OUT: used to discover zone sensors

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            [  # 0005: find any zones + their type (RAD, UFH, VAL, MIX, ELE)
                self._send_cmd("0005", payload=f"00{zone_type}")
                for zone_type in ("08", "09", "0A", "0B", "11")  # CODE_0005_ZONE_TYPE
            ]

            [  # 0005: find any others - as per an RFG100
                self._send_cmd("0005", payload=f"00{zone_type}")
                for zone_type in ("00", "04", "0C", "0F", "10")
            ]

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("0006")

    def _handle_msg(self, msg, prev_msg=None):
        def OUT_find_zone_sensors() -> None:
            """Determine each zone's sensor by matching zone/sensor temperatures.

            The temperature of each zone is reliably known (30C9 array), but the sensor
            for each zone is not. In particular, the controller may be a sensor for a
            zone, but unfortunately it does not announce its sensor temperatures.

            In addition, there may be 'orphan' (e.g. from a neighbour) sensors
            announcing temperatures with the same value.

            This leaves only a process of exclusion as a means to determine which zone
            uses the controller as a sensor.
            """

            prev_msg, self._prev_30c9 = self._prev_30c9, msg
            if prev_msg is None:
                return

            if len([z for z in self.zones if z.sensor is None]) == 0:
                return  # (currently) no zone without a sensor

            # if self._gwy.serial_port:  # only if in monitor mode...
            secs = self._get_msg_value("1F09", "remaining_seconds")
            if secs is None or msg.dtm > prev_msg.dtm + td(seconds=secs):
                return  # only compare against 30C9 (array) pkt from the last cycle

            _LOGGER.debug("System state (before): %s", self)

            changed_zones = {
                z["zone_idx"]: z["temperature"]
                for z in msg.payload
                if z not in prev_msg.payload
            }  # zones with changed temps
            _LOGGER.debug("Changed zones (from 30C9): %s", changed_zones)
            if not changed_zones:
                return  # ctl's 30C9 says no zones have changed temps during this cycle

            testable_zones = {
                z: t
                for z, t in changed_zones.items()
                if self.zone_by_idx[z].sensor is None
                and t not in [v for k, v in changed_zones.items() if k != z] + [None]
            }  # ...with unique (non-null) temps, and no sensor
            _LOGGER.debug(
                " - with unique/non-null temps (from 30C9), no sensor (from state): %s",
                testable_zones,
            )
            if not testable_zones:
                return  # no testable zones

            testable_sensors = [
                d
                for d in self._gwy.devices  # not: self.devices
                if d._ctl in (self, None)
                and d.addr.type in DEVICE_HAS_ZONE_SENSOR
                and d.temperature is not None
                and d._msgs["30C9"].dtm > prev_msg.dtm  # changed temp during last cycle
            ]

            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug(
                    "Testable zones: %s (unique/non-null temps & sensorless)",
                    testable_zones,
                )
                _LOGGER.debug(
                    "Testable sensors: %s (non-null temps & orphans or zoneless)",
                    {d.id: d.temperature for d in testable_sensors},
                )

            if testable_sensors:  # the main matching algorithm...
                for zone_idx, temp in testable_zones.items():
                    # TODO: when sensors announce temp, ?also includes it's parent zone
                    matching_sensors = [
                        s
                        for s in testable_sensors
                        if s.temperature == temp and s._zone in (zone_idx, None)
                    ]
                    _LOGGER.debug("Testing zone %s, temp: %s", zone_idx, temp)
                    _LOGGER.debug(
                        " - matching sensor(s): %s (same temp & not from another zone)",
                        [s.id for s in matching_sensors],
                    )

                    if len(matching_sensors) == 1:
                        _LOGGER.debug("   - matched sensor: %s", matching_sensors[0].id)
                        zone = self.zone_by_idx[zone_idx]
                        zone._set_sensor(matching_sensors[0])
                        zone.sensor._set_ctl(self)
                    elif len(matching_sensors) == 0:
                        _LOGGER.debug("   - no matching sensor (uses CTL?)")
                    else:
                        _LOGGER.debug("   - multiple sensors: %s", matching_sensors)

                _LOGGER.debug("System state (after): %s", self)

            # now see if we can allocate the controller as a sensor...
            if self._zone is not None:
                return  # the controller has already been allocated
            if len([z for z in self.zones if z.sensor is None]) != 1:
                return  # no single zone without a sensor

            testable_zones = {
                z: t
                for z, t in changed_zones.items()
                if self.zone_by_idx[z].sensor is None
            }  # this will be true if ctl is sensor
            if not testable_zones:
                return  # no testable zones

            zone_idx, temp = list(testable_zones.items())[0]
            _LOGGER.debug("Testing (sole remaining) zone %s, temp: %s", zone_idx, temp)
            # want to avoid complexity of z._temp
            # zone = self.zone_by_idx[zone_idx]
            # if zone._temp is None:
            #     return  # TODO: should have a (not-None) temperature

            matching_sensors = [
                s
                for s in testable_sensors
                if s.temperature == temp and s._zone in (zone_idx, None)
            ]

            _LOGGER.debug(
                " - matching sensor(s): %s (excl. controller)",
                [s.id for s in matching_sensors],
            )

            # can safely(?) assume this zone is using the CTL as a sensor...
            if len(matching_sensors) == 0:
                _LOGGER.debug("   - matched sensor: %s (by exclusion)", self._ctl.id)
                zone = self.zone_by_idx[zone_idx]
                zone._set_sensor(self)
                zone.sensor._set_ctl(self)

            _LOGGER.debug("System state (finally): %s", self)

        super()._handle_msg(msg)

        if msg.code in ("000A",) and isinstance(msg.payload, list):
            for zone_idx in self.zone_by_idx:
                cmd = Command.get_zone_mode(self.id, zone_idx, priority=Priority.LOW)
                self._gwy.send_cmd(cmd)
            # for zone in self.zones:
            #     zone._discover(discover_flags=DISCOVER_PARAMS)

        if msg.code in ("000A", "2309", "30C9"):
            pass
            # if isinstance(msg.payload, list):

        # elif msg.code == "000C":
        #     self._msgs[f"{msg.code}"] = msg

        # elif msg.code == "0005" and prev_msg is not None:
        #     zone_added = bool(prev_msg.code == "0004")  # else zone_deleted

        # elif msg.code == "30C9" and isinstance(msg.payload, list):  # msg.is_array:
        #     find_zone_sensors()

    def _get_zone(self, zone_idx, sensor=None, **kwargs) -> Zone:
        """Return a zone (will create it if required).

        Can also set a zone's sensor, and zone_type, and actuators.
        """

        def create_zone(zone_idx) -> Zone:
            if int(zone_idx, 16) >= self._gwy.config[MAX_ZONES]:
                raise ValueError(f"Invalid zone idx: {zone_idx} (exceeds max_zones)")

            if zone_idx in self.zone_by_idx:
                raise LookupError(f"Duplicated zone: {zone_idx} for {self}")

            zone = Zone(self, zone_idx)

            if not self._gwy.config[DISABLE_DISCOVERY]:  # TODO: needs tidyup (ref #67)
                zone._discover()  # discover_flag=DISCOVER_ALL)

            return zone

        if zone_idx == "HW":
            return super()._get_zone(zone_idx, sensor=sensor, **kwargs)
        if int(zone_idx, 16) >= self._gwy.config[MAX_ZONES]:
            raise ValueError(f"Unknown zone_idx/domain_id: {zone_idx}")

        zone = self.zone_by_idx.get(zone_idx)
        if zone is None:
            zone = create_zone(zone_idx)

        if kwargs.get("zone_type"):
            zone._set_zone_type(kwargs["zone_type"])

        if kwargs.get("actuators"):  # TODO: check not an address before implmenting
            for device in [d for d in kwargs["actuators"] if d not in zone.devices]:
                zone.devices.append(device)
                zone.device_by_id[device.id] = device

        if sensor is not None:
            zone._set_sensor(sensor)

        return zone

    @property
    def _zones(self) -> dict:
        return sorted(self.zones, key=lambda x: x.idx)

    @property
    def schema(self) -> dict:
        assert ATTR_ZONES not in super().schema  # TODO: removeme
        return {**super().schema, ATTR_ZONES: {z.idx: z.schema for z in self._zones}}

    @property
    def params(self) -> dict:
        assert ATTR_ZONES not in super().params  # TODO: removeme
        return {**super().params, ATTR_ZONES: {z.idx: z.params for z in self._zones}}

    @property
    def status(self) -> dict:
        assert ATTR_ZONES not in super().status  # TODO: removeme
        return {**super().status, ATTR_ZONES: {z.idx: z.status for z in self._zones}}


class UfhSystem:
    @property
    def schema(self) -> dict:
        assert ATTR_UFH_SYSTEM not in super().schema  # TODO: removeme
        return {
            **super().schema,
            ATTR_UFH_SYSTEM: {
                d.id: d.schema for d in sorted(self._ctl.devices) if d.type == "02"
            },
        }

    @property
    def params(self) -> dict:
        assert ATTR_UFH_SYSTEM not in super().params  # TODO: removeme
        return {
            **super().params,
            ATTR_UFH_SYSTEM: {
                d.id: d.params for d in sorted(self._ctl.devices) if d.type == "02"
            },
        }

    @property
    def status(self) -> dict:
        assert ATTR_UFH_SYSTEM not in super().status  # TODO: removeme
        return {
            **super().status,
            ATTR_UFH_SYSTEM: {
                d.id: d.status for d in sorted(self._ctl.devices) if d.type == "02"
            },
        }


class SystemBase(Entity):  # 3B00 (multi-relay)
    """The most basic controllers - a generic controller (e.g. ST9420C)."""

    # 0008|0009|1030|1100|2309|3B00

    def __init__(self, gwy, ctl, **kwargs) -> None:
        # _LOGGER.debug("Creating a System: %s (%s)", dev_addr.id, self.__class__)
        super().__init__(gwy, **kwargs)

        self.id = ctl.id
        gwy.systems.append(self)
        gwy.system_by_id[self.id] = self

        self._ctl = ctl
        self._domain_id = "FF"
        self._evo = None

        self._heat_demand = None
        self._htg_control = None

    def __repr__(self) -> str:
        return f"{self._ctl.id} (sys_base)"

    # def __str__(self) -> str:  # TODO: WIP
    #     return json.dumps({self._ctl.id: self.schema})

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            [  # 000C: find the HTG relay and DHW sensor, if any (DHW relays in DHW)
                self._send_cmd("000C", payload=dev_type)
                for dev_type in ("000D", "000F")  # CODE_000C_DEVICE_TYPE
                # for dev_type, description in CODE_000C_DEVICE_TYPE.items() fix payload
                # if description is not None
            ]

        if discover_flag & DISCOVER_PARAMS:
            self._send_cmd("1100", payload="FC")  # TPI params

        # # for code in ("3B00",):  # 3EF0, 3EF1
        # #     for payload in ("0000", "00", "F8", "F9", "FA", "FB", "FC", "FF"):
        # #         self._send_cmd(code, payload=payload)

        # # TODO: opentherm: 1FD4, 22D9, 3220

        # if discover_flag & DISCOVER_PARAMS:
        #     for domain_id in range(0xF8, 0x100):
        #         self._send_cmd("0009", payload=f"{domain_id:02X}00")

        if discover_flag & DISCOVER_STATUS:
            # for domain_id in range(0xF8, 0x100):
            #     self._send_cmd("0008", payload=f"{domain_id:02X}00")
            pass

    def _handle_msg(self, msg) -> bool:
        def OUT_is_exchange(this, prev):  # TODO:use is?
            return this.src is prev.dst and this.dst is prev.src.addr

        def OUT_find_htg_relay(this, prev=None):
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
            # 14:41:46.631 063 RP --- 10:067219 01:078710 --:------ 3EF0 006 0000100000FF  # noqa

            # 06:49:03.465 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
            # 06:49:05.467 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
            # 06:49:07.468 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
            # 09:03:59.693 051  I --- 13:237335 --:------ 13:237335 3B00 002 00C8
            # 09:04:02.667 045  I --- 01:145038 --:------ 01:145038 3B00 002 FCC8

            # note the order: most to least reliable
            heater = None

            if this.code == "3220" and this.verb == "RQ":
                if this.src is self and this.dst.type == "10":
                    heater = this.dst

            elif this.code == "3EF0" and this.verb == "RQ":
                if this.src is self and this.dst.type in ("10", "13"):
                    heater = this.dst

            elif this.code == "3B00" and this.verb == " I" and prev is not None:
                if prev.code == this.code and prev.verb == this.verb:
                    if this.src is self and prev.src.type == "13":
                        heater = prev.src

            if heater is not None:
                self._set_htg_control(heater)

        if msg.code in ("000A", "2309", "30C9") and not isinstance(msg.payload, list):
            pass
        else:
            super()._handle_msg(msg)

        if msg.code == "0008" and msg.verb in (" I", "RP"):
            if "domain_id" in msg.payload:
                self._relay_demands[msg.payload["domain_id"]] = msg
                if msg.payload["domain_id"] == "F9":
                    device = self.dhw.heating_valve if self.dhw else None
                elif msg.payload["domain_id"] == "FA":
                    device = self.dhw.hotwater_valve if self.dhw else None
                elif msg.payload["domain_id"] == "FC":
                    device = self.heating_control
                else:
                    device = None

                if False and device is not None:  # TODO: FIXME
                    qos = {"priority": Priority.LOW, "retries": 2}
                    for code in ("0008", "3EF1"):
                        device._send_cmd(code, qos)

        if msg.code == "3150" and msg.verb in (" I", "RP"):
            if "domain_id" in msg.payload and msg.payload["domain_id"] == "FC":
                self._heat_demand = msg.payload

        # if msg.code in ("3220", "3B00", "3EF0"):  # self.heating_control is None and
        #     find_htg_relay(msg, prev=prev_msg)

    def _send_cmd(self, code, **kwargs) -> None:
        dest = kwargs.pop("dest_addr", self._ctl.id)
        payload = kwargs.pop("payload", "00")
        super()._send_cmd(code, dest, payload, **kwargs)

    @property
    def devices(self) -> List[Device]:
        return self._ctl.devices + [self._ctl]  # TODO: to sort out

    @property
    def heating_control(self) -> Device:
        if self._htg_control:
            return self._htg_control
        htg_control = [d for d in self._ctl.devices if d._domain_id == "FC"]
        return htg_control[0] if len(htg_control) == 1 else None  # HACK for 10:

    def _set_htg_control(self, device: Device) -> None:  # self._htg_control
        """Set the heating control relay for this system (10: or 13:)."""

        if not isinstance(device, Device) or device.type not in ("10", "13"):
            raise TypeError(f"{ATTR_HTG_CONTROL} can't be: {device}")

        if self._htg_control is not None:
            if self._htg_control is device:
                return
            raise CorruptStateError(
                f"{ATTR_HTG_CONTROL} shouldn't change: {self._htg_control} to {device}"
            )

        # if device.evo is not None and device.evo is not self:
        #     raise LookupError

        if self._htg_control is None:
            self._htg_control = device
            device._set_parent(self, domain="FC")

    @property
    def tpi_params(self) -> Optional[float]:  # 1100
        return self._get_msg_value("1100")

    @property
    def heat_demand(self) -> Optional[float]:  # 3150/FC
        if self._heat_demand:
            return self._heat_demand["heat_demand"]

    @property
    def is_calling_for_heat(self) -> Optional[bool]:
        """Return True is the system is currently calling for heat."""
        if not self._htg_control:
            return

        if self._htg_control.actuator_state:
            return True

    @property
    def schema(self) -> dict:
        """Return the system's schema."""

        schema = {ATTR_CONTROLLER: self._ctl.id, ATTR_HTG_SYSTEM: {}}
        assert ATTR_HTG_SYSTEM in schema  # TODO: removeme

        assert ATTR_HTG_CONTROL not in schema[ATTR_HTG_SYSTEM]  # TODO: removeme
        schema[ATTR_HTG_SYSTEM][ATTR_HTG_CONTROL] = (
            self.heating_control.id if self.heating_control else None
        )

        assert ATTR_ORPHANS not in schema[ATTR_HTG_SYSTEM]  # TODO: removeme
        schema[ATTR_ORPHANS] = sorted(
            [d.id for d in self._ctl.devices if not d._domain_id and d.type != "02"]
        )  # devices without a parent zone, NB: CTL can be a sensor for a zones

        # TODO: where to put this?
        # assert "devices" not in schema  # TODO: removeme
        # schema["devices"] = {d.id: d.device_info for d in sorted(self._ctl.devices)}

        return schema

    @property
    def params(self) -> dict:
        """Return the system's configuration."""

        params = {ATTR_HTG_SYSTEM: {}}
        assert ATTR_HTG_SYSTEM in params  # TODO: removeme

        # devices don't have params
        # assert ATTR_HTG_CONTROL not in params[ATTR_HTG_SYSTEM]  # TODO: removeme
        # params[ATTR_HTG_SYSTEM][ATTR_HTG_CONTROL] = (
        #     self.heating_control.params if self.heating_control else None
        # )

        assert "tpi_params" not in params[ATTR_HTG_SYSTEM]  # TODO: removeme
        params[ATTR_HTG_SYSTEM]["tpi_params"] = (
            self.heating_control._get_msg_value("1100")
            if self.heating_control
            else None
        )

        return params

    @property
    def status(self) -> dict:
        """Return the system's current state."""

        status = {ATTR_HTG_SYSTEM: {}}
        assert ATTR_HTG_SYSTEM in status  # TODO: removeme

        # assert ATTR_HTG_CONTROL not in status[ATTR_HTG_SYSTEM]  # TODO: removeme
        # status[ATTR_HTG_SYSTEM][ATTR_HTG_CONTROL] = (
        #     self.heating_control.status if self.heating_control else None
        # )

        status[ATTR_HTG_SYSTEM]["heat_demand"] = self.heat_demand

        status[ATTR_DEVICES] = {d.id: d.status for d in sorted(self._ctl.devices)}

        return status


class System(StoredHw, SysDatetime, SystemBase):  # , SysFaultLog
    """The Controller class."""

    def __init__(self, gwy, ctl, **kwargs) -> None:
        super().__init__(gwy, ctl, **kwargs)

        self._heat_demands = {}
        self._relay_demands = {}
        self._relay_failsafes = {}

    def __repr__(self) -> str:
        return f"{self._ctl.id} (system)"

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if "domain_id" in msg.payload:
            idx = msg.payload["domain_id"]
            if msg.code == "0008":
                self._relay_demands[idx] = msg
            elif msg.code == "0009":
                self._relay_failsafes[idx] = msg
            elif msg.code == "3150":
                self._heat_demands[idx] = msg
            elif msg.code not in ("0001", "000C", "0418", "1100", "3B00"):
                assert False, msg.code

    @property
    def heat_demands(self) -> Optional[dict]:  # 3150
        if self._heat_demands:
            return {k: v.payload["heat_demand"] for k, v in self._heat_demands.items()}

    @property
    def relay_demands(self) -> Optional[dict]:  # 0008
        if self._relay_demands:
            return {
                k: v.payload["relay_demand"] for k, v in self._relay_demands.items()
            }

    @property
    def relay_failsafes(self) -> Optional[dict]:  # 0009
        if self._relay_failsafes:
            return {}  # failsafe_enabled

    @property
    def status(self) -> dict:
        """Return the system's current state."""

        status = super().status
        assert ATTR_HTG_SYSTEM in status  # TODO: removeme

        status[ATTR_HTG_SYSTEM]["heat_demands"] = self.heat_demands
        status[ATTR_HTG_SYSTEM]["relay_demands"] = self.relay_demands
        status[ATTR_HTG_SYSTEM]["relay_failsafes"] = self.relay_failsafes

        return status


class Evohome(SysLanguage, SysMode, MultiZone, UfhSystem, System):  # evohome
    # class Evohome(System):  # evohome
    """The Evohome system - some controllers are evohome-compatible."""

    def __init__(self, gwy, ctl, **kwargs) -> None:
        super().__init__(gwy, ctl, **kwargs)

    def __repr__(self) -> str:
        return f"{self._ctl.id} (evohome)"

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("1F09")

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        # def xxx(zone_dict):
        #     zone = self.zone_by_idx[zone_dict.pop("zone_idx")]
        #     if msg.code == "000A":
        #         zone._zone_config = zone_dict
        #     elif msg.code == "2309":
        #         zone._temp = zone_dict
        #     elif msg.code == "30C9":
        #         zone._temp = zone_dict

        # if msg.code in ("000A", "2309", "30C9"):
        #     if isinstance(msg.payload, list):
        #         super()._handle_msg(msg)
        #         [xxx(z) for z in msg.payload]
        #     else:
        #         xxx(msg.payload)

        if msg.code in ("000A", "2309", "30C9") and isinstance(msg.payload, list):
            pass


class Chronotherm(Evohome):
    def __repr__(self) -> str:
        return f"{self._ctl.id} (chronotherm)"


class Hometronics(System):
    RQ_SUPPORTED = ("0004", "000C", "2E04", "313F")  # TODO: WIP
    RQ_UNSUPPORTED = ("xxxx",)  # 10E0?

    def __repr__(self) -> str:
        return f"{self._ctl.id} (hometronics)"

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # super()._discover(discover_flag=discover_flag)

        # will RP to: 0005/configured_zones_alt, but not: configured_zones
        # will RP to: 0004

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("1F09")


class Programmer(Evohome):
    def __repr__(self) -> str:
        return f"{self._ctl.id} (programmer)"


class Sundial(Evohome):
    def __repr__(self) -> str:
        return f"{self._ctl.id} (sundial)"


SYSTEM_CLASSES = {
    SystemType.CHRONOTHERM: Chronotherm,
    SystemType.EVOHOME: Evohome,
    SystemType.HOMETRONICS: Hometronics,
    SystemType.PROGRAMMER: Programmer,
    SystemType.SUNDIAL: Sundial,
    SystemType.GENERIC: System,
}
