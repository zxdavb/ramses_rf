#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - The evohome-compatible system."""

import asyncio
from datetime import timedelta as td
import json
import logging
from threading import Lock
from typing import List, Optional

from .command import Priority, FaultLog
from .const import (
    ATTR_CONTROLLER,
    ATTR_DEVICES,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_SYSTEM,
    ATTR_ZONE_SENSOR,
    DEVICE_HAS_ZONE_SENSOR,
    DISCOVER_SCHEMA,
    DISCOVER_PARAMS,
    DISCOVER_STATUS,
    DISCOVER_ALL,
    SYSTEM_MODE_LOOKUP,
    SYSTEM_MODE_MAP,
    _dev_mode_,
)
from .devices import Device, Entity, _payload
from .exceptions import CorruptStateError, ExpiredCallbackError
from .helpers import dtm_to_hex
from .schema import (
    ATTR_HTG_CONTROL,
    ATTR_ORPHANS,
    ATTR_UFH_CONTROLLERS,
    ATTR_ZONES,
    DISABLE_DISCOVERY,
    MAX_ZONES,
)


from .zones import DhwZone, Zone

DEV_MODE = _dev_mode_

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class SysFaultLog(Entity):  # 0418
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._fault_log = FaultLog(self._ctl)

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            self._gwy._tasks.append(asyncio.create_task(self.get_fault_log()))  # 0418

    def _handle_msg(self, msg, prev_msg=None):
        super()._handle_msg(msg)

        if msg.code == "0418" and msg.verb in (" I"):
            pass

    async def get_fault_log(self, force_refresh=None) -> Optional[dict]:  # 0418
        try:
            return await self._fault_log.get_fault_log(force_refresh=force_refresh)
        except ExpiredCallbackError:
            return

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "fault_log": self._fault_log.fault_log,
        }


class SysDatetime(Entity):  # 313F
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._datetime = None

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("313F")

    def _handle_msg(self, msg, prev_msg=None):
        super()._handle_msg(msg)

        if msg.code == "313F" and msg.verb in (" I", "RP"):  # TODO: W
            self._datetime = msg

    @property
    def datetime(self) -> Optional[str]:
        return _payload(self._datetime, "datetime")  # TODO: make a dt object

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
        return {
            **super().status,
            "datetime": self.datetime,
        }


class SysLanguage(Entity):  # 0100
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
        return _payload(self._language, "language")

    @property
    def params(self) -> dict:
        return {
            **super().params,
            "language": self.language,
        }


class SysMode:  # 2E04
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._mode = None

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("2E04", payload="FF")  # system mode

        # TODO: testing only
        # asyncio.create_task(
        #     self.async_set_mode(5, dt_now() + td(minutes=120))
        #     # self.async_set_mode(5)
        #     # self.async_reset_mode()
        # )

    def _handle_msg(self, msg, prev_msg=None):
        super()._handle_msg(msg)

        if msg.code == "2E04" and msg.verb in (" I", "RP"):  # this is a special case
            self._mode = msg

    @property
    def mode(self) -> Optional[dict]:  # 2E04
        return _payload(self._mode)

    async def set_mode(self, mode, until=None):
        """Set the system mode for a specified duration, or indefinitely."""

        if isinstance(mode, int):
            mode = f"{mode:02X}"
        elif not isinstance(mode, str):
            raise TypeError("Invalid system mode")
        elif mode in SYSTEM_MODE_LOOKUP:
            mode = SYSTEM_MODE_LOOKUP[mode]

        if mode not in SYSTEM_MODE_MAP:
            raise ValueError("Unknown system mode")

        until = dtm_to_hex(until) + "00" if until is None else "01"

        self._send_cmd("2E04", verb=" W", payload=f"{mode}{until}")

    async def reset_mode(self) -> None:
        """Revert the system mode to Auto."""  # TODO: is it AutoWithReset?
        self._send_cmd("2E04", verb=" W", payload="00FFFFFFFFFFFF00")

    @property
    def params(self) -> dict:
        return {
            **super().params,
            "mode": self.mode,
        }


class StoredHw:
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._dhw = None

    def __repr__(self) -> str:
        return f"{self._ctl.id}_HW (DHW)"

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            pass

    def _handle_msg(self, msg, prev_msg=None):
        """Eavesdrop packets, or pairs of packets, to maintain the system state."""

        def OUT_find_dhw_sensor(this):
            """Discover the stored HW this system (if any).

            There is only 2 way2 to find a controller's DHW sensor:
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

        Can also set a DHW zone's sensor.
        """

        def create_dhw() -> DhwZone:
            if self.dhw:
                raise LookupError(f"Duplicate stored hw: {zone_idx}")

            dhw = self._dhw = DhwZone(self)

            if not self._gwy.config[DISABLE_DISCOVERY]:
                dhw._discover()  # discover_flag=DISCOVER_ALL)

            return dhw

        if zone_idx == "HW":
            zone = self.dhw
            if zone is None:
                zone = create_dhw()

            if kwargs.get("dhw_valve"):
                zone._set_dhw_valve(kwargs["dhw_valve"])

            if kwargs.get("htg_valve"):
                zone._set_dhw_valve(kwargs["htg_valve"])

        else:
            raise ValueError(f"Unknown zone_idx/domain_id: {zone_idx}")

        if sensor is not None:
            zone._set_sensor(sensor)

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
    def schema(self) -> dict:
        return {
            **super().schema,
            "stored_hotwater": None if self.dhw is None else self.dhw.schema,
        }

    @property
    def params(self) -> dict:
        return {
            **super().params,
            "stored_hotwater": None if self.dhw is None else self.dhw.params,
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "stored_hotwater": None if self.dhw is None else self.dhw.status,
        }


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

        if msg.code in ("000A", "2309", "30C9"):
            pass
            # if isinstance(msg.payload, list):

        # elif msg.code == "0005" and prev_msg is not None:
        #     zone_added = bool(prev_msg.code == "0004")  # else zone_deleted

        # elif msg.code == "30C9" and isinstance(msg.payload, list):  # msg.is_array:
        #     find_zone_sensors()

    def _get_zone(self, zone_idx, sensor=None, **kwargs) -> Zone:
        """Return a zone (will create it if required).

        Can also set a zone's sensor, and zone_type.
        """

        def create_zone(zone_idx) -> Zone:
            if int(zone_idx, 16) >= self._gwy.config[MAX_ZONES]:
                raise ValueError(f"Invalid zone idx: {zone_idx} (exceeds max_zones)")

            assert zone_idx not in self.zone_by_idx, f"Dup zone: {zone_idx} for {self}"
            if zone_idx in self.zone_by_idx:
                raise LookupError(f"Duplicated zone: {zone_idx} for {self}")

            zone = Zone(self, zone_idx)

            if not self._gwy.config[DISABLE_DISCOVERY]:  # TODO: needs tidyup (ref #67)
                zone._discover()  # discover_flag=DISCOVER_ALL)

            return zone

        if zone_idx == "HW":
            return super()._get_zone(zone_idx, sensor=sensor, **kwargs)

        if int(zone_idx, 16) <= self._gwy.config[MAX_ZONES]:
            zone = self.zone_by_idx.get(zone_idx)
            if zone is None:
                zone = create_zone(zone_idx)

            if kwargs.get("zone_type"):
                zone._set_zone_type(kwargs["zone_type"])

            if kwargs.get("actuators"):  # TODO: check not an address before implmenting
                for device in [d for d in kwargs["actuators"] if d not in zone.devices]:
                    zone.devices.append(device)
                    zone.device_by_id[device.id] = device

        else:
            raise ValueError(f"Unknown zone_idx/domain_id: {zone_idx}")

        if sensor is not None:
            zone._set_sensor(sensor)

        return zone

    @property
    def _zones(self) -> dict:
        return sorted(self.zones, key=lambda x: x.idx)

    @property
    def schema(self) -> dict:
        return {
            **super().schema,
            ATTR_ZONES: {z.idx: z.schema for z in self._zones},
        }

    @property
    def params(self) -> dict:
        return {
            **super().params,
            ATTR_ZONES: {z.idx: z.params for z in self._zones},
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            ATTR_ZONES: {z.idx: z.status for z in self._zones},
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

        self._dhw_sensor = None
        self._dhw_valve = None
        self._htg_valve = None

    def __repr__(self) -> str:
        return f"{self._ctl.id} (controller)"

    def __str__(self) -> str:  # TODO: WIP
        return json.dumps({self._ctl.id: self.schema})

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

                if device is not None:
                    qos = {"priority": Priority.LOW, "retries": 2}
                    for code in ("0008", "3EF1"):
                        device._send_cmd(code, qos)

        # if msg.code == "0009" and msg.verb in (" I", "RP"):
        #     if "domain_id" in msg.payload:
        #         self._relay_failsafes[msg.payload["domain_id"]] = msg

        if msg.code == "3150" and msg.verb in (" I", "RP"):
            self._heat_demands[msg.payload["domain_id"]] = msg
            if "domain_id" in msg.payload:
                self._heat_demands[msg.payload["domain_id"]] = msg
                if msg.payload["domain_id"] == "FC":
                    self._heat_demand = msg.payload

        # if msg.code in ("3220", "3B00", "3EF0"):  # self.heating_control is None and
        #     find_htg_relay(msg, prev=prev_msg)

    def _send_cmd(self, code, **kwargs) -> None:
        dest = kwargs.pop("dest_addr", self._ctl.id)
        payload = kwargs.pop("payload", "00")
        super()._send_cmd(code, dest, payload, **kwargs)

    @property
    def devices(self) -> List[Device]:
        return self._ctl.devices

    # def _get_zone(self, *args, **kwargs):
    #     return self._evo._get_zone(*args, **kwargs)

    @property
    def heating_control(self) -> Device:
        return self._htg_control

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
    def dhw_sensor(self) -> Device:
        """Blah it now.

        Check and Verb the DHW sensor (07:) of this system/CTL (if there is one).

        There is only 1 way to find a controller's DHW sensor:
        1.  The 10A0 RQ/RP *from/to a 07:* (1x/4h)

        The RQ is initiated by the DHW, so is not authorative (the CTL will RP any RQ).
        The I/1260 is not to/from a controller, so is not useful.
        """  # noqa: D402

        # 07:38:39.124 047 RQ --- 07:030741 01:102458 --:------ 10A0 006 00181F0003E4
        # 07:38:39.140 062 RP --- 01:102458 07:030741 --:------ 10A0 006 0018380003E8

        # if "10A0" in self._msgs:
        #     return self._msgs["10A0"].dst.addr

        return self._dhw_sensor

    def _set_dhw_sensor(self, device: Device) -> None:  # self._sensor
        """Set the temp sensor for this DHW system (07: only)."""

        if self._dhw_sensor != device and self._dhw_sensor is not None:
            raise CorruptStateError(
                f"{ATTR_ZONE_SENSOR} shouldn't change: {self._dhw_sensor} to {device}"
            )

        if not isinstance(device, Device) or device.type != "07":
            raise TypeError(f"{ATTR_ZONE_SENSOR} can't be: {device}")

        if self._dhw_sensor is None:
            self._dhw_sensor = device
            device._set_parent(self, domain="FA")

    @property
    def hotwater_valve(self) -> Device:
        return self._dhw_valve

    def _set_dhw_valve(self, device: Device) -> None:  # self._dhw_valve
        """Set the hotwater valve relay for this DHW system (13: only)."""

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
    def heating_valve(self) -> Device:
        return self._htg_valve

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
    def tpi_params(self) -> Optional[float]:  # 1100
        return self._get_msg_value("1100")

    @property
    def relay_demands(self) -> Optional[dict]:  # 0008
        if self._relay_demands:
            return {
                k: v.payload["relay_demand"] for k, v in self._relay_demands.items()
            }

    @property
    def heat_demand(self) -> Optional[float]:  # 3150/FC
        if self._heat_demand:
            return self._heat_demand["heat_demand"]

    @property
    def heat_demands(self) -> Optional[dict]:  # 3150
        if self._heat_demands:
            return {k: v.payload["heat_demand"] for k, v in self._heat_demands.items()}

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

        schema = {ATTR_CONTROLLER: self._ctl.id}

        # devices without a parent zone, NB: CTL can be a sensor for a zones
        orphans = [
            d.id for d in self._ctl.devices if not d._domain_id and d.type != "02"
        ]
        orphans.sort()
        # system" schema[ATTR_SYSTEM][ATTR_ORPHANS] = orphans

        schema[ATTR_SYSTEM] = {
            ATTR_HTG_CONTROL: self.heating_control.id
            if self.heating_control is not None
            else None,
            ATTR_ORPHANS: orphans,
        }

        # schema[ATTR_STORED_HW] = self.dhw.schema if self.dhw is not None else None

        schema[ATTR_UFH_CONTROLLERS] = {
            u.id: u.schema
            for u in sorted(
                [d for d in self._ctl.devices if d.type == "02"], key=lambda x: x.id
            )
        }

        return schema

    @property
    def params(self) -> dict:
        """Return the system's configuration."""

        params = {}

        params[ATTR_SYSTEM] = {
            "mode": self._get_msg_value("2E04"),  # **self.mode()
            "language": self._get_msg_value("0100", "language"),
            ATTR_HTG_CONTROL: {},
        }

        if self.heating_control is not None:
            params[ATTR_SYSTEM][ATTR_HTG_CONTROL] = {
                "tpi_params": self.heating_control._get_msg_value("1100"),
                "boiler_setpoint": self.heating_control._get_msg_value("22D9"),
            }

        # params[ATTR_STORED_HW] = self.dhw.params if self.dhw is not None else None

        # ufh_controllers = [
        #     {d.id: d.config}
        #     for d in sorted(self.devices, key=lambda x: x.idx)
        #     if d.type == "02"
        # ]
        # ufh_controllers.sort()
        # config[ATTR_UFH_CONTROLLERS] = ufh_controllers

        # orphans = [
        #     {d.id: d.config}
        #     for d in sorted(self.devices, key=lambda x: x.idx)
        #     if d._zone is None
        #     # and d._ctl != d
        # ]  # devices without a parent zone, CTL can be a sensor for a zones
        # orphans.sort()
        # config[ATTR_ORPHANS] = orphans

        return params

    @property
    def status(self) -> dict:
        """Return the system's current state."""

        result = {ATTR_SYSTEM: {}}

        if self.heating_control is not None:
            result[ATTR_SYSTEM][ATTR_HTG_CONTROL] = self.heating_control.status

        # result[ATTR_STORED_HW] = self.dhw.status if self.dhw is not None else None

        result[ATTR_DEVICES] = {
            d.id: d.status
            for d in sorted(self._ctl.devices, key=lambda x: x.id)
            if d.id != self._ctl.id
        }

        result["heat_demand"] = self.heat_demand
        result["heat_demands"] = self.heat_demands
        result["relay_demands"] = self.relay_demands

        return result


class System(SysDatetime, SysFaultLog, SystemBase):
    """The Controller class."""

    def __init__(self, gwy, ctl, **kwargs) -> None:
        super().__init__(gwy, ctl, **kwargs)

        self._heat_demands = {}
        self._relay_demands = {}
        self._relay_failsafes = {}

    def __repr__(self) -> str:
        return f"{self._ctl.id} (system)"


class Evohome(SysLanguage, SysMode, MultiZone, StoredHw, System):  # evohome
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

    @property
    def schema(self) -> dict:
        """Return the system's schema."""
        return super().schema

    @property
    def params(self) -> dict:
        """Return the system's current state."""
        return super().params

    @property
    def status(self) -> dict:
        """Return the system's current state."""
        return super().status


# class Chronotherm(System):
# class Hometronics(System):
# class Sundial(System):
# class Cm927(System):
#     def __init__(self, gwy, ctl, synchronizer=False, **kwargs) -> None:
#         pass


SYSTEM_CLASSES = {"01": Evohome, "12": System, "22": System, "23": System}
