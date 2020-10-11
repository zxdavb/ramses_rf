#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""The evohome-compatible system (is a 1-1 with a controller)."""

# import asyncio
from datetime import timedelta
import json
import logging
from typing import Optional

# from .command import Priority, RQ_RETRY_LIMIT, RQ_TIMEOUT
from .const import (
    ATTR_CONTROLLER,
    ATTR_DEVICES,
    ATTR_SYSTEM,
    # CODE_0005_ZONE_TYPE,
    # CODE_000C_DEVICE_TYPE,
    DEVICE_HAS_ZONE_SENSOR,
    DEVICE_TYPES,
    DISCOVER_SCHEMA,
    DISCOVER_PARAMS,
    DISCOVER_STATUS,
    DISCOVER_ALL,
    SYSTEM_MODE_LOOKUP,
    SYSTEM_MODE_MAP,
    __dev_mode__,
)
from .devices import _dtm, Controller, Device
from .exceptions import CorruptStateError
from .schema import (
    ATTR_HTG_CONTROL,
    ATTR_ORPHANS,
    ATTR_STORED_HOTWATER,
    ATTR_UFH_CONTROLLERS,
    ATTR_ZONES,
)

from .zones import DhwZone, Zone

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


class System(Controller):
    """The Controller base class, supports child devices and zones only."""

    def __init__(self, gateway, ctl_addr, **kwargs) -> None:
        super().__init__(gateway, ctl_addr, **kwargs)

        assert ctl_addr.id not in gateway.system_by_id, "Duplicate controller address"

        gateway.systems.append(self)
        gateway.system_by_id[self.id] = self

        self._dhw = None
        self._boiler_control = None

        self.zones = []
        self.zone_by_idx = {}
        # self.zone_by_name = {}

        self._heat_demand = None

    def _proc_msg(self, msg) -> None:
        if msg.code in ("000A", "2309", "30C9") and not isinstance(msg.payload, list):
            pass
        else:
            super()._proc_msg(msg)

        if msg.code in ("000A", "2309", "30C9") and isinstance(msg.payload, list):
            pass

        if msg.code == "3150" and msg.verb in (" I", "RP"):
            if msg.payload.get("domain_id") == "FC":
                self._heat_demand = msg.payload["heat_demand"]

        # if msg.code in ("0005", "000C", "2E04"):
        #     pass
        # elif "zone_idx" in msg.payload:
        #     pass
        # else:
        #     assert False, "Unknown packet code"

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return f"{self.id} ({DEVICE_TYPES.get(self.type)})"

    def __str__(self) -> str:  # TODO: WIP
        """Return a brief readable string representation of this object."""
        return json.dumps({self.id: self.schema})

    def get_zone(
        self, domain_id, zone_type=None, sensor=None, actuators=None
    ) -> Optional[Zone]:
        """Return a zone (will create it if required).

        Can also set a zone's sensor, and zone_type.
        """

        if domain_id == "FA":
            zone = self.dhw if self.dhw is not None else DhwZone(self)

        elif int(domain_id, 16) < self._gwy.config["max_zones"]:
            zone = self.zone_by_idx.get(domain_id)
            if zone is None:
                zone = Zone(self, domain_id)
            if zone_type is not None:
                zone._set_type(zone_type)

        elif domain_id in ("FC", "FF"):
            return

        else:
            raise ValueError("Unknown zone_type/domain_id")

        if sensor is not None:
            zone._set_sensor(sensor)  # TODO: check not an address

        if actuators is not None:
            zone.devices = actuators  # TODO: check not an address
            zone.device_by_id = {d.id: d for d in actuators}

        return zone

    @property
    def dhw(self) -> DhwZone:
        return self._dhw

    @dhw.setter
    def dhw(self, dhw: DhwZone) -> None:
        if not isinstance(dhw, DhwZone):
            raise ValueError

        if self._dhw is not None and self._dhw != dhw:
            raise CorruptStateError("The DHW has changed")

        if self._dhw is None:
            # self._gwy.get_device(xxx)
            # self.add_device(dhw.sensor)
            # self.add_device(dhw.relay)
            self._dhw = dhw

    @property
    def boiler_control(self) -> Device:
        return self._boiler_control

    @boiler_control.setter
    def boiler_control(self, device: Device) -> None:
        """Set the heater relay for this system (10: or 13:)."""

        if not isinstance(device, Device) or device.type not in ("10", "13"):
            raise TypeError

        if self._boiler_control is not None and self._boiler_control != device:
            raise CorruptStateError("The boiler relay has changed")
        # elif device.evo is not None and device.evo != self:
        #     raise LookupError  #  do this in self._gwy.get_device()

        if self._boiler_control is None:
            self._boiler_control = device
            device._set_domain(ctl=self)

    @property
    def schema(self) -> dict:
        """Return the system's schema."""

        schema = {ATTR_CONTROLLER: self.id}

        # devices without a parent zone, NB: CTL can be a sensor for a zones
        orphans = [d.id for d in self.devices if not d._domain_id and d.type != "02"]
        orphans.sort()
        # system" schema[ATTR_SYSTEM][ATTR_ORPHANS] = orphans

        schema[ATTR_SYSTEM] = {
            ATTR_HTG_CONTROL: self.boiler_control.id
            if self.boiler_control is not None
            else None,
            ATTR_ORPHANS: orphans,
        }

        schema[ATTR_STORED_HOTWATER] = self.dhw.schema if self.dhw is not None else None

        schema[ATTR_UFH_CONTROLLERS] = {
            u.id: u.schema
            for u in sorted(
                [d for d in self.devices if d.type == "02"], key=lambda x: x.id
            )
        }

        schema[ATTR_ZONES] = {
            z.idx: z.schema for z in sorted(self.zones, key=lambda x: x.idx)
        }

        schema["device_info"] = {
            d.id: d.hardware_info for d in self.devices if d.hardware_info is not None
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

        if self.boiler_control is not None:
            params[ATTR_SYSTEM][ATTR_HTG_CONTROL] = {
                "tpi_params": self.boiler_control._get_msg_value("1100"),
                "boiler_setpoint": self.boiler_control._get_msg_value("22D9"),
            }

        params[ATTR_STORED_HOTWATER] = self.dhw.params if self.dhw is not None else None

        params[ATTR_ZONES] = {
            z.idx: z.params for z in sorted(self.zones, key=lambda x: x.idx)
        }

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

        result = {}

        result[ATTR_SYSTEM] = {"datetime": self._get_msg_value("313F")}

        if self.boiler_control is not None:
            result[ATTR_SYSTEM][ATTR_HTG_CONTROL] = self.boiler_control.status

        result[ATTR_STORED_HOTWATER] = self.dhw.status if self.dhw is not None else None

        result[ATTR_ZONES] = {
            z.idx: z.status for z in sorted(self.zones, key=lambda x: x.idx)
        }

        result[ATTR_DEVICES] = {
            d.id: d.status
            for d in sorted(self.devices, key=lambda x: x.id)
            if d.id != self.id
        }

        return result

    @property
    def tpi_params(self) -> Optional[float]:  # 1100
        return self._get_msg_value("1100")

    @property
    def sync_tpi(self) -> Optional[float]:  # 3B00
        return self._get_msg_value("3B00", "sync_tpi")

    @property
    def heat_demand(self) -> Optional[float]:  # 3150/FC
        return self._heat_demand


class EvoSystem(System):
    """The EvoSystem class - some controllers are evohome-compatible."""

    def __init__(self, gateway, ctl_addr, **kwargs) -> None:
        super().__init__(gateway, ctl_addr, **kwargs)

        self._prev_30c9 = None
        self._fault_log = {}
        self._mode = None

        # self._discover()

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        if self._gwy.config["disable_discovery"]:
            return
        super()._discover()

        if discover_flag & DISCOVER_SCHEMA:
            [  # 000C: find the HTG relay and DHW sensor, if any (DHW relays in DHW)
                self._send_cmd("000C", payload=dev_type)
                for dev_type in ("000F", "000D")  # CODE_000C_DEVICE_TYPE
                # for dev_type, description in CODE_000C_DEVICE_TYPE.items() fix payload
                # if description is not None
            ]

            [  # 0005: find any configured zones, + their type (RAD, UFH, VAL, MIX, ELE)
                self._send_cmd("0005", payload=f"00{zone_type}")
                for zone_type in ("08", "09", "0A", "0B", "11")  # CODE_0005_ZONE_TYPE
                # for zone_type, description in CODE_0005_ZONE_TYPE.items()
                # if description is not None
            ]

        if discover_flag & DISCOVER_PARAMS:
            self._send_cmd("1100", payload="FC")  # TPI params
            self._send_cmd("0100")  # language

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("2E04", payload="FF")  # system mode
            for code in ("1F09", "313F"):  # system_sync, datetime
                self._send_cmd(code)

        # TODO: test only
        # asyncio.create_task(
        #     self.async_set_mode(5, dt_now() + timedelta(minutes=120))
        #     # self.async_set_mode(5)
        #     # self.async_reset_mode()
        # )

        # # for code in ("3B00"):  # 3EF0, 3EF1
        # #     for payload in ("0000", "00", "F8", "F9", "FA", "FB", "FC", "FF"):
        # #         self._send_cmd(code, payload=payload)

        # # TODO: opentherm: 1FD4, 22D9, 3220

        # TODO: Get the fault log entries
        # self._fault_log.req_log(log_idx=0)
        # # for log_idx in range(0, 0x6):  # max is 0x3C?, 0x3F (highest log is 0x3E?)
        # #     self._send_cmd("0418", payload=f"{log_idx:06X}", priority=Priority.LOW)

    def _proc_msg(self, msg, prev_msg=None):
        """Eavesdrop packets, or pairs of packets, to maintain the system state."""

        def is_exchange(this, prev):  # TODO:use is?
            return this.src is prev.dst and this.dst is prev.src.addr

        def find_htg_relay(this, prev=None):
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
                self.boiler_control = heater

        def find_dhw_sensor(this):
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
                    self.get_zone("FA")
                self.dhw._set_sensor(sensor)

        def find_zone_sensors() -> None:
            """Determine each zone's sensor by matching zone/sensor temperatures.

            The temperature of each zone is reliably known (30C9 array), but the sensor
            for each zone is not. In particular, the controller may be a sensor for a
            zone, but unfortunately it does not announce its sensor temperatures.

            In addition, there may be 'orphan' (e.g. from a neighbour) sensors
            announcing temperatures with the same value.

            This leaves only a process of exclusion as a means to determine which zone
            uses the controller as a sensor.
            """

            # A reasonable assumption from this point on: a zone's _temperature attr has
            # just been updated via the controller's 30C9 pkt, and hasn't changed since.
            # It's also assumed that the gateway (18:) has received the same 30C9 pkts
            # from the sensors as the controller has: for some this may not be reliable.
            # The final assumption: the controller, as a sensor, has a temp distinct
            # from all others (so another sensor isn't matched to the controllers zone).
            # If required (and it's not clear that it is required), the above can be
            # mitigated by confirming a sensor after two (consistent) matches.

            prev_msg, self._prev_30c9 = self._prev_30c9, msg
            if prev_msg is None:
                return

            if len([z for z in self.zones if z.sensor is None]) == 0:
                return  # (currently) no zone without a sensor

            # if self._gwy.serial_port:  # only if in monitor mode...
            secs = self._get_msg_value("1F09", "remaining_seconds")
            if secs is None or msg.dtm > prev_msg.dtm + timedelta(seconds=secs):
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
                        zone.sensor.controller = self
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
            # want to avoid complexity of z._temperature
            # zone = self.zone_by_idx[zone_idx]
            # if zone._temperature is None:
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
                _LOGGER.debug("   - matched sensor: %s (by exclusion)", self.id)
                zone = self.zone_by_idx[zone_idx]
                zone._set_sensor(self)
                zone.sensor.controller = self

            _LOGGER.debug("System state (finally): %s", self)

        super()._proc_msg(msg)

        # if msg.code == "0005" and prev_msg is not None:
        #     zone_added = bool(prev_msg.code == "0004")  # else zone_deleted

        if msg.code == "0418" and msg.verb in (" I", "RP"):  # this is a special case
            _LOGGER.debug("Zone(%s).update: Received RP/0418 (fault_log)", self.id)
            # self._fault_log.add_entry(msg)
            # do the following only if we had: self._fault_log.req_log(log_idx=0)
            # self._fault_log.req_entry(log_idx=payload["log_idx"] + 1)
            if "log_idx" in msg.payload:
                self._fault_log[msg.payload["log_idx"]] = msg

        if msg.code == "2E04" and msg.verb in (" I", "RP"):  # this is a special case
            self._mode = msg.payload

        if msg.code == "30C9" and isinstance(msg.payload, list):  # msg.is_array:
            find_zone_sensors()

        if msg.code == "3EF1" and msg.verb == "RQ":  # relay attached to a burner
            if msg.dst.type == "13":  # this is the TPI relay
                pass
            if msg.dst.type == "10":  # this is the OTB
                pass

        if prev_msg is not None and prev_msg.src.controller is not None:
            if prev_msg.src.controller is not self:
                return

        # if msg.src.type == "01" and msg.dst.controller is None:  # 3EF0
        #     msg.dst.controller = msg.src  # useful for TPI/OTB, uses 3EF0

        if msg.code in ("3220", "3B00", "3EF0"):  # self.boiler_control is None and
            find_htg_relay(msg, prev=prev_msg)

        if msg.code in ("10A0", "1260"):  # self.dhw.sensor is None and
            find_dhw_sensor(msg)

        # else:
        #     assert False, "Unknown packet code"

    # def fault_log(self, force_update=False) -> Optional[list]:  # 0418
    #     # TODO: try to discover fault codes
    #     for log_idx in range(0x00, 0x3C):  # 10 pages of 6
    #         self._send_cmd("0418", payload=f"{log_idx:06X}")

    #     return [f.payload for f in self._fault_log.values()]

    @property
    def language(self) -> Optional[str]:  # 0100,
        return self._get_msg_value("0100", "language")

    @property
    def mode(self) -> dict:  # 2E04
        """Return the system mode."""
        # self._send_cmd("2E04", payload="FF")  # system mode
        return self._mode

    async def set_mode(self, mode, until=None):  # 2E04
        """Set the system mode for a specified duration, or indefinitely."""

        if isinstance(mode, int):
            mode = f"{mode:02X}"
        elif not isinstance(mode, str):
            raise TypeError("Invalid system mode")
        elif mode in SYSTEM_MODE_LOOKUP:
            mode = SYSTEM_MODE_LOOKUP[mode]

        if mode not in SYSTEM_MODE_MAP:
            raise ValueError("Unknown system mode")

        until = _dtm(until) + "00" if until is None else "01"

        self._send_cmd("2E04", verb=" W", payload=f"{mode}{until}")

    async def reset_mode(self) -> None:  # 2E04
        """Revert the system mode to Auto."""  # TODO: is it AutoWithReset?
        self._send_cmd("2E04", verb=" W", payload="00FFFFFFFFFFFF00")
