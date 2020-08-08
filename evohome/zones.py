"""The entities for Honeywell's RAMSES II / Residential Network Protocol."""
import asyncio
import json
import logging
from typing import Any, Optional

from .command import Schedule, Priority, RQ_RETRY_LIMIT, RQ_TIMEOUT
from .const import (
    DEVICE_HAS_ZONE_SENSOR,
    DEVICE_IS_ACTUATOR,
    DHW_STATE_MAP,
    MAX_ZONES,
    ZONE_CLASS_MAP,
    ZONE_TYPE_MAP,
    ZONE_MODE_LOOKUP,
    ZONE_MODE_MAP,
    __dev_mode__,
)
from .devices import Controller, Device, Entity, HeatDemand, _dtm
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
        value = float(value)
    except ValueError:
        raise ValueError("Invalid temperature")

    if value < 0:
        raise ValueError("Invalid temperature")

    return f"{int(value*100):04X}"


class ZoneBase(Entity):
    """The Domain/Zone base class."""

    def __init__(self, controller, zone_idx) -> None:
        super().__init__(controller._gwy, zone_idx, controller=controller)

        self._zone_type = None

    def __repr__(self):
        return json.dumps(self.schema, indent=2)

    def __str__(self):
        return f"{self._ctl.id}/{self.id} ({self._zone_type})"

    def _command(self, code, **kwargs) -> None:
        kwargs["dest_addr"] = kwargs.get("dest_addr", self._ctl.id)
        kwargs["payload"] = kwargs.get("payload", f"{self.id}00")
        super()._command(code, **kwargs)

    async def _get_msg(self, code) -> Optional[Any]:  # Optional[Message]:
        # if possible/allowed, simply get an up-todate packet from the controller
        if not self._gwy.config["listen_only"]:
            # self._msgs.pop(code, None)  # this is done in self._command()
            self._command(code, payload=f"{self.id}00", priority=Priority.ASAP)
            for _ in range(RQ_RETRY_LIMIT):  # TODO: check rq_len
                await asyncio.sleep(RQ_TIMEOUT)
                if code in self._msgs:
                    break  # return self._msgs[code]

        # otherwise, leverage an eavesdropped message, if any
        return self._msgs.get(code)


class DhwZone(ZoneBase, HeatDemand):
    """The DHW class.

    FC - 0008, 0009, 1100, 3150, 3B00, (& rare: 0001, 1FC9)
    """

    def __init__(self, controller) -> None:
        _LOGGER.debug("Creating a DHW Zone for system %s", controller.id)
        super().__init__(controller, "HW")

        controller.dhw = self

        self._sensor = None
        self._relay = None
        self._zone_type = "DHW"

        self._discover()  # should be last thing in __init__()

    def _discover(self):
        if __dev_mode__ and self.id == "FC":  # dev/test code
            self.async_set_override(state="On")

        for code in ("10A0", "1100", "1260", "1F41"):  # TODO: what about 1100?
            self._command(code, payload="0000")
            self._command(code, payload="00")

    def update(self, msg) -> None:
        super().update(msg)

    @property
    def schema(self) -> dict:
        """Return the stored HW's schema."""

        return {
            "sensor": self._sensor.id if self._sensor else None,
            "relay": self._relay.id if self._relay else None,
        }

    @property  # setpoint, config, mode (not schedule)
    def params(self) -> dict:
        """Return the stored HW's configuration (excl. schedule)."""

        return {}

    @property  # temp, open_windows
    def status(self) -> dict:
        """Return the stored HW's current state."""

        return {}

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

    @sensor.setter
    def sensor(self, device: Device) -> None:
        """Set the sensor for this DHW (07:)."""

        if not isinstance(device, Device) or device.type != "07":
            raise TypeError

        if self._sensor is not None and self._sensor != device:
            raise LookupError
        # elif device.evo is not None and device.evo != self:
        #     raise LookupError  #  do this in add_devices

        if self._sensor is None:
            self._sensor = device
            device._zone = self  # self.add_device(device)

    @property
    def relay(self) -> Device:
        return self._relay

    @relay.setter
    def relay(self, device: Device) -> None:
        if not isinstance(device, Device) or device.type != "13":
            raise TypeError

        if self._relay is not None and self._relay != device:
            raise LookupError
        # elif device.evo is not None and device.evo != self:
        #     raise LookupError  #  do this in add_devices

        if self._relay is None:
            self._relay = device
            self.add_device(device)

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return self._get_msg_value("0008", "relay_demand")

    @property  # only seen with FC, but seems should pair with 0008?
    def relay_failsafe(self) -> Optional[float]:  # 0009
        return self._get_msg_value("0009")

    @property
    def config(self):  # 10A0
        attrs = ("setpoint", "overrun", "differential")
        return {x: self._get_msg_value("10A0", x) for x in attrs}

    @property
    def name(self) -> Optional[str]:  # N/A
        return "Stored HW"

    @property
    def setpoint_status(self):  # 1F41
        attrs = ["active", "mode", "until"]
        return {x: self._get_msg_value("1F41", x) for x in attrs}

    @property
    def temperature(self):  # 1260
        return self._get_msg_value("1260", "temperature")

    @property
    def tpi_params(self) -> Optional[float]:  # 1100
        return self._get_msg_value("1100")

    @property
    def sync_tpi(self) -> Optional[float]:  # 3B00
        return self._get_msg_value("3B00", "sync_tpi")

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

        self._command("1F41", verb=" W", payload=payload)
        return False

    async def reset_config(self) -> bool:  # 10A0
        """Reset the DHW parameters to their default values."""
        return False

    async def set_config(self, setpoint, overrun=None, differential=None) -> bool:
        """Set the DHW parameters."""
        return False


class Zone(ZoneBase):
    """The Zone class."""

    def __init__(self, controller, zone_idx) -> None:
        _LOGGER.debug("Creating a zone for system %s: %s", controller.id, zone_idx)
        super().__init__(controller, zone_idx)

        assert zone_idx not in controller.zone_by_id, "Duplicate zone idx on controller"
        if int(zone_idx, 16) >= MAX_ZONES:
            raise ValueError  # TODO: better to aloow to disable via assert?

        controller.zones.append(self)
        controller.zone_by_id[zone_idx] = self
        # controller.zone_by_name[self.name] = self

        self.devices = []
        self.device_by_id = {}

        self._sensor = None
        self._schedule = Schedule(controller, zone_idx)
        self._temperature = None  # TODO: is needed?

        self._discover()

    def _discover(self):
        if __dev_mode__ and self.id == "99":  # dev/test code
            asyncio.create_task(  # TODO: test/dev only
                self.async_cancel_override()
                # self.async_set_override(
                #     setpoint=15.9,
                #     mode="AdvancedOverride",
                #     # until=dt_now() + timedelta(minutes=120)
                # )
            )

        self._schedule.req_fragment()  # dont use self._command() here

        for code in ("0004", "000C"):
            self._command(code, payload=f"{self.id}00")

        for code in ("000A", "2349", "30C9"):
            self._command(code, payload=self.id)

        for code in ("12B0",):  # TODO: only if TRV zone, or if window_state is enabled?
            self._command(code, payload=self.id)

        # TODO: 3150(00?): how to do (if at all) & for what zone types?

    def update(self, msg):
        super().update(msg)

        # not UFH (it seems), but BDR or VAL; and possibly a MIX support 0008 too
        if msg.code in ("0008", "0009"):  # TODO: how to determine is/isn't MIX?
            assert msg.src.type in ("01", "13")  # 01 as a stat
            assert self._zone_type in (None, "BDR", "VAL")

            if self._zone_type is None:
                self._set_zone_type("BDR")  # might eventually be: "VAL"

        elif msg.code == "0404" and msg.verb == "RP":
            _LOGGER.debug("Zone(%s).update: Received schedule RP for zone: ", self.id)
            self._schedule.add_fragment(msg)

        elif msg.code == "30C9":  # required for sensor matching
            assert msg.src.type in DEVICE_HAS_ZONE_SENSOR + ("01",)
            self._temperature = msg.payload["temperature"]

        elif msg.code == "3150":  # TODO: and msg.verb in (" I", "RP")?
            assert msg.src.type in ("02", "04", "13")
            assert self._zone_type in (None, "TRV", "UFH", "VAL")

            if msg.src.type in ("02", "04", "13"):
                zone_type = ZONE_CLASS_MAP[msg.src.type]
                self._set_zone_type("VAL" if zone_type == "BDR" else zone_type)

    @property  # id, type
    def schema(self) -> dict:
        """Return the zone's schema."""

        return {
            "type": self._zone_type,
            "sensor": self._sensor.id if self._sensor else None,
            "devices": [d.id for d in self.devices],
        }

    @property  # setpoint, config, mode (not schedule)
    def params(self) -> dict:
        """Return the zone's configuration (excl. schedule)."""

        return {
            "setpoint": self.setpoint,
            "mode": self.mode,
            "configuration": self.configuration,
        }

    @property  # temp, open_windows
    def status(self) -> dict:
        """Return the zone's current state."""

        return {
            "temperature": self.temperature,
            #  "open_window": self.open_window
        }

    @property
    def sensor(self) -> Device:
        return self._sensor

    @sensor.setter
    def sensor(self, device: Device):
        """Set the sensor for this zone (01:, 03:, 04:, 12:, 22:, 34:)."""

        if not isinstance(device, Device) or not hasattr(device, "temperature"):
            if not isinstance(device, Controller):
                raise TypeError

        if self._sensor is not None and self._sensor is not device:
            raise LookupError
        # elif device.evo is not None and device.evo != self:
        #     raise LookupError  #  do this in add_devices

        if self._sensor is None:
            self._sensor = device  # if TRV, zone type likely (but not req'd) RadValve
            self.add_device(device)

    @property
    def type(self) -> Optional[str]:
        if self._zone_type is not None:  # isinstance(self, ???)
            return self._zone_type

        # TODO: try to cast an initial type
        dev_types = [d.dev_type for d in self.devices if d.dev_type in ZONE_CLASSES]

        # contrived code is for edge case: TRV is being used as sensor for non-TRV zone
        for _type in (t for t in dev_types if t != "TRV"):
            self._zone_type = _type
            break
        else:
            if "TRV" in dev_types:
                self._zone_type = "TRV"

        if self._zone_type is not None:
            self.__class__ = ZONE_CLASSES[self._zone_type]
            _LOGGER.debug("Set Zone %s type as %s", self.id, self._zone_type)

        return self._zone_type

    def _set_zone_type(self, zone_type: str):
        """Set the zone's type, after validating it.

        There are two possible sources for the type of a zone:
        1. eavesdropping packet codes
        2. analyzing child devices

        Both will execute a zone.type = type (i.e. via this setter).
        """

        if zone_type not in ZONE_CLASSES:
            raise ValueError(f"Not a known zone type: {zone_type}")

        if self._zone_type is not None:
            if self._zone_type != zone_type and (
                self._zone_type != "BDR" and zone_type != "VAL"
            ):
                raise CorruptStateError(
                    f"Zone {self} has a mismatched type: "
                    f"old={self._zone_type}, new={zone_type}",
                )

        self._zone_type = zone_type
        self.__class__ = ZONE_CLASSES[zone_type]
        _LOGGER.debug("Zone %s: type now set to %s", self.id, self._zone_type)

    @property
    def description(self) -> str:
        return ZONE_TYPE_MAP.get(self._zone_type)

    def schedule(self, force_update=False) -> Optional[dict]:
        """Return the schedule if any."""
        if False or __dev_mode__:
            return
        return self._schedule.schedule if self._schedule else None

    @staticmethod
    def _most_recent_msg(msg_0, msg_1):  # -> Message:
        # if always_use_controllers:
        #     return msg_0
        if msg_0 is not None:
            return msg_1 if msg_1 is not None and msg_0.dtm < msg_1.dtm else msg_0
        return msg_1

    @property
    async def name(self) -> Optional[str]:  # 0004
        await self._get_msg("0004")  # if possible/allowed, get an up-to-date pkt

        return self._get_msg_value("0004", "name")

    @property
    async def configuration(self) -> Optional[dict]:  # 000A
        await self._get_msg("000A")  # if possible/allowed, get an up-to-date pkt

        msg_0 = self._ctl._msgs.get("000A")  # authorative, but 1/hourly
        msg_1 = self._msgs.get("000A")  # possibly more up-to-date (or null)

        if msg_1 is self._most_recent_msg(msg_0, msg_1):  # could be: None is None
            result = msg_1.payload["000A"]
        else:
            result = {
                k: v
                for z in msg_0.payload
                for k, v in z.items()
                if z["zone_idx"] == self.id
            }

        return {k: v for k, v in result.items() if k != "zone_idx"} if result else None

    @property
    async def actuators(self) -> Optional[list]:  # 000C
        await self._get_msg("000C")  # if possible/allowed, get an up-to-date pkt

        if "000C" in self._msgs:
            return self._msgs["000C"].payload["actuators"]
        return [d.id for d in self.devices if d[:2] in DEVICE_IS_ACTUATOR]

    @property
    async def temperature(self) -> Optional[float]:  # 30C9
        await self._get_msg("30C9")  # if possible/allowed, get an up-to-date pkt

        msg_0 = self.ctl._msgs.get("30C9")  # most authorative
        msg_1 = self.sensor._msgs.get("30C9")  # possibly most up-to-date

        if msg_1 is self._most_recent_msg(msg_0, msg_1):  # could be: None is None
            return msg_1.payload["temperature"] if msg_1 is not None else None

        self._temperature = {
            k: v
            for z in msg_0.payload
            for k, v in z.items()
            if z["zone_idx"] == self.id
        }["temperature"]

        return self._temperature

    @property
    async def setpoint(self) -> Optional[float]:  # 2309 (2349 is a superset of 2309)
        await self._get_msg("2309")  # if possible/allowed, get an up-to-date pkt

        msg_0 = self.ctl._msgs.get("2309")  # most authorative  # TODO: why 2349?
        msg_1 = self._msgs.get("2309")  # possibly more up-to-date (or null)

        if msg_1 is self._most_recent_msg(msg_0, msg_1):  # could be: None is None
            return msg_1.payload["setpoint"] if msg_1 is not None else None

        return {
            k: v
            for z in msg_0.payload
            for k, v in z.items()
            if z["zone_idx"] == self.id
        }["setpoint"]

    @property
    async def mode(self) -> Optional[dict]:  # 2349
        await self._get_msg("2349")  # if possible/allowed, get an up-to-date pkt

        result = self._get_msg_value("2349")
        return {k: v for k, v in result.items() if k != "zone_idx"} if result else None

    async def cancel_override(self):  # 2349
        """Revert to following the schedule."""
        await self.set_override()

    async def set_override(self, mode=None, setpoint=None, until=None):
        """Override the setpoint for a specified duration, or indefinitely.

        The setpoint has a resolution of 0.1 C. If a setpoint temperature is required,
        but none is provided, the controller will use the maximum possible value.

        The until has a resolution of 1 min.

        Incompatible combinations:
          - mode == Follow & setpoint not None (will silently ignore setpoint)
          - mode == Temporary & until is None (will silently drop W packet)
        """

        if mode is None and until is None:
            mode = "00" if setpoint is None else "02"  # Follow, Permanent
        elif mode is None:  # and until is not None
            mode = "04"  # Temporary
        elif isinstance(mode, int):
            mode = f"{mode:02X}"
        elif not isinstance(mode, str):
            raise TypeError("Invalid zone mode")
        elif mode in ZONE_MODE_LOOKUP:
            mode = ZONE_MODE_LOOKUP[mode]

        if mode not in ZONE_MODE_MAP:
            raise ValueError("Unknown zone mode")

        setpoint = _temp(setpoint)  # None means max, if a temp is required

        if until is None:
            mode = "01" if mode == "04" else mode
            payload = f"{self.id}{setpoint}{mode}FFFFFF"
        else:  # required only by: 04, Temporary, ignored by others
            payload = f"{self.id}{setpoint}{mode}FFFFFF{_dtm(until)}"

        self._command("2349", verb=" W", payload=payload)


class ZoneHeatDemand:  # not all zone types call for heat
    """Not all zones call for heat."""

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._get_msg_value("3150", "heat_demand")

    @property
    def heat_demand_alt(self) -> Optional[float]:  # 3150
        if not hasattr(self, "devices"):
            return

        demands = [
            d.heat_demand
            for d in self._ctl.devices
            if d.id in self.devices
            and hasattr(d, "heat_demand")
            and d.heat_demand is not None
        ]
        return max(demands + [0]) if demands else None


class BdrZone(Zone):  # Electric zones (do *not* call for heat)
    """Base for Electric Heat zones.

    For a small (5A) electric load controlled by a BDR91 (never calls for heat).
    """

    def update(self, msg):
        super().update(msg)

        # ZV zones are Elec zones that also call for heat; ? and also 1100/unkown_0 = 00
        if msg.code == "3150":
            self._set_zone_type("VAL")

    @property
    def actuator_enabled(self) -> Optional[bool]:  # 3EF0
        return self._get_msg_value("3EF0", "actuator_enabled")

    @property
    def actuator_state(self) -> Optional[float]:  # 3EF1
        return self._get_msg_value("3EF1")


class ValZone(BdrZone, ZoneHeatDemand):  # Zone valve zones
    """Base for Zone Valve zones.

    For a motorised valve controlled by a BDR91 (will also call for heat).
    """


class TrvZone(Zone, ZoneHeatDemand):  # Radiator zones
    """Base for Radiator Valve zones.

    For radiators controlled by HR92s or HR80s (will also call for heat).
    """

    # 3150 (heat_demand) but no 0008 (relay_demand)

    @property
    async def window_open(self) -> Optional[bool]:  # 12B0
        await self._get_msg("12B0")  # if possible/allowed, get an up-to-date pkt

        return self._get_msg_value("12B0", "window_open")


class UfhZone(Zone, ZoneHeatDemand):  # UFH zones
    """Base for Underfloor Heating zones.

    For underfloor heating controlled by an HCE80 or HCC80 (will also call for heat).
    """

    @property
    def ufh_setpoint(self) -> Optional[float]:  # 3B00
        return self._get_msg_value("22C9")


class MixZone(Zone, ZoneHeatDemand):  # Mix valve zones
    """Base for Mixing Valve zones.

    For a modulating valve controlled by a HM80 (will also call for heat).
    """

    @property
    def configuration(self):
        attrs = ["max_flow_temp", "pump_rum_time", "actuator_run_time", "min_flow_temp"]
        return {x: self._get_msg_value("1030", x) for x in attrs}


ZONE_CLASSES = {
    "TRV": TrvZone,
    "BDR": BdrZone,
    "VAL": ValZone,
    "UFH": UfhZone,
    "MIX": MixZone,
    "DHW": DhwZone,
}
