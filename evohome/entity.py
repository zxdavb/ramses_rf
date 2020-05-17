"""The entities for Honeywell's RAMSES II / Residential Network Protocol."""
import logging
from typing import Any, Optional

from .command import Command
from .const import (
    COMMAND_SCHEMA,
    DEVICE_LOOKUP,
    DEVICE_TYPES,
    ZONE_TYPE_MAP,
    __dev_mode__,
)

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)


def dev_hex_to_id(device_hex: str, friendly_id=False) -> str:
    """Convert (say) '06368E' to '01:145038' (or 'CTL:145038')."""
    if device_hex == "FFFFFE":  # aka '63:262142'
        return ">null dev<" if friendly_id else "63:262142"
    if not device_hex.strip():  # aka '--:------'
        return f"{'':10}" if friendly_id else "--:------"
    _tmp = int(device_hex, 16)
    dev_type = f"{(_tmp & 0xFC0000) >> 18:02d}"
    if friendly_id:
        dev_type = DEVICE_TYPES.get(dev_type, f"{dev_type:<3}")
    return f"{dev_type}:{_tmp & 0x03FFFF:06d}"


def dev_id_to_hex(device_id: str) -> str:
    """Convert (say) '01:145038' (or 'CTL:145038') to '06368E'."""
    if len(device_id) == 9:  # e.g. '01:123456'
        dev_type = device_id[:2]
    else:  # len(device_id) == 10, e.g. 'CTL:123456', or ' 63:262142'
        dev_type = DEVICE_LOOKUP.get(device_id[:3], device_id[1:3])
    return f"{(int(dev_type) << 18) + int(device_id[-6:]):0>6X}"  # sans preceding 0x


class Entity:
    """The base class."""

    def __init__(self, entity_id, gateway) -> None:
        self._id = entity_id
        self._gwy = gateway
        self._evo = gateway.evo
        self._cmd_que = gateway.cmd_queue

        self._pkts = {}
        self.last_pkt = None

    def _discover(self):
        pass
        # raise NotImplementedError

    def _command(self, code, **kwargs):
        if self._gwy.config["listen_only"]:
            return
        if kwargs.get("dest_addr") is None:
            kwargs["dest_addr"] = self._evo.ctl_id
        if kwargs.get("payload") is None:
            kwargs["payload"] = "00"
        self._cmd_que.put_nowait(Command(self._gwy, code=code, **kwargs))

    def _get_pkt_value(self, code, key=None) -> Optional[Any]:
        if self._pkts.get(code):
            if isinstance(self._pkts[code].payload, list):
                return self._pkts[code].payload

            key = key if key is not None else COMMAND_SCHEMA[code]["name"]
            return self._pkts[code].payload.get(key)

    @property
    def pkt_codes(self) -> list:
        return list(self._pkts.keys())

    def update(self, msg) -> None:
        self.last_pkt = f"{msg.date}T{msg.time}"
        if msg.verb == " W":
            if msg.code in self._pkts and self._pkts[msg.code].verb != msg.verb:
                return
        if msg.verb == "RQ":  # and msg.payload:
            if msg.code in self._pkts and self._pkts[msg.code].verb != msg.verb:
                return
        # may get an RQ/W initially, but RP/I will override
        self._pkts.update({msg.code: msg})


class Domain(Entity):
    """Base for the domains: F8 (rare), F9, FA (not FC, FF).

    F8 - 1F09/W (rare)
    F9 - 0008
    FA - 0008
    FC - 0008, 0009, and others
    """

    def __init__(self, domain_id, gateway) -> None:
        _LOGGER.debug("Creating a new Domain %s", domain_id)
        super().__init__(domain_id, gateway)

        self._type = None
        # self.discover()

    def update(self, msg) -> None:
        super().update(msg)

        # try to cast a new type (must be a superclass of the current type)
        if msg.code in ["1100", "3150", "3B00"]:
            self.__class__ = TpiDomain

    @property
    def domain_id(self) -> str:
        return self._id

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return self._get_pkt_value("0008")

    @property  # only seen with FC, but seems should pair with 0008?
    def relay_failsafe(self) -> Optional[float]:  # 3150
        return self._get_pkt_value("0009")


class TpiDomain(Domain):
    """Base for the FC domain.

    FC - 0008, 0009, 1100, 3150, 3B00, (& rare: 0001, 1FC9)
    """

    @property
    def tpi_params(self) -> Optional[float]:  # 1100
        return self._get_pkt_value("1100")

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._get_pkt_value("3150")

    @property
    def sync_tpi(self) -> Optional[float]:  # 3B00
        return self._get_pkt_value("3B00")


class Device(Entity):
    """The Device class."""

    def __init__(self, device_id, gateway) -> None:
        _LOGGER.debug("Creating a new Device %s", device_id)
        super().__init__(device_id, gateway)

        # TODO: does 01: have a battery - could use a lookup from const.py
        self._has_battery = device_id[:2] in ["04", "12", "22", "30", "34"]
        self._device_type = DEVICE_TYPES.get(device_id[:2], f"{device_id[:2]:>3}")
        self._parent_zone = None

        attrs = gateway.known_devices.get(device_id)
        self._friendly_name = attrs.get("friendly_name") if attrs else None
        self._blacklist = attrs.get("blacklist", False) if attrs else False

        # TODO: causing queue.Full exception with -i
        self._discover()  # needs self._device_type

        self.parent_000c = None

    def _discover(self):
        # TODO: an attempt to actively discover the CTL rather than by eavesdropping
        # self._command("313F", dest_addr=NUL_DEV_ID, payload="FF")

        # for code in COMMAND_SCHEMA:  # TODO: testing only
        #     self._command(code, dest_addr=self._id, payload="0000")
        # return

        # do these even if battery-powered (e.g. device might be in rf_check mode)
        for code in ["1FC9"]:
            self._command(code, dest_addr=self._id)
        for code in ["0016"]:
            self._command(code, dest_addr=self._id, payload="0000")

        if self._id[:2] not in ["04", "07", "12", "22", "34"]:  # battery-powered?
            self._command("10E0", dest_addr=self._id)
        # else:  # TODO: it's unlikely anything respond to an RQ/1060 (an 01: doesn't)
        #     self._command("1060", dest_addr=self._id)  # payload len()?

    @property
    def description(self) -> Optional[str]:  # 10E0
        # 01:, and (rarely) 04:
        return self._get_pkt_value("10E0", "description")

    @property
    def device_id(self) -> str:
        return self._id

    @property
    def device_type(self) -> str:
        """Return a friendly device type string."""
        return self._device_type

    @property
    def parent_zone(self) -> Optional[str]:
        if self._parent_zone:  # We assume that: once set, it never changes
            return self._parent_zone
        for msg in self._pkts.values():
            if "parent_zone_idx" in msg.payload:
                self._parent_zone = msg.payload["parent_zone_idx"]
                break
        return self._parent_zone


class HasBattery:
    """Some devices have a battery."""

    @property
    def battery(self):
        battery_level = self._get_pkt_value("1060", "battery_level")
        low_battery = self._get_pkt_value("1060", "low_battery")
        if battery_level is not None:
            return {"low_battery": low_battery, "battery_level": battery_level}
        return {"low_battery": low_battery}


class HasTemperature:
    """Some devices have a temperature sensor."""

    @property
    def setpoint(self) -> Optional[Any]:  # 2309
        return self._get_pkt_value("2309", "setpoint")

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        return self._get_pkt_value("30C9", "temperature")


class Controller(Device):
    """The Controller class."""

    """[
            "10E0", "3150", "2309", "1F09", "30C9", "3B00", "0008", "000A",
            "0418", "313F", "2349", "0100", "12B0", "0009", "1100", "2E04",
            "0004"
        ]
    """

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a new Controller %s", device_id)
        super().__init__(device_id, gateway)

    def _discover(self):
        super()._discover()

        # Note: could use this to discover zones
        # for zone_idx in range(12):
        #     self._command("0004", payload=f"{zone_idx:02x}00")

        # system-related... (not working: 1280, 22D9, 2D49, 2E04, 3220, 3B00)
        self._command("1F09", payload="FF")
        for code in ["313F", "0100", "0002"]:
            self._command(code)

        for code in ["10A0", "1260", "1F41"]:  # stored DHW
            self._command(code)

        self._command("0005", payload="0000")
        self._command("1100", payload="FC")
        self._command("2E04", payload="FF")

        # TODO: 1100(), 1290(00x), 0418(00x):
        # for code in ["000C"]:
        #     for payload in ["F800", "F900", "FA00", "FB00", "FC00", "FF00"]:
        #         self._command(code, payload=payload)

        # for code in ["3B00"]:
        #     for payload in ["0000", "00", "F8", "F9", "FA", "FB", "FC", "FF"]:
        #         self._command(code, payload=payload)

    def update(self, msg):
        super().update(msg)

        # if msg.code == "30C9":  # then try to find the zone sensors...
        #     sensors = [d for d in self._evo.devices if hasattr(d, "temperature")]
        #     any(sensors)

    @property
    def fault_log(self):
        # WIP: try to discover fault codes
        # for num in range(0x00, 0x3C):  # 10 pages of 6
        #     self._command("0418", payload=f"{num:06X}")
        return None

    @property
    def system_mode(self):
        attrs = ["mode", "until"]
        return {x: self._get_pkt_value("2E04", x) for x in attrs}

    @property
    def parent_zone(self) -> None:
        return "FF"

    @property
    def language(self) -> Optional[str]:  # 0100,
        return self._get_pkt_value("0100")

    @property
    def tpi_relay(self) -> Optional[str]:
        relays = [d.device_id for d in self._evo.devices if d.device_type == "TPI"]
        if not __dev_mode__:
            assert len(relays) < 2  # This may fail for testing (i.e. 2 TPI relays)
        return relays[0] if relays else None

    @property
    def dhw_sensor(self) -> Optional[str]:
        sensors = [d.device_id for d in self._evo.devices if d.device_type == "DHW"]
        if not __dev_mode__:
            assert len(sensors) < 2  # This may fail for testing
        return sensors[0] if sensors else None


class DhwSensor(Device, HasBattery):
    """The DHW class, such as a CS92."""

    def __init__(self, dhw_id, gateway) -> None:
        # _LOGGER.debug("Creating a new DHW %s", dhw_id)
        super().__init__(dhw_id, gateway)

        # self._discover()

    def _TBD_discover(self):
        for code in ["10A0", "1260", "1F41"]:
            self._command(code)

    @property
    def parent_zone(self) -> None:
        return "FC"

    @property
    def temperature(self):
        return self._get_pkt_value("1260", "temperature")


class Thermostat(Device, HasTemperature, HasBattery):  # TODO: the THM, THm devices
    """The STA class, such as a TR87RF."""

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a new STA %s", device_id)
        super().__init__(device_id, gateway)


class TrvActuator(Device, HasTemperature, HasBattery):
    """The TRV class, such as a HR92."""

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a new TRV %s", device_id)
        super().__init__(device_id, gateway)

    @property
    def language(self) -> Optional[str]:  # 0100,
        return self._get_pkt_value("0100")

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._get_pkt_value("3150")

    @property
    def window_state(self) -> Optional[bool]:  # 12B0
        return self._get_pkt_value("12B0", "window_open")


class BdrSwitch(Device):
    """The BDR class, such as a BDR91."""

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a new BDR %s", device_id)
        super().__init__(device_id, gateway)

        self._is_tpi = None

    def _discover(self):
        super()._discover()

        return

        for code in COMMAND_SCHEMA:  # TODO: testing only
            # for payload in DOMAIN_MAP:  # TODO: testing only
            self._command(code, dest_addr=self._id)

        return

        # self._command("3B00", dest_addr=self._id)  # never got an RP from a RQ/3B00
        for code in ["3EF0", "3EF1"]:
            self._command(code, dest_addr=self._id, payload="0000")
        # for code in ["3B00", "3EF0"]:  # these don't work, for 00 or 0000
        #     self._command(code, dest_addr=self._id, payload="FF")

        # for code in ["0008", "1100", "3EF1"]:  # these work, for any payload
        #     self._command(code, dest_addr=self._id, payload="0000")

        # the 'real' DHW controller will return 1260/dhw_temp != None
        # [self._command("1260", dest_addr=self._id, payload=d) for d in DOMAIN_MAP]

    def update(self, msg):
        super().update(msg)

        if self._is_tpi is None:
            _ = self.is_tpi

    @property
    def is_tpi(self) -> Optional[bool]:  # 3B00
        if self._is_tpi is not None:
            return self._is_tpi

        def make_tpi() -> bool:
            self.__class__ = TpiSwitch
            self._device_type = "TPI"
            self._parent_zone = "FC"
            self._discover()
            return True

        # for code in self._get_pkt_value("1FC9"):
        #     if code["command"] == COMMAND_MAP["3B00"]:
        if "1FC9" in self._pkts and self._pkts["1FC9"].verb == "RP":
            self._is_tpi = "3B00" in self._pkts["1FC9"].payload
            if self._is_tpi:
                make_tpi()
            return self._is_tpi

        # try to cast a new type (must be a superclass of the current type)
        if "3B00" in self._pkts and self._pkts["3B00"].verb == " I":
            self._is_tpi = make_tpi()

        return self._is_tpi

    @property
    def actuator_enabled(self) -> Optional[float]:  # 3EF0
        return self._get_pkt_value("3EF0")

    @property
    def actuator_state(self) -> Optional[float]:  # 3EF1
        return self._get_pkt_value("3EF1")


class TpiSwitch(BdrSwitch):  # TODO: superset of BDR switch?
    """The TPI class, the BDR91 that controlls the boiler."""

    def _discover(self):
        # NOTE: do not super()._discover()

        for code in ["1100"]:
            self._command(code, dest_addr=self._id, payload="FC")

        # doesn't like like TPIs respond to a 3B00
        # for payload in ["00", "C8"]:
        #     for code in ["00", "FC", "FF"]:
        #         self._command("3B00", dest_addr=self._id, payload=f"{code}{payload}")


class Zone(Entity):
    """Base for the 12 named Zones."""

    def __init__(self, zone_idx, gateway) -> None:
        _LOGGER.debug("Creating a new Zone %s", zone_idx)
        super().__init__(zone_idx, gateway)

        self._sensor = None
        self._zone_type = None
        self._discover()

    def _discover(self):
        # if self._id != "01":  # TODO: testing only
        #     return

        for code in ["0004", "000C"]:
            self._command(code, payload=f"{self._id}00")

        for code in ["000A", "2349", "30C9"]:
            self._command(code, payload=self._id)

        # TODO: 12B0: only if RadValve zone, or whenever window_state is enabled?
        for code in ["12B0"]:
            self._command(code, payload=self._id)

        # TODO: 3150(00?): how to do (if at all) & for what zone types?
        # TODO: 0005(002), 0006(001), 0404(00?):

    @property
    def configuration(self):
        # if self._zone_type != "Radiator Valve":
        #     return {}

        attrs = ["local_override", "multi_room_mode", "openwindow_function"]
        attrs += ["max_temp", "min_temp"]
        return {a: self._get_pkt_value("000A", a) for a in attrs}

    @property
    def actuators(self) -> list:
        actuators = self._get_pkt_value("000C", "actuators")
        return actuators if actuators is not None else []

    @property
    def devices(self) -> list:
        devices = {d.device_id for d in self._evo.devices if d.parent_zone == self._id}
        return list(set(self.actuators) | devices)

    @property
    def name(self) -> Optional[str]:
        return self._get_pkt_value("0004", "name")

    @property
    def sensor(self) -> list:
        if self._sensor:
            return self._sensor

        # attempt to determine sensor for the zone...
        # self._sensor = ...

        return self._sensor

    @property
    def setpoint_status(self):
        attrs = ["setpoint", "mode", "until"]
        return {a: self._get_pkt_value("2349", a) for a in attrs}

    @property
    def temperature(self):
        return self._get_pkt_value("30C9")

    @property
    def zone_idx(self):
        return self._id

    @property
    def zone_type(self) -> Optional[str]:
        if self._zone_type:  # isinstance(self, ???)
            return self._zone_type

        # try to cast a new type (must be a superclass of the current type)
        for device in self.actuators:
            device_type = DEVICE_TYPES[device[:2]]
            if device_type in ZONE_CLASS_MAP:
                self.__class__ = ZONE_CLASS_MAP[device_type]
                self._zone_type = ZONE_TYPE_MAP[device_type]
                break

        return self._zone_type

    def update(self, msg):
        super().update(msg)

        if self._sensor is None:
            _ = self.sensor

        if self._zone_type is None:
            _ = self.zone_type


class HasHeatDemand:
    """Base for the 12 named Zones."""

    @property
    def heat_demand(self) -> Optional[float]:
        demands = [
            d.heat_demand if d.heat_demand else 0
            for d in self._evo.devices
            if d.device_id in self.devices and hasattr(d, "heat_demand")
        ]
        return max(demands + [0]) if demands else None


class TrvZone(Zone, HasHeatDemand):
    """Base for Radiator Valve zones.

    For radiators controlled by HR92s or HR80s (will also call for heat).
    """

    # 3150 (heat_demand) but no 0008 (relay_demand)

    @property
    def window_open(self):
        return self._get_pkt_value("12B0", "window_open")


class BdrZone(Zone):
    """Base for Electric Heat zones.

    For a small (5A) electric load controlled by a BDR91 (never calls for heat).
    """

    # if also call for heat, then is a ZoneValve

    @property
    def actuator_enabled(self) -> Optional[float]:  # 3EF0
        return self._get_pkt_value("3EF0")

    @property
    def actuator_state(self) -> Optional[float]:  # 3EF1
        return self._get_pkt_value("3EF1")

    def update(self, msg):
        super().update(msg)

        # does it also call for heat?
        if msg.code == "3150":  # or 1100/unkown_0 = 00
            self.__class__ = ValZone
            self._zone_type = ZONE_TYPE_MAP["VAL"]


class ValZone(BdrZone, HasHeatDemand):
    """Base for Zone Valve zones.

    For a motorised valve controlled by a BDR91 (will also call for heat).
    """


class UfhZone(Zone, HasHeatDemand):
    """Base for Underfloor Heating zones.

    For underfloor heating controlled by an HCE80 or HCC80 (will also call for heat).
    """

    @property
    def ufh_setpoint(self) -> Optional[float]:  # 3B00
        return self._get_pkt_value("22C9")


class MixZone(Zone, HasHeatDemand):
    """Base for Mixing Valve zones.

    For a modulating valve controlled by a HM80 (will also call for heat).
    """

    @property
    def configuration(self):
        attrs = ["max_flow_temp", "pump_rum_time", "actuator_run_time", "min_flow_temp"]
        return {x: self._get_pkt_value("1030", x) for x in attrs}


class DhwZone(Zone, HasHeatDemand):
    """Base for the DHW (Fx) domain."""

    def __init__(self, zone_idx, gateway) -> None:
        # _LOGGER.debug("Creating a new Zone %s", zone_idx)
        super().__init__(zone_idx, gateway)

        self._zone_type = None  # or _domain_type
        # self._discover()

    @property
    def configuration(self):
        attrs = ["setpoint", "overrun", "differential"]
        return {x: self._get_pkt_value("10A0", x) for x in attrs}

    @property
    def name(self) -> Optional[str]:
        return "DHW Controller"

    @property
    def setpoint_status(self):
        attrs = ["active", "mode", "until"]
        return {x: self._get_pkt_value("1F41", x) for x in attrs}

    @property
    def temperature(self):
        return self._get_pkt_value("1260", "temperature")

    def _TBD_discover(self):
        # get config, mode, temp
        for code in ["10A0", "1F41", "1260"]:  # TODO: what about 1100?
            self._command(code)


DEVICE_CLASS_MAP = {
    DEVICE_LOOKUP["BDR"]: BdrSwitch,
    DEVICE_LOOKUP["CTL"]: Controller,
    DEVICE_LOOKUP["DHW"]: DhwSensor,
    DEVICE_LOOKUP["STA"]: Thermostat,
    DEVICE_LOOKUP["THM"]: Thermostat,
    DEVICE_LOOKUP["THm"]: Thermostat,
    DEVICE_LOOKUP["TRV"]: TrvActuator,
}

ZONE_CLASS_MAP = {
    "TRV": TrvZone,
    "BDR": BdrZone,
    "VAL": ValZone,
    "UFH": UfhZone,
    "MIX": MixZone,
}
