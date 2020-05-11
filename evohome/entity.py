"""The entities for Honeywell's RAMSES II / Residential Network Protocol."""
import logging
import queue
from typing import Any, Optional

from .command import Command
from .const import (
    # COMMAND_SCHEMA,
    CTL_DEV_ID,
    DEVICE_LOOKUP,
    DEVICE_TYPES,
    ZONE_TYPE_MAP,
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

    def _discover(self):
        # for code in COMMAND_SCHEMA:  # testing only
        #     payload = f"{self._id}00" if code != "0000" else self._id
        #     self._command(code, payload=payload)

        raise NotImplementedError

    # def _get_ctl_value(self, code, key) -> Optional[Any]:
    #     controller = self._evo.device_by_id["01:145038"]
    #     if controller._pkts.get(code):
    #         return controller._pkts[code].payload[key]
    #     else:
    #         pass  # TODO: send an RQ

    def _command(self, code, **kwargs):
        kwargs["code"] = code
        kwargs["dest_addr"] = kwargs.get("dest_id")
        self._cmd_que.put_nowait(Command(self._gwy, **kwargs))

    def _get_pkt_value(self, code, key) -> Optional[Any]:
        if self._pkts.get(code):
            return self._pkts[code].payload.get(key)

    @property
    def codes(self) -> list:
        return list(self._pkts.keys())

    def update(self, msg):
        if msg.verb in [" I", "RP"]:
            self._pkts.update({msg.code: msg})


class Domain(Entity):
    """Base for the named Zones and the other domains (e.g. DHW).

    Domains include F8 (rare), F9, FA, FC & FF.
    """

    def __init__(self, domain_id, gateway) -> None:
        _LOGGER.debug("Creating a new Domain %s", domain_id)
        super().__init__(domain_id, gateway)

        self._type = None
        # self.discover()

    @property
    def device_id(self) -> Optional[str]:  # TODO: delete me
        return self._id

    @property
    def domain_id(self):
        return self._id

    @property
    def heat_demand(self):  # 3150
        return self._get_pkt_value("3150", "heat_demand")

    @property
    def parent_zone(self) -> Optional[str]:  # TODO: delete me
        return None

    @property
    def relay_demand(self):  # 0008
        return self._get_pkt_value("0008", "relay_demand")


class System(Entity):
    """Base for the central heating (FC) domain."""

    def __init__(self, gateway):
        # _LOGGER.debug("Creating a new System %s", CTL_DEV_ID)
        super().__init__("", gateway)

    @property
    def database(self) -> Optional[dict]:
        pass

    @property
    def schedule(self):
        for zone_idx in range(0, 15):
            try:
                pass
            except queue.Full:
                pass

        return

    @property
    def fault_log(self):
        # WIP: try to discover fault codes
        for num in range(0x00, 0x3C):  # 10 pages of 6
            self._command("0418", CTL_DEV_ID, f"{num:06X}")

        return

    @property
    def heat_demand(self):  # 3150
        return self._get_pkt_value("3150", "heat_demand")

    @property
    def setpoint_status(self):
        attrs = ["mode", "until"]
        return {x: self._get_pkt_value("2E04", x) for x in attrs}

    @property
    def dhw_config(self) -> dict:
        sensors = [d.device_id for d in self._evo.devices if d.device_type == "DHW"]
        assert len(sensors) < 2

        relays = [d.device_id for d in self._evo.devices if d.device_type == "TPI"]
        assert len(relays) < 2

        return {
            "dhw_sensor": sensors[0] if sensors else None,
            "tpi_relay": relays[0] if relays else None,
        }

    @property
    def dhw_state(self) -> dict:
        pass


class Device(Entity):
    """The Device class."""

    def __init__(self, device_id, gateway) -> None:
        _LOGGER.debug("Creating a new Device %s", device_id)
        super().__init__(device_id, gateway)

        self._device_type = DEVICE_TYPES.get(device_id[:2])
        self._parent_zone = None
        self._has_battery = device_id[:2] in ["04", "12", "22", "30", "34"]

        attrs = gateway.known_devices.get(device_id)
        self._friendly_name = attrs.get("friendly_name") if attrs else None
        self._blacklist = attrs.get("blacklist", False) if attrs else False

        # TODO: causing queue.Full exception with -i
        self._discover()  # needs self._device_type

    def _discover(self):
        # if self._device_type not in ["BDR", "STA", "TRV", " 12"]:

        # 0016 works (unsolicited) with 01:, 13:
        # if self._id[:2] not in []:  # a device (e.g. a TRV) may be in rf_check mode
        if not self._has_battery:
            self._command("0016", dest_id=self._id, payload="00")

        # # 10E0 works with 01:, 30:
        # if self._id[:2] not in ["04", "12", "13", "32", "34"]:
        #     self._command("10E0", dest_id=self._id, payload="0000")

        # # # # sync cycle FF & 00
        # for payload in ["00", "0000", "FF"]:
        #     # check: relay_demand, rf_check, sync_cycle, boiler_params, actuator_state
        #     for code in ["0016"]:  # battery-operated wont respond
        #         self._command(code, dest_id=self._id, payload=payload)

        # for code in COMMAND_SCHEMA:
        #     self._command(code, dest_id=self._id, payload="0000")

    @property
    def description(self):  # 0100, 10E0,
        return self._get_pkt_value("10E0", "description")

    @property
    def device_id(self) -> Optional[str]:
        return self._id

    @property
    def device_type(self) -> Optional[str]:
        """Return a friendly device type string."""
        return DEVICE_TYPES.get(self._id[:2])

    @property
    def parent_zone(self) -> Optional[str]:
        if self._parent_zone:  # We assume that: once set, it never changes
            return self._parent_zone
        for msg in self._pkts.values():
            if "parent_zone_idx" in msg.payload:
                self._parent_zone = msg.payload["parent_zone_idx"]
                break
        return self._parent_zone

    def x_update(self, msg):
        # if isinstance(msg.payload, dict):
        #     if "zone_idx" in msg.payload:
        #         self._evo.data[msg.payload["zone_idx"]].update(msg.payload)

        # if msg.verb == " I":  # TODO: don't replace a I with an RQ!
        self._pkts.update({msg.code: msg})


class Controller(Device):
    """The Controller class."""

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a new Controller %s", device_id)
        super().__init__(device_id, gateway)

    def _discover(self):
        super()._discover()
        self._command("0100", dest_id=self._id, payload="00")

    @property
    def parent_zone(self) -> None:
        return "FF"

    def zone_properties(self, zone_idx) -> dict:
        # 0004/name, 000A/properties, 2309/setpoint, 30C9/temp
        pass

    def _TBD_discover(self):
        super()._discover()

        # # WIP: an attempt to actively discover the CTL rather than by eavesdropping
        # for cmd in ["313F"]:
        #     self._command(cmd, NUL_DEV_ID, "FF")

        # a 'real' Zone will return 0004/zone_name != None
        for zone_idx in range(12):
            _zone = f"{zone_idx:02x}00"
            self._command("0004", CTL_DEV_ID, _zone)

        # the 'real' DHW controller will return 1260/dhw_temp != None
        for _zone in ["FA"]:
            self._command("1260", CTL_DEV_ID, _zone)

        # WIP: the Controller, and 'real' Relays will respond to 0016/rf_check ???
        # self._command("0016", CTL_DEV_ID, f"{domain_id}FF")

        self._command("0000", verb="XX")

    def update(self, msg):
        super().update(msg)

        if type(msg.payload) == list:  # isinstance(msg.payload, list):
            if msg.code in ["000A", "2309", "30C9"]:
                [self._evo.data[z["zone_idx"]].update(z) for z in msg.payload]

        elif type(msg.payload) == dict:  # isinstance(msg.payload, dict):
            if "zone_idx" in msg.payload:
                self._evo.data[msg.payload["zone_idx"]].update(msg.payload)

            # if "domain_id" in msg.payload:
            #     self._evo.data[msg.payload["domain_id"]].update(msg.payload)

        else:
            pass

        # # TODO: take this out?
        # if msg.code in ["000A", "30C9"] and msg.verb == " I":  # payload is an array
        #     if not self._gwy.config["input_file"]:
        #         self._gwy.loop.call_later(5, print, self._evo.database)

    def handle_313f(self):
        """Controllers will RP to a RQ at anytime."""  # noqa: D401
        pass

    @property
    def tpi_relay(self) -> Optional[str]:
        relays = [d.device_id for d in self._evo.devices if d.device_type == "TPI"]
        assert len(relays) < 2
        return relays[0] if relays else None

    @property
    def dhw_sensor(self) -> Optional[str]:
        sensors = [d.device_id for d in self._evo.devices if d.device_type == "DHW"]
        assert len(sensors) < 2
        return sensors[0] if sensors else None


class DhwSensor(Device):
    """The DHW class, such as a CS92."""

    def __init__(self, dhw_id, gateway) -> None:
        # _LOGGER.debug("Creating a new DHW %s", dhw_id)
        super().__init__(dhw_id, gateway)

        # self._discover()

    @property
    def battery(self):
        return self._get_pkt_value("1060", "battery_level")
        # return self._get_pkt_value("1060", "low_battery")

    @property
    def parent_zone(self) -> None:
        return "FC"

    @property
    def temperature(self):
        return self._get_pkt_value("1260", "temperature")

    def _TBD_discover(self):
        for cmd in ["10A0", "1260", "1F41"]:
            self._command(cmd, CTL_DEV_ID, "00")


class TrvActuator(Device):
    """The TRV class, such as a HR92."""

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a new TRV %s", device_id)
        super().__init__(device_id, gateway)

    @property
    def battery(self) -> Optional[float]:  # 1060
        return self._get_pkt_value("1060", "battery_level")
        # return self._get_pkt_value("1060", "low_battery")

    @property
    def language(self) -> Optional[str]:  # 0100,
        return self._get_pkt_value("0100", "language")

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._get_pkt_value("3150", "heat_demand")

    @property
    def setpoint(self) -> Optional[Any]:  # 2309
        # TODO: differientiate between Off and Unknown
        return self._get_pkt_value("2309", "setpoint")

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        return self._get_pkt_value("30C9", "temperature")

    @property
    def window_state(self) -> Optional[bool]:  # 12B0
        return self._get_pkt_value("12B0", "window_open")

    def x_update(self, msg):
        super().update(msg)

        # if msg.code == "1060" and msg.device_type[2] != "CTL":
        #     return  # these do not contain a zone_idx

        # if msg.code in ["12B0", "2309"]:
        #     [self._evo.data[z["zone_idx"]].update(z) for z in msg.payload]

        # if msg.code in ["3150"]:
        #     [self._evo.data[z["zone_idx"]].update(z) for z in msg.payload]

        if msg.verb == " I":
            self._pkts.update({msg.code: msg})


class BdrSwitch(Device):
    """The BDR class, such as a BDR91."""

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a new BDR %s", device_id)
        super().__init__(device_id, gateway)

    def _TBD_discover(self):
        super()._discover()

        # for cmd in ["3B00", "3EF0"]:  # these don't work, for 00 or 0000
        #     self._command(cmd, self._id, "00")

        for cmd in ["0008", "1100", "3EF1"]:  # these work, for any payload
            self._command(cmd, self._id, "0000")

    def x_update(self, msg):
        super().update(msg)

        if msg.code == "3B00":  # the TPI relay for the boiler
            self._device_type = "TPI"
            self._parent_zone = "FC"


class TpiSwitch(Device):
    """The BDR class, such as a BDR91."""


class Thermostat(Device):
    """The STA class, such as a TR87RF."""

    # 045  I     STA:092243            >broadcast 3120 007 0070B0000000FF
    # every ~3:45:00 (each STA different, but each keeps its interval to the second)
    # payload never changes

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a new STA %s", device_id)
        super().__init__(device_id, gateway)

    @property
    def battery(self):  # 1060
        return self._get_pkt_value("1060", "battery_level")
        # return self._get_pkt_value("1060", "low_battery")

    @property
    def setpoint(self):  # 2309
        return self._get_pkt_value("2309", "setpoint")

    @property
    def temperature(self):  # 30C9
        return self._get_pkt_value("30C9", "temperature")


class Zone(Entity):
    """Base for the 12 named Zones."""

    def __init__(self, zone_idx, gateway) -> None:
        _LOGGER.debug("Creating a new Zone %s", zone_idx)
        super().__init__(zone_idx, gateway)

        self._zone_type = None
        # self._discover()

    def _discover(self):
        # get name, config, mode, temp
        # can't do: "3150" (TODO: 12B0/window_state only if enabled, or only if TRV?)
        for code in [
            "0004",
            "000A",
            "000C",
            "12B0",
            "2349",
            "30C9",
            "3150",
        ]:  # also: "2349", "30C9"]:
            payload = f"{self._id}00" if code != "0000" else self._id
            self._command(code, payload=payload)

        for code in [
            "0004",
            "000A",
            "000C",
            "12B0",
            "2349",
            "30C9",
            "3150",
        ]:  # also: "2349", "30C9"]:
            payload = f"{self._id}" if code != "0000" else self._id
            self._command(code, payload=payload)

    @property
    def configuration(self):
        # if self._zone_type != "Radiator Valve":
        #     return {}

        attrs = ["local_override", "multi_room_mode", "openwindow_function"]
        if self._pkts.get("zone_config"):
            return {
                k: v
                for k, v in self._pkts["zone_config"]["flags"].items()
                if k in attrs
            }
        return {k: None for k in attrs}

    @property
    def devices(self):  # TODO: use 000C
        return [d for d in self._evo.devices if d.parent_zone == self._id]

    @property
    def heat_demand(self) -> Optional[float]:
        demands = [
            d.heat_demand if d.heat_demand else 0
            for d in self.devices
            if d._device_type == "TRV"
        ]
        return max(demands + [0])

    @property
    def name(self) -> Optional[str]:
        return self._evo.data[self._id].get("name")
        # return self._get_ctl_value(f"0004-{self._id}", "name")

    @property
    def setpoint_capabilities(self):
        attrs = ["max_heat_setpoint", "min_heat_setpoint"]
        return {x: self._get_pkt_value("000A", x) for x in attrs}

    @property
    def setpoint_status(self):
        attrs = ["setpoint", "mode", "until"]
        return {x: self._get_pkt_value("2349", x) for x in attrs}

    @property
    def temperature(self):
        # turn self._get_pkt_value("30C9", "temperature")
        return self._evo.data[self._id].get("temperature")

    @property
    def zone_idx(self):
        return self._id

    @property
    def zone_type(self) -> Optional[str]:
        if self._zone_type:  # isinstance(self, ???)
            return self._zone_type

        # try to cast a new type (must be a superclass of the current type)
        for device in self.devices:  # the following ar emutally exclusive
            if device.device_type == "TRV":
                self.__class__ = RadValveZone
                self._zone_type = ZONE_TYPE_MAP["TRV"]

            elif device.device_type == "BDR":
                self.__class__ = ElectricZone  # if also call for heat, is a ZoneValve
                self._zone_type = ZONE_TYPE_MAP["BDR"]

            elif device.device_type == "UFH":
                self.__class__ = UnderfloorZone
                self._zone_type = ZONE_TYPE_MAP["UFH"]

            # elif device.device_type == "???":
            #     self.__class__ = MixValveZone
            #     self._zone_type = ZONE_TYPE_MAP["MIX"]

        return self._zone_type

    def update(self, msg):
        super().update(msg)

        if self._zone_type is None:
            _ = self.zone_type


class DhwZone(Zone):
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
        for cmd in ["10A0", "1F41", "1260"]:  # TODO: what about 1100?
            self._command(cmd, CTL_DEV_ID, "00")


class RadValveZone(Zone):
    """Base for Radiator Valve zones.

    For radiators controlled by HR92s or HR80s (will also call for heat).
    """

    # 3150 (heat_demand) but no 0008 (relay_demand)

    @property
    def window_open(self):
        return self._evo.data[f"{self._id:02X}"]["window_open"]

    def _TBD_discover(self):
        super()._discover()

        for cmd in ["12B0"]:
            self._command(cmd, CTL_DEV_ID, self._id)


class ElectricZone(Zone):
    """Base for Electric Heat zones.

    For a small (5A) electric load controlled by a BDR91 (never calls for heat).
    """

    def x_update(self, payload, msg):
        super().update(payload, msg)

        # does it also call for heat?
        if self._pkts.get("3150"):
            self.__class__ = ZoneValveZone
            self._zone_type = ZONE_TYPE_MAP["ZON"]


class ZoneValveZone(ElectricZone):
    """Base for Zone Valve zones.

    For a motorised valve controlled by a BDR91 (will also call for heat).
    """


class UnderfloorZone(Zone):
    """Base for Underfloor Heating zones.

    For underfloor heating controlled by an HCE80 or HCC80 (will also call for heat).
    """


class MixValveZone(Zone):
    """Base for Mixing Valve zones.

    For a modulating valve controlled by a HM80 (will also call for heat).
    """

    @property
    def configuration(self):
        attrs = ["max_flow_temp", "pump_rum_time", "actuator_run_time", "min_flow_temp"]
        return {x: self._get_pkt_value("1030", x) for x in attrs}


DEVICE_CLASSES = {
    DEVICE_LOOKUP["BDR"]: BdrSwitch,
    DEVICE_LOOKUP["CTL"]: Controller,
    DEVICE_LOOKUP["DHW"]: DhwSensor,
    DEVICE_LOOKUP["STA"]: Thermostat,
    DEVICE_LOOKUP["THM"]: Thermostat,
    DEVICE_LOOKUP["TRV"]: TrvActuator,
}

ZONE_CLASSES = {
    "01": Controller,
    "04": TrvActuator,
    "07": DhwSensor,
    "10": Device,
    "12": Thermostat,
    "13": BdrSwitch,
    "22": Thermostat,
    "34": Thermostat,
}
