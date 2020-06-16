"""The entities for Honeywell's RAMSES II / Residential Network Protocol."""
import logging
from typing import Any, Optional

from .command import Command, Schedule, PAUSE_LONG, PRIORITY_LOW
from .const import (
    CODE_SCHEMA,
    DEVICE_LOOKUP,
    DEVICE_HAS_BATTERY,
    DEVICE_TYPES,
    DEVICE_TYPE_MAP,
    DOMAIN_TYPE_MAP,
    ZONE_TYPE_MAP,
    __dev_mode__,
)

_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
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
        self.id = entity_id
        self._gwy = gateway
        self._evo = gateway.evo
        self._que = gateway.cmd_que

        self._pkts = {}
        self.last_comms = None

    def _discover(self):
        pass
        # raise NotImplementedError

    def _command(self, code, **kwargs):
        if self._gwy.config["listen_only"]:
            return

        cmd = Command(
            kwargs.get("verb", "RQ"),
            kwargs.get("dest_addr", self._evo.ctl_id),
            code,
            kwargs.get("payload", "00"),
            priority=kwargs.get("priority"),
        )
        self._que.put_nowait(cmd)

    def _get_pkt_value(self, code, key=None) -> Optional[Any]:
        if self._pkts.get(code):
            if isinstance(self._pkts[code].payload, list):
                return self._pkts[code].payload

            if key is not None:
                return self._pkts[code].payload.get(key)

            result = self._pkts[code].payload
            return {k: v for k, v in result.items() if k[:1] != "_"}

    @property
    def pkt_codes(self) -> list:
        return list(self._pkts.keys())

    def update(self, msg) -> None:
        self.last_comms = f"{msg.date}T{msg.time}"
        if msg.verb == " W":
            if msg.code in self._pkts and self._pkts[msg.code].verb != msg.verb:
                return
        if msg.verb == "RQ":  # and msg.payload:
            if msg.code in self._pkts and self._pkts[msg.code].verb != msg.verb:
                return
        # may get an RQ/W initially, but RP/I will override
        self._pkts.update({msg.code: msg})


class Battery:
    """Some devices have a battery."""

    @property
    def battery(self):
        low_battery = self._get_pkt_value("1060", "low_battery")
        if low_battery is not None:
            battery_level = self._get_pkt_value("1060", "battery_level")
            return {"low_battery": low_battery, "battery_level": battery_level}


class HeatDemand:
    """Some devices have heat demand."""

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._get_pkt_value("3150", "heat_demand")


class Temperature:
    """Some devices have a temperature sensor."""

    def update(self, msg):
        super().update(msg)

        # if msg.code == "30C9" and msg.payload["temperature"]:  # reports a temp change
        #     zone = self.parent_000c if self.parent_000c else self.parent_zone
        #     if zone:
        #         zones = [z for z in [zone] if self._evo.zone_by_id[z].sensor is None]
        #     else:
        #         zones = [z for z in self._evo.zones if z.sensor is None]

        # for z in zones:
        #     new_temp = msg.payload["temperature"]

    @property
    def setpoint(self) -> Optional[Any]:  # 2309
        return self._get_pkt_value("2309", "setpoint")

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        return self._get_pkt_value("30C9", "temperature")


class Domain(Entity):
    """Base for the domains: F8 (rare), F9, FA (not FC, FF).

    F8 - 1F09/W (rare)
    F9 - 0008
    FA - 0008
    FC - 0008, 0009, and others
    """

    def __init__(self, domain_id, gateway) -> None:
        _LOGGER.debug("Creating a Domain, %s", domain_id)
        super().__init__(domain_id, gateway)

        self.type = DOMAIN_TYPE_MAP[domain_id]

    def update(self, msg) -> None:
        super().update(msg)

        # try to cast a new type (must be a superclass of the current type)
        if msg.code in ["1100", "3150", "3B00"] and self.type is None:
            self.__class__ = TpiDomain
            self.type = "TPI"
            _LOGGER.warning("Promoted domain %s to TPI", self.id)

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return self._get_pkt_value("0008", "relay_demand")

    @property  # only seen with FC, but seems should pair with 0008?
    def relay_failsafe(self) -> Optional[float]:  # 3150
        return self._get_pkt_value("0009")


class TpiDomain(Domain, HeatDemand):
    """Base for the FC domain.

    FC - 0008, 0009, 1100, 3150, 3B00, (& rare: 0001, 1FC9)
    """

    @property
    def tpi_params(self) -> Optional[float]:  # 1100
        return self._get_pkt_value("1100")

    @property
    def sync_tpi(self) -> Optional[float]:  # 3B00
        return self._get_pkt_value("3B00", "sync_tpi")


class Device(Entity):
    """The Device class."""

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a Device, %s", device_id)
        super().__init__(device_id, gateway)

        self.hex_id = dev_id_to_hex(device_id)
        self.type = DEVICE_TYPES.get(device_id[:2], f"{device_id[:2]:>3}")
        self._has_battery = device_id[:2] in DEVICE_HAS_BATTERY
        self.__parent_zone = self.parent_000c = None

        attrs = gateway.known_devices.get(device_id)
        self._friendly_name = attrs.get("friendly_name") if attrs else None
        self._blacklist = attrs.get("blacklist", False) if attrs else False

        self._discover()

    def _discover(self):
        # TODO: an attempt to actively discover the CTL rather than by eavesdropping
        # self._command("313F", dest_addr=NUL_DEV_ID, payload="FF")

        # for code in CODE_SCHEMA:  # TODO: testing only
        #     self._command(code, dest_addr=self.id, payload="0000")
        # return

        # do these even if battery-powered (e.g. device might be in rf_check mode)
        for code in ["1FC9"]:
            self._command(code, dest_addr=self.id)
        for code in ["0016"]:
            self._command(code, dest_addr=self.id, payload="0000")

        if self.id[:2] not in ["04", "07", "12", "22", "34"]:  # battery-powered?
            self._command("10E0", dest_addr=self.id)
        # else:  # TODO: it's unlikely anything respond to an RQ/1060 (an 01: doesn't)
        #     self._command("1060", dest_addr=self.id)  # payload len()?

    @property
    def name(self) -> Optional[str]:
        """Return a friendly device type string."""
        return DEVICE_TYPE_MAP.get(self.type)

    @property
    def description(self) -> Optional[str]:  # 10E0
        # 01:, and (rarely) 04:
        return self._get_pkt_value("10E0", "description")

    @property
    def pkt_1fc9(self) -> list:
        return self._get_pkt_value("1FC9")  # we want the RPs

    @property
    def rf_signal(self) -> dict:
        return self._get_pkt_value("0016")

    @property
    def parent_zone(self) -> Optional[str]:
        # once set, it never changes
        if self.__parent_zone:  # We assume that: once set, it never changes
            return self.__parent_zone

        for msg in self._pkts.values():
            # assert "zone_idx" not in msg.payload
            if "parent_idx" in msg.payload:
                self.__parent_zone = msg.payload["parent_idx"]
                break

        if self.parent_000c is not None:
            if self.__parent_zone is None:
                self.__parent_zone = self.parent_000c
            else:
                assert self.__parent_zone == self.parent_000c  # I think done elsewhere

        return self.__parent_zone

    @parent_zone.setter
    def parent_zone(self, zone_idx) -> None:
        assert zone_idx is not None
        self.__parent_zone = zone_idx


class Controller(Device):
    """The Controller class."""

    def __init__(self, device_id, gateway) -> None:
        _LOGGER.debug("Creating the Controller, %s", device_id)
        super().__init__(device_id, gateway)

        if self._evo.ctl is not None:
            # TODO: do this earlier?
            raise ValueError(f">1 CTL! (new: {device_id}, old: {self._evo.ctl_id})")
        self._evo.ctl = self

        self._boiler_relay = None
        self._fault_log = {}
        self._prev_30c9 = None

    def _discover(self):
        super()._discover()

        # NOTE: could use this to discover zones
        # for idx in range(12):
        #     self._command("0004", payload=f"{idx:02x}00")

        # system-related... (not working: 1280, 22D9, 2D49, 2E04, 3220, 3B00)
        self._command("1F09", payload="00")
        for code in ["313F", "0100", "0002"]:
            self._command(code)

        for code in ["10A0", "1260", "1F41"]:  # stored DHW
            self._command(code)

        self._command("0005", payload="0000")
        self._command("1100", payload="FC")
        self._command("2E04", payload="FF")

        # Get the three most recent fault log entries
        for log_idx in range(0, 0x3):  # max is 0x3C?
            self._command("0418", payload=f"{log_idx:06X}", priority=PRIORITY_LOW)

        # TODO: 1100(), 1290(00x), 0418(00x):
        # for code in ["000C"]:
        #     for payload in ["F800", "F900", "FA00", "FB00", "FC00", "FF00"]:
        #         self._command(code, payload=payload)

        # for code in ["3B00"]:
        #     for payload in ["0000", "00", "F8", "F9", "FA", "FB", "FC", "FF"]:
        #         self._command(code, payload=payload)

    def update(self, msg):
        def maintain_state_data():
            # for z in self._evo.zones:
            #     _ = z.type  # check/update each zone's type
            pass

        def update_zone_sensors() -> None:
            prev_msg, self._prev_30c9 = self._prev_30c9, msg
            if prev_msg is None:
                return

            old, new = prev_msg.payload, msg.payload
            zones = [self._evo.zone_by_id[z["zone_idx"]] for z in new if z not in old]
            if not zones:  # have any zones changed their temp since the last cycle?
                return

            test_zones = [
                z
                for z in zones
                if z.sensor is None
                and z.temperature not in [x for x in zones if x != z] + [None]
            ]
            if not test_zones:  # we test sensorless zones with a unique, non-null temps
                return

            all_sensors = [
                d
                for d in self._evo.devices
                if d.type != "DHW" and hasattr(d, "temperature")
            ]

            if _LOGGER.isEnabledFor(logging.DEBUG):
                sensorless_zones = {z.idx: z.temperature for z in test_zones}
                _LOGGER.debug("Sensorless zones: %s (changed temps)", sensorless_zones)
                orphan_sensors = {
                    d.id: d.temperature for d in all_sensors if d.parent_zone is None
                }
                _LOGGER.debug("Zoneless sensors: %s (ever seen)", orphan_sensors)

            for z in test_zones:
                _LOGGER.debug("Can check zone %s, temp now: %s", z.idx, z.temperature)
                sensors = [
                    d
                    for d in all_sensors
                    if d.parent_zone in [z.idx, None]
                    and d.temperature == z.temperature
                    and d._pkts["30C9"].dtm > prev_msg.dtm
                ]

                if len(sensors) == 1:
                    z._sensor, sensors[0].parent_zone = sensors[0].id, z.idx
                    _LOGGER.debug(" - found sensor, zone %s: %s", z.idx, sensors[0].id)
                elif len(sensors) == 0:
                    _LOGGER.debug(" - ** No sensor, zone %s, uses CTL?", z.idx)
                else:
                    _LOGGER.debug(" - many sensors, zone %s: %s", z.idx, sensors)

            # now see if we can allocate the controller as a sensor...
            zones = [z for z in self._evo.zones if z.sensor is None]
            if len(zones) != 1:
                return  # no zone without a sensor

            # TODO: this can't be used if their neighbouring 'stats not blacklisted
            # if [d for d in all_sensors if d.parent_zone is None]:
            #     return  # >0 sensors without a zone

            # safely(?) assume this zone is using the CTL as a sensor...
            assert self.parent_zone is None, "Controller has already been allocated!"

            zones[0]._sensor, self.parent_zone = self.id, zones[0].id
            _LOGGER.debug(
                "Sensor is CTL by exclusion, zone %s: %s", zones[0].id, self.id
            )

        if msg.code in ["000A", "2309", "30C9"] and not isinstance(msg.payload, list):
            pass
        else:
            super().update(msg)

        if msg.code == "0418" and msg.verb in [" I", "RP"]:  # this is a special case
            self._fault_log[msg.payload["log_idx"]] = msg
            # print(self.fault_log)

        if msg.code == "1F09" and msg.verb == " I":
            maintain_state_data()

        if msg.code == "30C9" and isinstance(msg.payload, list):  # msg.is_array:
            update_zone_sensors()

        if msg.code == "3EF1" and msg.verb == "RQ":  # relay attached to a burner
            if msg.dev_dest[:2] == "13":  # this is the TPI relay
                pass
            if msg.dev_dest[:2] == "10":  # this is the OTB
                pass

    async def update_fault_log(self) -> list:
        # WIP: try to discover fault codes
        for log_idx in range(0x00, 0x3C):  # 10 pages of 6
            self._command("0418", payload=f"{log_idx:06X}")
        return None

    @property
    def fault_log(self):  # 0418
        return [f.payload for f in self._fault_log.values()]

    @property
    def language(self) -> Optional[str]:  # 0100,
        return self._get_pkt_value("0100", "language")

    @property
    def system_mode(self):  # 2E04
        attrs = ["mode", "until"]
        return {x: self._get_pkt_value("2E04", x) for x in attrs}

    @property
    def boiler_relay(self) -> Optional[str]:  # 3EF0
        # relays = [d.id for d in self._evo.devices if d.type == "TPI"]
        # if not __dev_mode__:
        #     assert len(relays) < 2  # This may fail for testing (i.e. 2 TPI relays)
        # return relays[0] if relays else None

        if self._boiler_relay is None:
            if "3EF0" in self._pkts:  # the relay is a 13:
                self._boiler_relay = self._pkts["3EF0"].dev_dest
        return self._boiler_relay  # could be a 13: or a 10:

    @property
    def dhw_sensor(self) -> Optional[str]:
        sensors = [d.id for d in self._evo.devices if d.type == "DHW"]
        if not __dev_mode__:
            assert len(sensors) < 2  # This may fail for testing
        return sensors[0] if sensors else None


class UfhController(Device, HeatDemand):
    """The UFH class, the HCE80 that controls the UFH heating zones."""

    def _discover(self):
        super()._discover()

        for code in CODE_SCHEMA:  # TODO: testing only
            # for payload in DOMAIN_TYPE_MAP:  # TODO: testing only
            self._command(code, dest_addr=self.id)

        return

    def update(self, msg):
        super().update(msg)

        # ["3150/ZZ|FC", "0008/FA|FC", "22D0/none", "22C9/Zone list"]

        if msg.code in ["22C9"] and not isinstance(msg.payload, list):
            pass
        else:
            super().update(msg)

    def zones(self):
        pass


class DhwSensor(Device, Battery):
    """The DHW class, such as a CS92."""

    def __init__(self, dhw_id, gateway) -> None:
        _LOGGER.debug("Creating a DHW sensor, %s", dhw_id)
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


class Thermostat(Device, Temperature, Battery):  # TODO: the THM, THm devices
    """The STA class, such as a TR87RF."""

    def __init__(self, device_id, gateway) -> None:
        _LOGGER.debug("Creating a XXX thermostat, %s", device_id)
        super().__init__(device_id, gateway)


class TrvActuator(Device, Battery, HeatDemand, Temperature):
    """The TRV class, such as a HR92."""

    def __init__(self, device_id, gateway) -> None:
        # _LOGGER.debug("Creating a TRV actuator, %s", device_id)
        super().__init__(device_id, gateway)

    @property
    def language(self) -> Optional[str]:  # 0100,
        return self._get_pkt_value("0100", "language")

    @property
    def window_state(self) -> Optional[bool]:  # 12B0
        return self._get_pkt_value("12B0", "window_open")


class OtbGateway(Device, HeatDemand):
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    # 10E0, 1FD4, 22D9, 3150, 3220, 3EF0

    def __init__(self, device_id, gateway) -> None:
        _LOGGER.debug("Creating an OTB gateway, %s", device_id)
        super().__init__(device_id, gateway)

    def _discover(self):
        super()._discover()

        for code in CODE_SCHEMA:  # TODO: testing only
            # for payload in DOMAIN_TYPE_MAP:  # TODO: testing only
            self._command(code, dest_addr=self.id)

        return

    def update(self, msg):
        super().update(msg)

    @property
    def actuator_enabled(self) -> Optional[bool]:  # 3EF0 (does 10: RP/3EF1?)
        return self._get_pkt_value("3EF0", "actuator_enabled")

    @property
    def actuator_state(self) -> Optional[float]:  # 3EF1
        return self._get_pkt_value("3EF1")

    @property
    def boiler_setpoint(self) -> Optional[Any]:  # 22D9
        return self._get_pkt_value("22D9", "boiler_setpoint")


class BdrSwitch(Device):
    """The BDR class, such as a BDR91."""

    def __init__(self, device_id, gateway) -> None:
        _LOGGER.debug("Creating a BDR relay, %s", device_id)
        super().__init__(device_id, gateway)

        self._is_tpi = None

    def _discover(self):
        super()._discover()

        self._command("1100", dest_addr=self.id, payload="00")

        # all relays seem the same, except for 0016, and 1100
        # for code in ["3B00", "3EF0", "3EF1"] + ["0008", "1100", "1260"]:
        #     for payload in ["00", "FC", "FF", "0000", "000000"]:
        #         self._command(code, dest_addr=self.id, payload=payload)

        return

        for code in CODE_SCHEMA:  # TODO: testing only
            # for payload in DOMAIN_TYPE_MAP:  # TODO: testing only
            self._command(code, dest_addr=self.id)

        return

    def update(self, msg):
        super().update(msg)

        if self._is_tpi is None:
            _ = self.is_tpi

    @property
    def is_tpi(self) -> Optional[bool]:  # 3B00
        def make_tpi():
            self.__class__ = TpiSwitch
            self.type = "TPI"
            _LOGGER.warning("Promoted device %s to %s", self.id, self.type)

            self._is_tpi = True
            self.parent_zone = "FC"
            self._discover()

        if self._is_tpi is not None:
            return self._is_tpi

        # try to cast a new type (must be a superclass of the current type)
        if "1FC9" in self._pkts and self._pkts["1FC9"].verb == "RP":
            if "3B00" in self._pkts["1FC9"].raw_payload:
                make_tpi()

        elif "3B00" in self._pkts and self._pkts["3B00"].verb == " I":
            make_tpi()

        return self._is_tpi

    @property
    def actuator_enabled(self) -> Optional[bool]:  # 3EF0
        return self._get_pkt_value("3EF0", "actuator_enabled")

    @property
    def actuator_state(self) -> Optional[float]:  # 3EF1
        return self._get_pkt_value("3EF1")

    @property
    def tpi_params(self) -> dict:
        return self._get_pkt_value("1100")


class TpiSwitch(BdrSwitch):  # TODO: superset of BDR switch?
    """The TPI class, the BDR91 that controls the boiler."""

    def _discover(self):
        # NOTE: do not super()._discover()

        for code in ["1100"]:
            self._command(code, dest_addr=self.id, payload="00")

        # doesn't like like TPIs respond to a 3B00
        # for payload in ["00", "C8"]:
        #     for code in ["00", "FC", "FF"]:
        #         self._command("3B00", dest_addr=self.id, payload=f"{code}{payload}")


class Zone(Entity):
    """Base for the 12 named Zones."""

    def __init__(self, idx, gateway) -> None:
        # _LOGGER.debug("Creating a Zone, %s", idx)
        super().__init__(idx, gateway)

        self._sensor = None
        self._type = None
        self._discover()
        self._fragments = {}
        self._schedule = Schedule(gateway, idx)

    def _discover(self):
        for code in ["0004", "000C"]:
            self._command(code, payload=f"{self.id}00")

        for code in ["000A", "2349", "30C9"]:
            self._command(code, payload=self.id)

        # TODO: 12B0: only if RadValve zone, or whenever window_state is enabled?
        for code in ["12B0"]:
            self._command(code, payload=self.id)

        # TODO: 3150(00?): how to do (if at all) & for what zone types?
        # TODO: 0005(002), 0006(001)

        # 095 RQ --- 18:013393 01:145038 --:------ 0404 007 00200008000100
        # 045 RP --- 01:145038 18:013393 --:------ 0404 048 00200008290105 68816DCDB..
        # if self.id == "00":  # TODO: when testing,,,
        # self._schedule.request_fragment(restart=True)  # TODO: only if r/w?
        self._command("0404", payload=f"{self.id}200008000100", pause=PAUSE_LONG)

    def update(self, msg):
        super().update(msg)

        if self._sensor is None:
            _ = self.sensor

        if self._type is None:
            _ = self.type

        # not UFH (it seems), but BDR or VAL; and possibly a MIX support 0008 too
        if msg.code in ["0008", "0009"]:  # TODO: how to determine is/isnt MIX?
            assert msg.dev_from[:2] in ["01", "13"]  # 01 as a stat

            if self.type:
                assert self.type in ["BDR", "VAL"]
            else:
                self.type = "BDR"
                self.__class__ = _ZONE_CLASS[self.type]
                _LOGGER.warning("Promoted zone %s to %s", self.id, self.type)

        if msg.code == "0404" and msg.verb == "RP":
            self._schedule.add_fragment(msg)

        if msg.code == "3150":  # TODO: and msg.verb in [" I", "RP"]?
            assert msg.dev_from[:2] in ["02", "04", "13"]

            if self.type:
                return

            if msg.dev_from[:2] == "02":  # UFH zone
                self.type = "UFH"

            if msg.dev_from[:2] == "04":  # Zone valve zone
                self.type = "TRV"

            if msg.dev_from[:2] == "13":  # Zone valve zone
                self.type = "VAL"

            self.__class__ = _ZONE_CLASS[self.type]
            _LOGGER.warning("Promoted zone %s to %s", self.id, self.type)

    @property
    def schedule(self) -> Optional[dict]:
        """Return the schedule if any."""
        return self._schedule.schedule if self._schedule else None

    @property
    def idx(self) -> str:
        return self.id

    @property
    def type(self) -> Optional[str]:
        if self._type is not None:  # isinstance(self, ???)
            return self._type

        # TODO: try to cast an initial type
        for device in self.devices:
            device_type = DEVICE_TYPES[device[:2]]
            if device_type in _ZONE_CLASS:
                self._type = device_type
                self.__class__ = _ZONE_CLASS[self._type]
                _LOGGER.debug("Set Zone type %s to %s", self.id, self._type)
                break

        return self._type

    @type.setter
    def type(self, value):
        assert value in _ZONE_CLASS
        self._type = value

    @property
    def description(self) -> str:
        return ZONE_TYPE_MAP.get(self._type)

    @property
    def name(self) -> Optional[str]:  # 0004
        return self._get_pkt_value("0004", "name")

    @property
    def configuration(self) -> Optional[dict]:  # 000A
        msg_1 = self._evo.ctl._pkts.get("000A")  # authorative, but 1/hourly
        msg_2 = self._pkts.get("000A")  # possibly more up-to-date, or null

        if msg_1 is not None and msg_2 is not None:
            msg = msg_1 if msg_1.dtm > msg_2.dtm else msg_2
        else:
            msg = msg_1 if msg_1 is not None else msg_2

        if msg is msg_2:  # could be: None is None
            result = self._get_pkt_value("000A")
        elif msg_1 is not None:  # elif not required, if sufficent
            result = self._evo.ctl._get_pkt_value("000A")
            if result:
                result = {
                    k: v
                    for d in result
                    for k, v in d.items()
                    if d["zone_idx"] == self.idx
                }

        if result:
            return {k: v for k, v in result.items() if k != "zone_idx"}

    @property
    def mode(self) -> Optional[dict]:  # 2349
        result = self._get_pkt_value("2349")
        if result:
            return {k: v for k, v in result.items() if k != "zone_idx"}

    @property
    def setpoint(self) -> Optional[float]:  # 2309
        msg_1 = self._evo.ctl._pkts.get("2309")  # authorative
        msg_2 = self._pkts.get("2349")  # possibly more up-to-date, or null

        if msg_1 is not None and msg_2 is not None:
            msg = msg_1 if msg_1.dtm > msg_2.dtm else msg_2
        else:
            msg = msg_1 if msg_1 is not None else msg_2

        if msg is msg_2:  # could be: None is None
            result = self._get_pkt_value("2349")
        elif msg_1 is not None:  # elif not required, if sufficent
            result = self._evo.ctl._get_pkt_value("2309")
            if result:
                result = (
                    {
                        k: v
                        for d in result
                        for k, v in d.items()
                        if d["zone_idx"] == self.idx
                    }
                    if result
                    else None
                )

        if result:
            return result.get("setpoint")

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        # OK to simply use the controller's sync_cycle array value for now
        result = self._evo.ctl._get_pkt_value("30C9")
        if result:
            result = {
                k: v for d in result for k, v in d.items() if d["zone_idx"] == self.idx
            }
            return result.get("temperature")

        # TODO: this value _may_ be more up-to-date (but only if from *the* sensor?)
        # result = self._get_pkt_value("30C9", "temperature")
        # return result if result else None

    @property
    def heat_demand_alt(self) -> Optional[float]:  # 3150
        if not hasattr(self, "devices"):
            return

        demands = [
            d.heat_demand
            for d in self._evo.devices
            if d.id in self.devices
            and hasattr(d, "heat_demand")
            and d.heat_demand is not None
        ]
        return max(demands + [0]) if demands else None

    @property
    def actuators(self) -> list:  # 000C
        # actuators = self._get_pkt_value("000C", "actuators")
        # return actuators if actuators is not None else []  # TODO: or just: actuators

        return [d for d in self.devices if d[:2] in ["02", "04", "13"]]

        return [
            d for d in self.devices if hasattr(self._evo.device_by_id[d], "heat_demand")
        ]

    @property
    def devices(self) -> list:
        # actuators = self._get_pkt_value("000C", "actuators")
        devices_1 = {d.id for d in self._evo.devices if d.parent_000c == self.id}
        devices_2 = {d.id for d in self._evo.devices if d.parent_zone == self.id}
        return list(devices_1 | devices_2)

    @property
    def sensors(self) -> list:
        sensors = [
            d for d in self.devices if hasattr(self._evo.device_by_id[d], "temperature")
        ]
        return list(set(sensors) | {self._sensor})

    @property
    def sensor(self) -> Optional[str]:  # TODO: WIP
        return self._sensor


class TrvZone(Zone, HeatDemand):
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

    def update(self, msg):
        super().update(msg)

        # ZV zones are Elec zones that also call for heat; ? and also 1100/unkown_0 = 00
        if msg.code == "3150" and self.type != "VAL":
            self.type = "VAL"
            self.__class__ = _ZONE_CLASS[self.type]
            _LOGGER.warning("Promoted zone %s to %s", self.id, self.type)

    @property
    def actuator_enabled(self) -> Optional[bool]:  # 3EF0
        return self._get_pkt_value("3EF0", "actuator_enabled")

    @property
    def actuator_state(self) -> Optional[float]:  # 3EF1
        return self._get_pkt_value("3EF1")


class ValZone(BdrZone, HeatDemand):
    """Base for Zone Valve zones.

    For a motorised valve controlled by a BDR91 (will also call for heat).
    """


class UfhZone(Zone, HeatDemand):
    """Base for Underfloor Heating zones.

    For underfloor heating controlled by an HCE80 or HCC80 (will also call for heat).
    """

    @property
    def ufh_setpoint(self) -> Optional[float]:  # 3B00
        return self._get_pkt_value("22C9")


class MixZone(Zone, HeatDemand):
    """Base for Mixing Valve zones.

    For a modulating valve controlled by a HM80 (will also call for heat).
    """

    @property
    def configuration(self):
        attrs = ["max_flow_temp", "pump_rum_time", "actuator_run_time", "min_flow_temp"]
        return {x: self._get_pkt_value("1030", x) for x in attrs}


class DhwZone(Zone, HeatDemand):
    """Base for the DHW (Fx) domain."""

    def __init__(self, idx, gateway) -> None:
        _LOGGER.warning("Creating a DHW Zone, %s", idx)
        super().__init__(idx, gateway)

        self.type = None  # or _domain_type
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


DEVICE_CLASS = {
    DEVICE_LOOKUP["BDR"]: BdrSwitch,
    DEVICE_LOOKUP["CTL"]: Controller,
    DEVICE_LOOKUP["DHW"]: DhwSensor,
    DEVICE_LOOKUP["STA"]: Thermostat,
    DEVICE_LOOKUP["THM"]: Thermostat,
    DEVICE_LOOKUP["THm"]: Thermostat,
    DEVICE_LOOKUP["TRV"]: TrvActuator,
    DEVICE_LOOKUP["OTB"]: OtbGateway,
    DEVICE_LOOKUP["UFH"]: UfhController,
}

_ZONE_CLASS = {
    "TRV": TrvZone,
    "BDR": BdrZone,
    "VAL": ValZone,  # not a real device type
    "UFH": UfhZone,
    "MIX": MixZone,
}
