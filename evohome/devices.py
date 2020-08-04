"""The entities for Honeywell's RAMSES II / Residential Network Protocol."""
from datetime import datetime as dt, timedelta
import logging
from typing import Any, Optional

from .command import (
    Command,
    PAUSE_DEFAULT,
    PRIORITY_DEFAULT,
    PRIORITY_HIGH,
)
from .const import __dev_mode__, DEVICE_LOOKUP, DEVICE_TABLE, DEVICE_TYPES
from .exceptions import CorruptStateError

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


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


def _dtm(value) -> str:
    def dtm_to_hex(tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, *args):
        return f"{tm_min:02X}{tm_hour:02X}{tm_mday:02X}{tm_mon:02X}{tm_year:04X}"

    if value is None:
        return "FF" * 6

    if isinstance(value, str):
        try:
            value = dt.fromisoformat(value)
        except ValueError:
            raise ValueError("Invalid datetime isoformat string")
    elif not isinstance(value, dt):
        raise TypeError("Invalid datetime object")

    if value < dt.now() + timedelta(minutes=1):
        raise ValueError("Invalid datetime")

    return dtm_to_hex(*value.timetuple())


class Entity:
    """The Device/Zone base class."""

    def __init__(self, gateway, entity_id, controller=None) -> None:
        self._gwy = gateway
        self._que = gateway.cmd_que
        self._ctl = controller

        self.id = entity_id

        self._msgs = {}

    @property
    def controller(self):  # -> Optional[Controller]:
        """Return the id of the entity's controller, if known."""

        return self._ctl  # TODO: if the controller is not known, try to find it?

    @controller.setter
    def controller(self, controller) -> None:
        """Set the device's parent controller, after validating it."""

        if not isinstance(controller, Controller) and not controller.is_controller:
            raise TypeError(f"Not a controller: {controller}")

        if self._ctl is not None:  # zones have this set at instantiation
            if self._ctl is not controller:
                # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5
                raise CorruptStateError(
                    f"Device {self} has a mismatched controller: "
                    f"old={self._ctl.id}, new={controller.id}",
                )
            return

        self._ctl = controller
        self._ctl.devices.append(self)
        self._ctl.device_by_id[self.id] = self
        _LOGGER.debug("Entity %s: controller now set to %s", self.id, self._ctl.id)

    def _command(self, code, **kwargs) -> None:
        dest = kwargs.get("dest_addr", self.id)
        verb = kwargs.get("verb", "RQ")
        payload = kwargs.get("payload", "00")

        self._msgs.pop(code, None)  # remove the old one, so we can tell if RP'd

        priority_default = PRIORITY_HIGH if verb == " W" else PRIORITY_DEFAULT
        kwargs = {
            "pause": kwargs.get("pause", PAUSE_DEFAULT),
            "priority": kwargs.get("priority", priority_default),
        }

        self._que.put_nowait(Command(verb, dest, code, payload, **kwargs))

    def _discover(self):
        # pass
        raise NotImplementedError

    def _get_msg_value(self, code, key=None) -> Optional[Any]:
        if self._msgs.get(code):
            if isinstance(self._msgs[code].payload, list):
                return self._msgs[code].payload

            if key is not None:
                return self._msgs[code].payload.get(key)

            result = self._msgs[code].payload
            return {
                k: v
                for k, v in result.items()
                if k[:1] != "_" and k not in ("domain_id", "zone_idx")
            }

    def update(self, msg) -> None:
        if "domain_id" in msg.payload:  # isinstance(msg.payload, dict) and
            self._domain[msg.payload["domain_id"]] = {msg.code: msg}  # 01/02/23
            return

        if msg.verb == " W":
            if msg.code in self._msgs and self._msgs[msg.code].verb != msg.verb:
                return

        if msg.verb == "RQ":  # and msg.payload:
            if msg.code in self._msgs and self._msgs[msg.code].verb != msg.verb:
                return

        # may get an RQ/W initially, but RP/I will override
        # self._msgs.update({msg.code: msg})
        self._msgs[msg.code] = msg

    @property
    def pkt_codes(self) -> list:
        return list(self._msgs.keys())


class Actuator:  # 3EF0, 3EF1
    """Some devices have a actuator."""

    @property
    def actuator_enabled(self) -> Optional[bool]:  # 3EF0, TODO: does 10: RP/3EF1?
        return self._get_msg_value("3EF0", "actuator_enabled")

    @property
    def actuator_state(self) -> Optional[float]:  # 3EF1, TODO: not all actuators
        return self._get_msg_value("3EF1")


class BatteryState:  # 1060
    """Some devices have a battery."""

    @property
    def battery_state(self):
        low_battery = self._get_msg_value("1060", "low_battery")
        if low_battery is not None:
            battery_level = self._get_msg_value("1060", "battery_level")
            return {"low_battery": low_battery, "battery_level": battery_level}


class HeatDemand:  # 3150
    """Some devices have heat demand."""

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._get_msg_value("3150", "heat_demand")


class Setpoint:  # 2309
    """Some devices have a setpoint."""

    @property
    def setpoint(self) -> Optional[Any]:  # 2309
        return self._get_msg_value("2309", "setpoint")


class Temperature:  # 30C9
    """Some devices have a temperature sensor."""

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        return self._get_msg_value("30C9", "temperature")


# ######################################################################################

# ??: used for unknown device types
class Device(Entity):
    """The Device base class."""

    def __init__(self, gateway, device_addr, controller=None, domain_id=None) -> None:
        _LOGGER.debug("Creating a %s, %s", self.__class__, device_addr.id)
        super().__init__(gateway, device_addr.id, controller)

        assert device_addr.id not in gateway.device_by_id, "Duplicate device address"

        gateway.devices.append(self)
        gateway.device_by_id[device_addr.id] = self

        if controller is not None:  # here, assumed to be valid
            controller.devices.append(self)
            controller.device_by_id[self.id] = self

        self.addr = device_addr
        self.type = device_addr.type
        self.dev_type = DEVICE_TYPES.get(self.addr.type)
        self.hex_id = dev_id_to_hex(device_addr.id)

        if self.addr.type in DEVICE_TABLE:
            self._has_battery = DEVICE_TABLE[self.addr.type].get("has_battery")
            self._is_actuator = DEVICE_TABLE[self.addr.type].get("is_actuator")
            self._is_sensor = DEVICE_TABLE[self.addr.type].get("is_sensor")
        else:
            self._has_battery = None
            self._is_actuator = None
            self._is_sensor = None

        self._zone = None
        self._domain = {}
        self._domain_id = domain_id

        attrs = gateway.known_devices.get(device_addr.id)
        self._friendly_name = attrs.get("friendly_name") if attrs else None
        self._ignored = attrs.get("ignored", False) if attrs else False

        # self._discover()

    # def __repr__(self) -> str:
    #     """Return a JSON dict of all the public atrributes of an entity."""

    #     result = {
    #         a: getattr(self, a)
    #         for a in dir(self)
    #         if not a.startswith("_") and not callable(getattr(self, a))
    #     }
    #     return json.dumps(result)

    def __repr__(self) -> str:
        return self.id

    def __str__(self) -> str:
        return f"{self.id} ({self.dev_type})"

    @property
    def _discover(self):
        # do these even if battery-powered (e.g. device might be in rf_check mode)
        for code in ("0016", "1FC9"):
            self._command(code, payload="0000" if code == "0016" else "00")

        if self.has_battery is not True:
            self._command("10E0")

        # if self.addr.type not in ("01", "13") and not self.has_battery:  # TODO: dev
        #     for code in CODE_SCHEMA:
        #         if code == "0404":
        #             continue
        #         self._command(code, payload="0000" if code != "1F09" else "00")

    def update(self, msg) -> None:
        super().update(msg)

        if self._ctl is not None and "parent_idx" in msg.payload:
            self.zone = self._ctl.get_zone(msg.payload["parent_idx"])

    @property
    def zone(self) -> Optional[Entity]:  # should be: Optional[Zone]
        """Return the device's parent zone, if known."""

        return self._zone

    @zone.setter
    def zone(self, zone: Entity) -> None:  # should be: zone: Zone
        """Set the device's parent zone, after validating it.

        There are three possible sources for the parent zone of a device:
        1. a 000C packet (from their controller) for actuators only
        2. a message.payload["zone_idx"]
        3. the sensor-matching algorithm fro zone sensors only

        All three will execute a dev.zone = zone (i.e. via this setter).

        Devices don't have parents, rather: Zones have children; a mis-configured
        system could have a device as a child of two domains.
        """

        if not isinstance(zone, Entity):  # should be: zone, Zone)
            raise TypeError(f"Not a zone: {zone}")

        if self._zone is not None:
            if self._zone is not zone:
                #
                raise CorruptStateError(
                    f"Device {self} has a mismatched parent zone: "
                    f"old={self._zone}, new={zone}",
                )
            return

        self._zone = self._domain_id = zone
        self._zone.devices.append(self)
        self._zone.device_by_id[self.id] = self
        _LOGGER.debug("Device %s: parent zone now set to %s", self.id, self._zone)

    @property
    def description(self) -> Optional[str]:
        return DEVICE_TABLE[self.type]["name"] if self.type in DEVICE_TABLE else None

    @property
    def hardware_info(self) -> Optional[str]:  # 10E0
        return self._get_msg_value("10E0")

    @property
    def has_battery(self) -> Optional[bool]:  # 1060
        """Return True if a device is battery powered.

        Devices with a battery-backup may still be mains-powered.
        """
        if self._has_battery is not None:
            return self._has_battery

        if "1060" in self._msgs:
            self._has_battery = True
        return self._has_battery

    @property
    def is_controller(self) -> Optional[bool]:  # 1F09
        if self._ctl is self:
            return True
        # if isinstance(self, Controller):
        #     return True
        # if self.type in ("01", "23"):
        #     return True
        # if "1F09" in self._msgs:  # TODO: needs to add msg to instaition
        #     return self._msgs["1F09"].verb == " I"
        # if "31D9" in self._msgs:  # TODO: needs to add msg to instaition
        #     return self._msgs["31D9"].verb == " I"
        return False

    @property
    def _pkt_1fc9(self) -> list:
        return self._get_msg_value("1FC9")  # we want the RPs

    @property
    def rf_signal(self) -> Optional[dict]:  # TODO: make 'current', else add dtm?
        return self._get_msg_value("0016")


# 01:
class Controller(Device):
    """The Controller base class, supports child devices and zones only."""

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self.devices = [self]
        self.device_by_id = {self.id: self}

        self._ctl = self
        self._domain_id = "FF"


# 02: "10E0", "3150";; "0008", "22C9", "22D0"
class UfhController(Device, HeatDemand):
    """The UFH class, the HCE80 that controls the UFH heating zones."""

    # 12:27:24.398 067  I --- 02:000921 --:------ 01:191718 3150 002 0360
    # 12:27:24.546 068  I --- 02:000921 --:------ 01:191718 3150 002 065A
    # 12:27:24.693 067  I --- 02:000921 --:------ 01:191718 3150 002 045C
    # 12:27:24.824 059  I --- 01:191718 --:------ 01:191718 3150 002 FC5C
    # 12:27:24.857 067  I --- 02:000921 --:------ 02:000921 3150 006 0060015A025C

    def update(self, msg):
        def do_3150_magic() -> None:
            return

        super().update(msg)
        return

        # "0008|FA/FC", "22C9|array", "22D0|none", "3150|ZZ/array(/FC?)"

        if msg.code in ("22C9") and not isinstance(msg.payload, list):
            pass
        else:
            super().update(msg)

        if msg.code == "3150" and isinstance(msg.payload, list):  # msg.is_array:
            do_3150_magic()

    @property
    def zones(self):  # 22C9
        return self._get_msg_value("22C9")


# 07: "1060";; "1260" "10A0"
class DhwSensor(Device, BatteryState):
    """The DHW class, such as a CS92."""

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._domain_id = "HW"

    def update(self, msg):
        super().update(msg)

        # if msg.code == "10A0":
        #     return self._msgs["10A0"].dst.addr

    @property
    def temperature(self):
        return self._get_msg_value("1260", "temperature")


# 10: "10E0", "3EF0", "3150";; "22D9", "3220" ("1FD4"), TODO: 3220
class OtbGateway(Device, Actuator, HeatDemand):
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._domain_id = "FC"

    @property
    def boiler_setpoint(self) -> Optional[Any]:  # 22D9
        return self._get_msg_value("22D9", "boiler_setpoint")

    @property
    def _last_opentherm_msg(self) -> Optional[Any]:  # 3220
        return self._get_msg_value("3220")


# 03/12/22/34: 1060/2309/30C9;; (03/22: 0008/0009/3EF1, 2349?) (34: 000A/10E0/3120)
class Thermostat(Device, BatteryState, Setpoint, Temperature):
    """The STA class, such as a TR87RF."""


# 13: "3EF0", "1100";; ("3EF1"?)
class BdrSwitch(Device, Actuator):
    """The BDR class, such as a BDR91."""

    def __init__(self, gateway, device_addr, **kwargs) -> None:
        super().__init__(gateway, device_addr, **kwargs)

        self._is_tpi = None

    def _discover(self):
        super()._discover()

        self._command("1100", payload="00")

        # all relays seem the same, except for 0016, and 1100
        # for code in ("3B00", "3EF0", "3EF1"] + ["0008", "1100", "1260"):
        #     for payload in ("00", "FC", "FF", "0000", "000000"):
        #         self._command(code, payload=payload)

    def update(self, msg):
        super().update(msg)

        if self._is_tpi is None:
            _ = self.is_tpi

    @property
    def is_tpi(self) -> Optional[bool]:  # 3B00
        def make_tpi():
            self.__class__ = TpiSwitch
            self.dev_type = "TPI"
            self._domain_id = "FC"  # TODO: check is None first
            _LOGGER.debug("Promoted device %s to %s", self.id, self.dev_type)

            self._is_tpi = True

            # self._discover()

        if self._is_tpi is not None:
            return self._is_tpi

        # try to cast a new type (must be a superclass of the current type)
        if "1FC9" in self._msgs and self._msgs["1FC9"].verb == "RP":
            if "3B00" in self._msgs["1FC9"].raw_payload:
                make_tpi()

        elif "3B00" in self._msgs and self._msgs["3B00"].verb == " I":
            make_tpi()

        return self._is_tpi

    @property
    def tpi_params(self) -> dict:  # 1100
        return self._get_msg_value("1100")


# 13: "3EF0", "1100"; ("3B00")
class TpiSwitch(BdrSwitch):  # TODO: superset of BDR switch?
    """The TPI class, the BDR91 that controls the boiler."""

    # No __init__(), as not instantiated directly

    def _discover(self):  # NOTE: do not super()._discover()

        for code in ("1100",):
            self._command(code, payload="00")

        # doesn't like like TPIs respond to a 3B00
        # for payload in ("00", "C8"):
        #     for code in ("00", "FC", "FF"):
        #         self._command("3B00", payload=f"{code}{payload}")


# 04: "1060", "3150", "2309", "30C9";; "0100", "12B0" ("0004")
class TrvActuator(Device, BatteryState, HeatDemand, Setpoint, Temperature):
    """The TRV class, such as a HR92."""

    @property
    def window_state(self) -> Optional[bool]:  # 12B0
        return self._get_msg_value("12B0", "window_open")


DEVICE_CLASSES = {
    "01": Controller,  # use EvoSystem instead of Controller
    "02": UfhController,
    "03": Thermostat,
    "04": TrvActuator,
    "07": DhwSensor,
    "10": OtbGateway,
    "12": Thermostat,
    "13": BdrSwitch,
    "22": Thermostat,
    "23": Controller,  # a Programmer, use System instead of Controller
    "34": Thermostat,
}
