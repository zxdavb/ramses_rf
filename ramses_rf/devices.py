#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import logging
from inspect import getmembers, isclass
from sys import modules
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from .command import FUNC, TIMEOUT, Command, Priority
from .const import (
    _000C_DEVICE,
    ATTR_HEAT_DEMAND,
    ATTR_RELAY_DEMAND,
    ATTR_SETPOINT,
    ATTR_TEMP,
    ATTR_WINDOW_OPEN,
    DEVICE_HAS_BATTERY,
    DEVICE_TABLE,
    DEVICE_TYPES,
    DISCOVER_ALL,
    DISCOVER_PARAMS,
    DISCOVER_SCHEMA,
    DISCOVER_STATUS,
    DOMAIN_TYPE_MAP,
    __dev_mode__,
    id_to_address,
)
from .exceptions import CorruptStateError
from .helpers import dev_id_to_hex, schedule_task
from .opentherm import MSG_ID, MSG_TYPE, VALUE  # R8810A_MSG_IDS
from .ramses import RAMSES_DEVICES

I_, RQ, RP, W_ = " I", "RQ", "RP", " W"

DEFAULT_BDR_ID = "13:000730"
DEFAULT_EXT_ID = "17:000730"
DEFAULT_THM_ID = "03:000730"


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


DEVICE_CLASS = SimpleNamespace(
    BDR="BDR",  # Electrical relay
    CTL="CTL",  # Controller
    C02="C02",  # HVAC C02 sensor
    DEV="DEV",  # Generic device
    DHW="DHW",  # DHW sensor
    EXT="EXT",  # External weather sensor
    FAN="FAN",  # HVAC fan, 31D[9A]: 20|29|30|37 (some, e.g. 29: only 31D9)
    GWY="GWY",  # Gateway interface (RF to USB), aka HGI
    HUM="HUM",  # HVAC humidity sensor, 1260: 32
    OTB="OTB",  # OpenTherm bridge
    PRG="PRG",  # Programmer
    RFG="RFG",  # RF gateway (RF to ethernet)
    STA="STA",  # Thermostat
    SWI="SWI",  # HVAC switch, 22F[13]: 02|06|20|32|39|42|49|59 (no 20: are both)
    TRV="TRV",  # Thermostatic radiator valve
    UFC="UFC",  # UFH controller
)
_DEV_TYPE_TO_CLASS = {
    None: DEVICE_CLASS.DEV,  # a generic, promotable device
    "00": DEVICE_CLASS.TRV,
    "01": DEVICE_CLASS.CTL,
    "02": DEVICE_CLASS.UFC,
    "03": DEVICE_CLASS.STA,
    "04": DEVICE_CLASS.TRV,
    "07": DEVICE_CLASS.DHW,
    "10": DEVICE_CLASS.OTB,
    "12": DEVICE_CLASS.STA,  # 12: can act like a DEVICE_CLASS.PRG
    "13": DEVICE_CLASS.BDR,
    "17": DEVICE_CLASS.EXT,
    "18": DEVICE_CLASS.GWY,
    "20": DEVICE_CLASS.FAN,
    "22": DEVICE_CLASS.STA,  # 22: can act like a DEVICE_CLASS.PRG
    "23": DEVICE_CLASS.PRG,
    "29": DEVICE_CLASS.FAN,
    "30": DEVICE_CLASS.RFG,  # also: FAN
    "32": DEVICE_CLASS.HUM,  # also: SWI
    "34": DEVICE_CLASS.STA,
    "37": DEVICE_CLASS.FAN,
    "39": DEVICE_CLASS.SWI,
    "42": DEVICE_CLASS.SWI,
    "49": DEVICE_CLASS.SWI,
    "59": DEVICE_CLASS.SWI,
}  # these are the default device classes for common types


class Entity:
    """The Device/Zone base class."""

    def __init__(self, gwy) -> None:
        self._loop = gwy._loop

        self._gwy = gwy
        self.id = None

        self._msgs = {}
        self._msgz = {I_: {}, RQ: {}, RP: {}, W_: {}}

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        pass

    def _get_msg_value(self, code, key=None) -> dict:
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

    def _handle_msg(self, msg) -> None:  # TODO: beware, this is a mess
        if msg.code in self._msgz[msg.verb]:
            self._msgz[msg.verb][msg.code][msg._pkt._index] = msg
        else:
            self._msgz[msg.verb][msg.code] = {msg._pkt._index: msg}

        if msg.verb in (I_, RP):  # TODO: deprecate
            self._msgs[msg.code] = msg

    @property
    def _dump_msgs(self) -> List:
        return [msg for msg in self._msgs.values()]

    def _send_cmd(self, code, dest_id, payload, verb=RQ, **kwargs) -> None:
        self._msgs.pop(code, None)  # remove the old one, so we can tell if RP'd rcvd
        self._gwy.send_cmd(Command(verb, code, payload, dest_id, **kwargs))

    def _msg_payload(self, msg, key=None) -> Optional[Any]:
        if msg and not msg.is_expired:
            if key:
                return msg.payload.get(key)
            return {k: v for k, v in msg.payload.items() if k[:1] != "_"}

    def _msg_expired(self, msg_name: str) -> Optional[bool]:
        attr = f"_{msg_name}"
        if not hasattr(self, attr):
            _LOGGER.error("%s: is not tracking %s msgs", self, msg_name)
            return

        msg = getattr(self, f"_{msg_name}")
        if not msg:
            _LOGGER.warning("%s: has no valid %s msg", self, msg_name)
        # elif msg_name != RAMSES_CODES[msg.code][NAME]:
        #     _LOGGER.warning(
        #         "%s: Message(%s) doesn't match name: %s",
        #         self,
        #         msg._pkt._header,
        #         msg_name,
        #     )
        #     assert False, msg.code
        elif msg.is_expired:
            _LOGGER.warning(
                "%s: Message(%s) has expired (%s)", self, msg._pkt._header, attr
            )
        else:
            return True

    @property
    def _codes(self) -> dict:
        return {
            "codes": sorted([k for k, v in self._msgs.items()]),
        }

    @property
    def controller(self):  # -> Optional[Controller]:
        """Return the entity's controller, if known."""

        return self._ctl  # TODO: if the controller is not known, try to find it?


class DeviceBase(Entity):
    """The Device base class."""

    def __init__(self, gwy, dev_addr, ctl=None, domain_id=None) -> None:
        _LOGGER.debug("Creating a Device: %s (%s)", dev_addr.id, self.__class__)
        super().__init__(gwy)

        self.id = dev_addr.id
        if self.id in gwy.device_by_id:
            raise LookupError(f"Duplicate device: {self.id}")

        gwy.device_by_id[self.id] = self
        gwy.devices.append(self)

        self._ctl = self._set_ctl(ctl) if ctl else None

        self._domain_id = domain_id
        self._parent = None

        self.addr = dev_addr
        self.hex_id = dev_id_to_hex(dev_addr.id)
        self.type = dev_addr.type

        if self.type in DEVICE_TABLE:
            self._has_battery = DEVICE_TABLE[self.addr.type].get("has_battery")
            self._is_actuator = DEVICE_TABLE[self.addr.type].get("is_actuator")
            self._is_sensor = DEVICE_TABLE[self.addr.type].get("is_sensor")
        else:
            self._has_battery = None
            self._is_actuator = None
            self._is_sensor = None

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id})"

    def __str__(self) -> str:
        return f"{self.id} ({DEVICE_TYPES.get(self.id[:2])})"

    def __lt__(self, other) -> bool:
        if not hasattr(other, "id"):
            return NotImplemented
        return self.id < other.id

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # sometimes, battery-powered devices will respond to an RQ (e.g. bind mode)
        # super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA and self.type not in DEVICE_HAS_BATTERY:
            self._send_cmd("1FC9", retries=3)  # rf_bind

        # if discover_flag & DISCOVER_PARAMS and self.type not in DEVICE_HAS_BATTERY:
        #     pass

        if discover_flag & DISCOVER_STATUS and self.type not in DEVICE_HAS_BATTERY:
            self._send_cmd("0016", retries=3)  # rf_check

    def _send_cmd(self, code, **kwargs) -> None:
        dest = kwargs.pop("dest_addr", self.id)
        payload = kwargs.pop("payload", "00")
        super()._send_cmd(code, dest, payload, **kwargs)

    def _set_ctl(self, ctl) -> None:  # self._ctl
        """Set the device's parent controller, after validating it."""

        if self._ctl is ctl:
            return
        if self._ctl is not None:
            raise CorruptStateError(f"{self} changed controller: {self._ctl} to {ctl}")

        #  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5  # has been seen
        if not isinstance(ctl, Controller) and not ctl._is_controller:
            raise TypeError(f"Device {ctl} is not a controller")

        self._ctl = ctl
        ctl.device_by_id[self.id] = self
        ctl.devices.append(self)
        _LOGGER.debug("%s: controller now set to %s", self, ctl)

    def _handle_msg(self, msg) -> None:
        """Check that devices only handle messages they have sent."""
        assert msg.src is self, "Devices should only keep msgs they sent"
        super()._handle_msg(msg)

    @property
    def _is_present(self) -> bool:
        """Try to exclude ghost devices (as caused by corrupt packet addresses)."""
        return any(
            m.src == self for m in self._msgs.values() if not m.is_expired
        )  # TODO: needs addressing

    @property
    def _is_controller(self) -> Optional[bool]:  # 1F09
        if self._ctl is not None:
            return self._ctl is self

        # if isinstance(device, Controller):
        # if domain_id == "FF"
        # if dev_addr.type in SYSTEM_CLASSES:
        if self.type in ("01", "23"):
            pass
        # if "1F09" in self._msgs:  # TODO: needs to add msg as attr
        #     return self._msgs["1F09"].verb == I_
        # if "31D9" in self._msgs:  # TODO: needs to add msg as attr
        #     return self._msgs["31D9"].verb == I_
        return False

    @property
    def schema(self) -> dict:
        """Return the fixed attributes of the device (e.g. TODO)."""

        return self._codes if DEV_MODE else {}

    @property
    def params(self):
        return {}

    @property
    def status(self):
        return {}


class Actuator:  # 3EF0, 3EF1

    ACTUATOR_CYCLE = "actuator_cycle"
    ACTUATOR_ENABLED = "actuator_enabled"  # boolean
    ACTUATOR_STATE = "actuator_state"
    ENABLED = "enabled"
    MODULATION_LEVEL = "modulation_level"

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("3EF1")  # No RPs to 3EF0

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == "3EF0" and msg.verb == I_:  # NOT RP, TODO: why????
            self._send_cmd("3EF1", priority=Priority.LOW, retries=1)

    @property
    def actuator_cycle(self) -> Optional[dict]:  # 3EF1
        return self._msg_payload(self._msgs.get("3EF1"))

    @property
    def actuator_state(self) -> Optional[dict]:  # 3EF0 (mod_level, flame_active, etc.)
        return self._msg_payload(self._msgs.get("3EF0"))

    @property
    def enabled(self) -> Optional[bool]:  # 3EF0, 3EF1
        """Return the actuator's current state."""
        msgs = [m for m in self._msgs.values() if m.code in ("3EF0", "3EF1")]
        return max(msgs).payload[self.ACTUATOR_ENABLED] if msgs else None

    @property
    def modulation_level(self) -> Optional[float]:  # 3EF0/3EF1
        msgs = [m for m in self._msgs.values() if m.code in ("3EF0", "3EF1")]
        return max(msgs).payload[self.MODULATION_LEVEL] if msgs else None

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.ACTUATOR_CYCLE: self.actuator_cycle,
            self.ACTUATOR_STATE: self.actuator_state,
            self.MODULATION_LEVEL: self.modulation_level,  # TODO: keep? (is duplicate)
        }


class BatteryState:  # 1060

    BATTERY_LOW = "battery_low"  # boolean
    BATTERY_STATE = "battery_state"  # percentage

    @property
    def battery_low(self) -> Optional[bool]:  # 1060
        if "1060" in self._msgs:
            return self._msgs["1060"].payload[self.BATTERY_LOW]

    @property
    def battery_state(self) -> Optional[dict]:  # 1060
        return self._msg_payload(self._msgs.get("1060"))

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.BATTERY_STATE: self.battery_state,
        }


class HeatDemand:  # 3150

    HEAT_DEMAND = ATTR_HEAT_DEMAND  # percentage valve open

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        if "3150" in self._msgs:
            return self._msgs["3150"].payload[self.HEAT_DEMAND]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.HEAT_DEMAND: self.heat_demand,
        }


class Setpoint:  # 2309

    SETPOINT = ATTR_SETPOINT  # degrees Celsius

    @property
    def setpoint(self) -> Optional[float]:  # 2309
        try:
            if "2309" in self._msgs:
                return self._msgs["2309"].payload[self.SETPOINT]
        except TypeError:  # FIXME: 12: as a controller = {[{}, ...]}, not {}
            pass

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.SETPOINT: self.setpoint,
        }


class Temperature:  # 30C9 (fakeable)

    TEMPERATURE = ATTR_TEMP  # degrees Celsius

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._30C9_faked = None

    def _make_fake(self, bind=None):
        self._30C9_faked = True
        if bind:
            self._bind()
        _LOGGER.error("%s: Faking now enabled", self)  # TODO: shoudl be info/debug

    def _bind(self):
        if not self._30C9_faked:
            raise TypeError("Can't bind sensor (Faking is not enabled)")

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        try:
            if "30C9" in self._msgs:
                return self._msgs["30C9"].payload[self.TEMPERATURE]
        except TypeError:  # FIXME: 12: as a controller = {[{}, ...]}, not {}
            pass

    @temperature.setter
    def temperature(self, value) -> None:  # 30C9
        if not self._30C9_faked:
            raise AttributeError("Can't set attribute (Faking is not enabled)")

        cmd = Command.put_sensor_temp(self.id, value)
        # cmd = Command.put_sensor_temp(
        #     self._gwy.rfg.id if self == self._gwy.rfg._faked_thm else self.id, value
        # )
        self._gwy.send_cmd(cmd)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class DeviceInfo:  # 10E0

    RF_BIND = "rf_bind"
    DEVICE_INFO = "device_info"

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        if discover_flag & DISCOVER_SCHEMA and self.type not in DEVICE_HAS_BATTERY:
            self._send_cmd("1FC9", retries=3)  # rf_bind
            if self.type != "13":
                self._send_cmd("10E0", retries=3)  # TODO: use device hints

    @property
    def device_info(self) -> Optional[dict]:  # 10E0
        return self._msg_payload(self._msgs.get("10E0"))

    @property
    def schema(self) -> dict:
        result = super().schema
        # result.update({self.RF_BIND: self._msg_payload(self._msgs.get("1FC9"))})
        if "10E0" in self._msgs or "10E0" in RAMSES_DEVICES.get(self.type, []):
            result.update({self.DEVICE_INFO: self.device_info})
        return result


class Device(DeviceInfo, DeviceBase):
    """The Device base class - also used for unknown device types."""

    __dev_class__ = DEVICE_CLASS.DEV  # DEVICE_TYPES = ("??", )

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if not msg._gwy.config.enable_eavesdrop:
            return

        if self._ctl is not None and "parent_idx" in msg.payload:
            # TODO: is buggy - remove? how?
            self._set_parent(self._ctl._evo._get_zone(msg.payload["parent_idx"]))

    def _set_parent(self, parent, domain=None) -> None:  # self._parent
        """Set the device's parent zone, after validating it.

        There are three possible sources for the parent zone of a device:
        1. a 000C packet (from their controller) for actuators only
        2. a message.payload["zone_idx"]
        3. the sensor-matching algorithm for zone sensors only

        Devices don't have parents, rather: Zones have children; a mis-configured
        system could have a device as a child of two domains.
        """

        # these imports are here to prevent circular references
        from .systems import System
        from .zones import DhwZone, Zone

        if self._parent is not None and self._parent is not parent:
            raise CorruptStateError(
                f"{self} changed parent: {self._parent} to {parent}, "
            )

        if isinstance(parent, Zone):
            if domain and domain != parent.idx:
                raise TypeError(f"{self}: domain must be {parent.idx}, not {domain}")
            domain = parent.idx

        elif isinstance(parent, DhwZone):  # usu. FA
            if domain not in ("F9", "FA"):  # may not be known if eavesdrop'd
                raise TypeError(f"{self}: domain must be F9 or FA, not {domain}")

        elif isinstance(parent, System):  # usu. FC
            if domain != "FC":  # was: not in ("F9", "FA", "FC", "HW"):
                raise TypeError(f"{self}: domain must be FC, not {domain}")

        else:
            raise TypeError(f"{self}: parent must be System, DHW or Zone, not {parent}")

        self._set_ctl(parent._ctl)
        self._parent = parent
        self._domain_id = domain

        if hasattr(parent, "devices") and self not in parent.devices:
            parent.devices.append(self)
            parent.device_by_id[self.id] = self
        _LOGGER.debug("Device %s: parent now set to %s", self, parent)

    @property
    def zone(self) -> Optional[Entity]:  # should be: Optional[Zone]
        """Return the device's parent zone, if known."""

        return self._parent

    @property
    def has_battery(self) -> Optional[bool]:  # 1060
        """Return True if a device is battery powered (excludes battery-backup)."""

        if self._has_battery is not None:
            return self._has_battery

        if "1060" in self._msgs:
            self._has_battery = True

        return self._has_battery

    @property
    def schema(self) -> dict:
        """Return the fixed attributes of the device (e.g. TODO)."""

        return {
            **super().schema,
            "dev_class": self.__dev_class__,
        }


class RfiGateway(DeviceBase):  # GWY: 18
    """The HGI80 base class."""

    __dev_class__ = DEVICE_CLASS.GWY  # DEVICE_TYPES = ("18", )

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._ctl = None
        self._domain_id = "FF"
        self._evo = None

        self._faked_bdr = None
        self._faked_ext = None
        self._faked_thm = None

    def _handle_msg(self, msg) -> None:
        def fake_addrs(msg, faked_dev):
            msg.src == faked_dev if msg.src is self else self
            msg.dst == faked_dev if msg.dst is self else self
            return msg

        super()._handle_msg(msg)

        # the following is for aliased devices (not fully-faked devices)
        if msg.code in ("3EF0",) and self._faked_bdr:
            self._faked_bdr._handle_msg(fake_addrs(msg, self._faked_bdr))

        if msg.code in ("0002",) and self._faked_ext:
            self._faked_ext._handle_msg(fake_addrs(msg, self._faked_ext))

        if msg.code in ("30C9",) and self._faked_thm:
            self._faked_thm._handle_msg(fake_addrs(msg, self._faked_thm))

    def _create_fake_dev(self, dev_type, device_id) -> Device:
        if device_id[:2] != dev_type:
            raise TypeError(f"Invalid device ID {device_id} for type '{dev_type}:'")

        dev = self.device_by_id.get(device_id)
        if dev:
            _LOGGER.warning("Destroying %s", dev)
            if dev._ctl:
                del dev._ctl.device_by_id[dev.id]
                dev._ctl.devices.remove(dev)
                dev._ctl = None
            del self.device_by_id[dev.id]
            self.devices.remove(dev)
            dev = None

        dev = self._get_device(id_to_address(device_id))
        dev._make_fake(bind=True)
        return dev

    def create_fake_bdr(self, device_id=DEFAULT_BDR_ID) -> Device:
        """Bind a faked relay (BDR91A) to a controller (i.e. to a domain/zone).

        Will alias the gateway (as "13:000730"), or create a fully-faked 13:.

        HGI80s can only alias one device of a type (use_gateway), but evofw3-based
        gateways can also fully fake multiple devices of the same type.
        """
        if device_id in (self.id, None):
            device_id = DEFAULT_BDR_ID
        device = self._create_fake_dev("13", device_id=device_id)

        if device.id == DEFAULT_BDR_ID:
            self._faked_bdr = device
        return device

    def create_fake_ext(self, device_id=DEFAULT_EXT_ID) -> Device:
        """Bind a faked external sensor (???) to a controller.

        Will alias the gateway (as "17:000730"), or create a fully-faked 17:.

        HGI80s can only alias one device of a type (use_gateway), but evofw3-based
        gateways can also fully fake multiple devices of the same type.
        """

        if device_id in (self.id, None):
            device_id = DEFAULT_EXT_ID
        device = self._create_fake_dev("17", device_id=device_id)

        if device.id == DEFAULT_EXT_ID:
            self._faked_ext = device
        return device

    def create_fake_thm(self, device_id=DEFAULT_THM_ID) -> Device:
        """Bind a faked zone sensor (TR87RF) to a controller (i.e. to a zone).

        Will alias the gateway (as "03:000730"), or create a fully-faked 34:, albeit
        named "03:xxxxxx".

        HGI80s can only alias one device of a type (use_gateway), but evofw3-based
        gateways can also fully fake multiple devices of the same type.
        """
        if device_id in (self.id, None):
            device_id = DEFAULT_THM_ID
        device = self._create_fake_dev("03", device_id=device_id)

        if device.id == DEFAULT_THM_ID:
            self._faked_thm = device
        return device

    @property
    def schema(self):
        return {
            "device_id": self.id,
            "faked_bdr": self._faked_bdr and self._faked_bdr.id,
            "faked_ext": self._faked_ext and self._faked_ext.id,
            "faked_thm": self._faked_thm and self._faked_thm.id,
        }

    @property
    def params(self):
        return {}

    @property
    def status(self):
        return {}


class Controller(Device):  # CTL (01):
    """The Controller base class."""

    __dev_class__ = DEVICE_CLASS.CTL  # DEVICE_TYPES = ("01", )

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._ctl = self  # or args[1]
        self._domain_id = "FF"
        self._evo = None

        self.devices = []  # [self]
        self.device_by_id = {}  # {self.id: self}

    # def _discover(self, discover_flag=DISCOVER_ALL) -> None:
    #     super()._discover(discover_flag=discover_flag)

    #     if discover_flag & DISCOVER_SCHEMA and self.type not in DEVICE_HAS_BATTERY:
    #         pass  # self._send_cmd("1F09", retries=3)

    # #     if discover_flag & DISCOVER_STATUS and self.type not in DEVICE_HAS_BATTERY:
    # #         self._send_cmd("0016", retries=3)  # rf_check


class Programmer(Controller):  # PRG (23):
    """The Controller base class."""

    __dev_class__ = DEVICE_CLASS.PRG  # DEVICE_TYPES = ("23", )


class UfhController(Device):  # UFC (02):
    """The UFC class, the HCE80 that controls the UFH zones."""

    __dev_class__ = DEVICE_CLASS.UFC  # DEVICE_TYPES = ("02", )

    HEAT_DEMAND = ATTR_HEAT_DEMAND

    # 12:27:24.398 067  I --- 02:000921 --:------ 01:191718 3150 002 0360
    # 12:27:24.546 068  I --- 02:000921 --:------ 01:191718 3150 002 065A
    # 12:27:24.693 067  I --- 02:000921 --:------ 01:191718 3150 002 045C
    # 12:27:24.824 059  I --- 01:191718 --:------ 01:191718 3150 002 FC5C
    # 12:27:24.857 067  I --- 02:000921 --:------ 02:000921 3150 006 0060-015A-025C

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.klass = self.__dev_class__

        self._circuits = {}
        self._setpoints = None
        self._heat_demand = None

        self.devices = []  # [self]
        self.device_by_id = {}  # {self.id: self}

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            [  # 000C: used to find evo zone for each configured channel
                self._send_cmd("000C", payload=f"{idx:02X}{_000C_DEVICE.UFH}")
                for idx in range(8)  # for each possible UFH channel/circuit
            ]

        # if discover_flag & DISCOVER_PARAMS:
        #     pass

        # if discover_flag & DISCOVER_STATUS:
        #     pass

        # [  # 3150: no answer
        #     self._send_cmd("3150", payload=f"{zone_idx:02X}")for zone_idx in range(8)
        # ]

        # [  # 22C9: no answer
        #     self._send_cmd("22C9", payload=f"{payload}")
        #     for payload in ("00", "0000", "01", "0100")
        # ]

        # [  # 22D0: dunno, always: {'unknown': '000002'}
        #     self._send_cmd("22D0", payload=f"{payload}")
        #     for payload in ("00", "0000", "00000002")
        # ]

        [  # 0005: shows which channels are active - ?no use? (see above)
            self._send_cmd("0005", payload=f"00{zone_type}")
            for zone_type in ("09",)  # _0005_ZONE_TYPE, also ("00", "04", "0F")
            # for zone_type in _0005_ZONE_TYPE
        ]

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == "000C":
            assert "ufh_idx" in msg.payload, "wsdfh"
            if msg.payload["zone_id"] is not None:
                self._circuits[msg.payload["ufh_idx"]] = msg

        elif msg.code == "22C9":
            if isinstance(msg.payload, list):
                self._setpoints = msg
            # else:
            #     pass  # update the self._circuits[]

        elif msg.code == "3150":
            if isinstance(msg.payload, list):
                self._heat_demands = msg
            elif "domain_id" in msg.payload:
                self._heat_demand = msg
            # else:
            #     pass  # update the self._circuits[]

        # "0008|FA/FC", "22C9|array", "22D0|none", "3150|ZZ/array(/FC?)"

    @property
    def circuits(self) -> Optional[Dict]:  # 000C
        return {
            k: {"zone_idx": m.payload["zone_id"]} for k, m in self._circuits.items()
        }

        # def fix(k):
        #     return "zone_idx" if k == "zone_id" else k

        # return [
        #     {fix(k): v for k, v in m.payload.items() if k in ("ufh_idx", "zone_id")}
        #     for m in self._circuits.values()
        # ]

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        if self._heat_demand:
            return self._heat_demand.payload[self.HEAT_DEMAND]

    @property
    def relay_demand(self) -> Optional[Dict]:  # 0008
        try:
            return self._msgs["0008"].payload[ATTR_RELAY_DEMAND]
        except KeyError:
            return

    @property
    def setpoints(self) -> Optional[Dict]:  # 22C9
        if self._setpoints is None:
            return

        return {
            c["ufh_idx"]: {"temp_high": c["temp_high"], "temp_low": c["temp_low"]}
            for c in self._setpoints.payload
        }
        # return [
        #     {k: v for k, v in d.items() if k in ("ufh_idx", "temp_high", "temp_low")}
        #     for d in (self._setpoints.payload if self._setpoints else [])
        # ]

    @property  # id, type
    def schema(self) -> dict:
        return {
            **super().schema,
            "circuits": self.circuits,
        }

    @property  # setpoint, config, mode (not schedule)
    def params(self) -> dict:
        return {
            **super().params,
            "circuits": self.setpoints,
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            ATTR_HEAT_DEMAND: self.heat_demand,
            ATTR_RELAY_DEMAND: self.relay_demand,
        }


class DhwSensor(BatteryState, Device):  # DHW (07): 10A0, 1260
    """The DHW class, such as a CS92."""

    __dev_class__ = DEVICE_CLASS.DHW  # DEVICE_TYPES = ("07", )

    DHW_PARAMS = "dhw_params"
    TEMPERATURE = ATTR_TEMP
    # _STATE = TEMPERATURE

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._domain_id = "FA"

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.temperature}"

    @property
    def dhw_params(self) -> Optional[dict]:  # 10A0
        return self._msg_payload(self._msgs.get("10A0"))

    @property
    def temperature(self) -> Optional[float]:  # 1260
        if "1260" in self._msgs:
            return self._msgs["1260"].payload[self.TEMPERATURE]

    @property
    def params(self) -> dict:
        return {
            **super().params,
            self.DHW_PARAMS: self.dhw_params,
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class ExtSensor(Device):  # EXT: 17
    """The EXT class (external sensor), such as a HB85/HB95."""

    __dev_class__ = DEVICE_CLASS.EXT  # DEVICE_TYPES = ("17", )

    LUMINOSITY = "luminosity"  # lux
    TEMPERATURE = "temperature"  # Celsius
    WINDSPEED = "windspeed"  # km/h

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._0002_faked = None
        self._1fc9_state = None

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.temperature}"

    def _make_fake(self, bind=None):
        self._0002_faked = True
        if bind:
            self._bind()

    def _bind(self):
        def bind_callback(msg) -> None:
            self._1fc9_state == "bound"

            self._gwy._get_device(self, ctl_addr=id_to_address(msg.payload[0][2]))
            self._ctl._evo._get_zone(msg.payload[0][0])._set_sensor(self)

            cmd = Command(
                I_, "1FC9", f"002309{self.hex_id}", self._ctl.id, from_id=self.id
            )
            self._gwy.send_cmd(cmd)

        if not self._0002_faked:
            raise TypeError("Can't bind sensor (Faking is not enabled)")
        self._1fc9_state = "binding"

        cmd = Command.packet(
            I_,
            "1FC9",
            f"000002{self.hex_id}",
            addr0=self.id,
            addr2=self.id,
            callback={FUNC: bind_callback, TIMEOUT: 3},
        )
        self._gwy.send_cmd(cmd)

    @property
    def temperature(self) -> Optional[float]:  # 0002
        if "0002" in self._msgs:
            return self._msgs["0002"].payload[self.TEMPERATURE]

    @temperature.setter
    def temperature(self, value) -> None:  # 0002
        if not self._0002_faked:
            raise AttributeError("Can't set attribute (Faking is not enabled)")

        cmd = Command.put_outdoor_temp(
            self._gwy.rfg.id if self == self._gwy.rfg._faked_ext else self.id, value
        )
        self._gwy.send_cmd(cmd)

    @property
    def luminosity(self) -> Optional[float]:  # 0002
        raise NotImplementedError

    @luminosity.setter
    def luminosity(self, value) -> None:  # 0002
        raise NotImplementedError

    @property
    def windspeed(self) -> Optional[float]:  # 0002
        raise NotImplementedError

    @windspeed.setter
    def windspeed(self, value) -> None:  # 0002
        raise NotImplementedError

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.LUMINOSITY: self.luminosity,
            self.TEMPERATURE: self.temperature,
            self.WINDSPEED: self.windspeed,
        }


class OtbGateway(Actuator, HeatDemand, Device):  # OTB (10): 22D9, 3220
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    __dev_class__ = DEVICE_CLASS.OTB  # DEVICE_TYPES = ("10", )

    BOILER_SETPOINT = "boiler_setpoint"
    OPENTHERM_STATUS = "opentherm_status"
    # _STATE = super().MODULATION_LEVEL

    SCHEMA_MSG_IDS = (
        0x03,  # ..3: "Slave configuration",
        0x06,  # ..6: "Remote boiler parameter flags",                # see: 0x38, 0x39
        0x0F,  # .15: "Max. boiler capacity (kW) and modulation level setting (%)",
        0x30,  # .48: "DHW Setpoint upper & lower bounds for adjustment (°C)",
        0x31,  # .49: "Max CH water Setpoint upper & lower bounds for adjustment (°C)",
        0x7D,  # 125: "Opentherm version Slave",                            # not native
        0x7F,  # 127: "Slave product version number and type",
    )
    PARAMS_MSG_IDS = (
        0x38,  # .56: "DHW Setpoint (°C) (Remote parameter 1)",             # see: 0x06
        0x39,  # .57: "Max CH water Setpoint (°C) (Remote parameters 2)",   # see: 0x06
        # These are error codes...
        0x05,  # ..5: "Fault flags & OEM codes",
        0x73,  # 115: "OEM diagnostic code",
        # These are STATUS seen RQ'd by 01:/30:, but here to retreive less frequently
        0x71,  # 113: "Number of un-successful burner starts",
        0x72,  # 114: "Number of times flame signal was too low",
        0x74,  # 116: "Number of starts burner",
        0x75,  # 117: "Number of starts central heating pump",
        0x76,  # 118: "Number of starts DHW pump/valve",
        0x77,  # 119: "Number of starts burner during DHW mode",
        0x78,  # 120: "Number of hours burner is in operation (i.e. flame on)",
        0x79,  # 121: "Number of hours central heating pump has been running",
        0x7A,  # 122: "Number of hours DHW pump has been running/valve has been opened",
        0x7B,  # 123: "Number of hours DHW burner is in operation during DHW mode",
    )
    STATUS_MSG_IDS = (
        0x00,  # ..0: "Master/Slave status flags",                          # not native
        0x11,  # .17: "Relative Modulation Level (%)",
        0x12,  # .18: "Water pressure in CH circuit (bar)",
        0x13,  # .19: "Water flow rate in DHW circuit. (L/min)",
        0x19,  # .25: "Boiler flow water temperature (°C)",
        0x1A,  # .26: "DHW temperature (°C)",
        0x1B,  # .27: "Outside temperature (°C)",  # TODO: any value here?  # not native
        0x1C,  # .28: "Return water temperature (°C)",
    )
    WRITE_MSG_IDS = (  # Write-Data, some may also Read-Data (will need to check)
        0x01,  # ..1: "CH water temperature Setpoint (°C)",
        0x02,  # ..2: "Master configuration",
        0x0E,  # .14: "Maximum relative modulation level setting (%)",  # c.f. 0x11
        0x10,  # .16: "Room Setpoint (°C)",     # tell slave the room setpoint?
        0x18,  # .24: "Room temperature (°C)",  # tell slave the room temp?
        0x38,  # .56:  -see above-
        0x39,  # .57:  -see above-
        0x7C,  # 124: "Opentherm version Master",
        0x7E,  # 126: "Master product version number and type",
    )

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._domain_id = "FC"

        self._opentherm_msg = self._msgz[RP]["3220"] = {}
        self._supported_msg = {}

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.modulation_level}"  # 3EF0

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # see: https://www.opentherm.eu/request-details/?post_ids=2944
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            [
                self._gwy.send_cmd(Command.get_opentherm_data(self.id, m))
                for m in self.SCHEMA_MSG_IDS  # From OT v2.2: version numbers
                if self._supported_msg.get(m) is not False
                and (
                    not self._opentherm_msg.get(m) or self._opentherm_msg[m].is_expired
                )
            ]

        if discover_flag & DISCOVER_PARAMS:
            [
                self._gwy.send_cmd(Command.get_opentherm_data(self.id, m))
                for m in self.PARAMS_MSG_IDS
                if self._supported_msg.get(m) is not False
                and (
                    not self._opentherm_msg.get(m) or self._opentherm_msg[m].is_expired
                )
            ]

        if discover_flag & DISCOVER_STATUS:
            self._gwy.send_cmd(Command(RQ, "22D9", "00", self.id))
            [
                self._gwy.send_cmd(Command.get_opentherm_data(self.id, m, retries=0))
                for m in self.STATUS_MSG_IDS
                if self._supported_msg.get(m) is not False
                and (
                    not self._opentherm_msg.get(m) or self._opentherm_msg[m].is_expired
                )
            ]

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == "1FD4":  # every 30s
            if msg.payload["ticker"] % 60 in (1, 3):
                self._discover(discover_flag=DISCOVER_PARAMS)
            elif msg.payload["ticker"] % 6 in (0, 2):
                self._discover(discover_flag=DISCOVER_STATUS)

        elif msg.code == "3220":  # all are RP
            if msg.payload[MSG_TYPE] == "Unknown-DataId":
                self._supported_msg[msg.payload[MSG_ID]] = False
            else:
                self._supported_msg[msg.payload[MSG_ID]] = True

    def _ot_msg_value(self, msg_id) -> Optional[float]:
        try:
            return self._opentherm_msg[f"{msg_id:02X}"].payload[VALUE]
        except KeyError:
            return

    @property
    def boiler_water_temperature(self) -> Optional[float]:  # 3220/0x19
        return self._ot_msg_value(0x19)

    @property
    def ch_water_pressure(self) -> Optional[float]:  # 3220/0x12
        return self._ot_msg_value(0x12)

    @property
    def dhw_flow_rate(self) -> Optional[float]:  # 3220/0x13
        return self._ot_msg_value(0x13)

    @property
    def dhw_temperature(self) -> Optional[float]:  # 3220/0x1A
        return self._ot_msg_value(0x1A)

    @property  # HA
    def relative_modulation_level(self) -> Optional[float]:  # 3220/0x11
        return self._ot_msg_value(0x11)

    @property
    def return_water_temperature(self) -> Optional[float]:  # 3220/0x1C
        return self._ot_msg_value(0x1C)

    @property  # HA
    def boiler_setpoint(self) -> Optional[float]:  # 22D9
        try:
            return self._msgs["22D9"].payload[self.BOILER_SETPOINT]
        except KeyError:
            return

    @property
    def opentherm_schema(self) -> dict:
        result = {
            v.payload["msg_name"]: v.payload
            for k, v in self._opentherm_msg.items()
            if self._supported_msg.get(int(k, 16)) and int(k, 16) in self.SCHEMA_MSG_IDS
        }
        return {
            m: {k: v for k, v in p.items() if k.startswith(VALUE)}
            for m, p in result.items()
        }

    @property
    def opentherm_params(self) -> dict:
        result = {
            v.payload["msg_name"]: v.payload
            for k, v in self._opentherm_msg.items()
            if self._supported_msg.get(int(k, 16)) and int(k, 16) in self.PARAMS_MSG_IDS
        }
        return {
            m: {k: v for k, v in p.items() if k.startswith(VALUE)}
            for m, p in result.items()
        }

    @property
    def opentherm_status(self) -> dict:
        opentherm_status = {
            "boiler_water_temperature": self.boiler_water_temperature,
            "ch_water_pressure": self.ch_water_pressure,
            "dhw_flow_rate": self.dhw_flow_rate,
            "dhw_temperature": self.dhw_temperature,
            "relative_modulation_level": self.relative_modulation_level,
            "return_water_temperature": self.return_water_temperature,
        }
        others = {
            v.payload["msg_name"]: {
                x: y for x, y in v.payload.items() if x.startswith(VALUE)
            }
            for k, v in self._opentherm_msg.items()
            if self._supported_msg.get(int(k, 16)) and k in ("00", "1B")
        }
        return {
            **opentherm_status,
            "other_state_attrs": others,
        }
        # return {
        #     slugify(self._opentherm_msg[msg_id].payload[MSG_NAME]): (
        #         self._opentherm_msg[msg_id].payload[VALUE]
        #     )
        #     for msg_id in (0x11, 0x12, 0x13, 0x19, 0x1A, 0x1C)
        #     if msg_id in self._opentherm_msg
        # }

    @property
    def schema(self) -> dict:
        return {
            **super().schema,
            "opentherm_codes": [
                f"0x{k:02X}" for k, v in self._supported_msg.items() if v
            ],
            "opentherm_schema": self.opentherm_schema,
        }

    @property
    def params(self) -> dict:
        return {
            **super().params,
            "opentherm_params": self.opentherm_params,
        }

    @property
    def status(self) -> dict:
        # llevering: [0, 3, 5, 6, 12, 13, 17, 18, 25, 26, 28, 48, 49, 56, 125]
        # bruce:     [0, 3, 5,    12, 13, 17, 18, 25, 27, 28, 48, 49, 56, 125]
        return {
            **super().status,
            self.BOILER_SETPOINT: self.boiler_setpoint,
            self.OPENTHERM_STATUS: self.opentherm_status,
        }


class Thermostat(BatteryState, Setpoint, Temperature, Device):  # THM (..):
    """The THM/STA class, such as a TR87RF."""

    __dev_class__ = DEVICE_CLASS.STA  # DEVICE_TYPES = ("03", "12", "22", "34")

    # _STATE = super().TEMPERATURE

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._1fc9_state = None

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.temperature}"

    def _bind(self):
        def bind_callback(msg) -> None:
            self._1fc9_state == "bound"

            self._gwy._get_device(self, ctl_addr=id_to_address(msg.payload[0][2]))
            self._ctl._evo._get_zone(msg.payload[0][0])._set_sensor(self)

            cmd = Command(
                I_, "1FC9", f"002309{self.hex_id}", self._ctl.id, from_id=self.id
            )
            self._gwy.send_cmd(cmd)

        super()._bind()
        self._1fc9_state = "binding"

        callback = {FUNC: bind_callback, TIMEOUT: 3}
        payload = "".join(
            f"00{c}{self.hex_id}" for c in ("2309", "30C9", "0008", "1FC9")
        )
        cmd = Command.packet(
            I_, "1FC9", payload, addr0=self.id, addr2=self.id, callback=callback
        )
        self._gwy.send_cmd(cmd)


class BdrSwitch(Actuator, Device):  # BDR (13):
    """The BDR class, such as a BDR91.

    BDR91s can be used in six disctinct modes, including:
    - x2 boiler controller (FC/TPI): either traditional, or newer heat pump-aware
    - x1 electric heat zones (0x/ELE)
    - x1 zone valve zones (0x/VAL)
    - x2 DHW thingys (F9/DHW, FA/DHW)
    """

    __dev_class__ = DEVICE_CLASS.BDR  # DEVICE_TYPES = ("13", )

    RELAY_DEMAND = "relay_demand"  # percentage
    TPI_PARAMS = "tpi_params"
    # _STATE = super().ENABLED, or relay_demand

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._is_tpi = None

        # if kwargs.get("domain_id") == "FC":  # TODO: F9/FA/FC, zone_idx
        #     self._ctl._set_htg_control(self)

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.enabled}"  # or: relay_demand?

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        """The BDRs have one of six roles:
         - heater relay *or* a heat pump relay (alternative to an OTB)
         - DHW hot water valve *or* DHW heating valve
         - Zones: Electric relay *or* Zone valve relay

        They all seem to respond thus (TODO: heat pump/zone valve relay):
         - all BDR91As will (erractically) RP to these RQs
             0016, 1FC9 & 0008, 1100, 3EF1
         - all BDR91As will *not* RP to these RQs
             0009, 10E0, 3B00, 3EF0
         - a BDR91A will *periodically* send an I/3B00/00C8 if it is the heater relay
        """

        super()._discover(discover_flag=discover_flag)

        # if discover_flag & DISCOVER_SCHEMA:
        #     self._send_cmd("1FC9")  # will include a 3B00 if is a heater_relay

        if discover_flag & DISCOVER_PARAMS:
            self._send_cmd("1100")

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd("0008")

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == "3EF0" and msg.verb == I_:  # NOT RP, TODO: why????
            self._send_cmd("0008", priority=Priority.LOW, retries=1)

        # elif msg.code == "1FC9" and msg.verb == RP:
        #     pass  # only a heater_relay will have 3B00

        # elif msg.code == "3B00" and msg.verb == I_:
        #     pass  # only a heater_relay will I/3B00
        #     # for code in ("0008", "3EF1"):
        #     #     self._send_cmd(code, delay=1)

    @property
    def role(self) -> Optional[str]:
        """Return the role of the BDR91A (there are six possibilities)."""

        if self._domain_id in DOMAIN_TYPE_MAP:
            return DOMAIN_TYPE_MAP[self._domain_id]
        elif self._parent:
            return self._parent.heating_type  # TODO: only applies to zones

    @property
    def _role(self) -> Optional[str]:  # TODO: XXX
        """Return the role of the BDR91A (there are six possibilities)."""

        if self._is_tpi is not None:
            return self._is_tpi

        elif "1FC9" in self._msgs and self._msgs["1FC9"].verb == RP:
            if "3B00" in self._msgs["1FC9"].raw_payload:
                self._is_tpi = True

        elif "3B00" in self._msgs and self._msgs["3B00"].verb == I_:
            self._is_tpi = True

        if self._is_tpi:
            self._domain_id = "FC"  # TODO: check is None first
            self._ctl._set_htg_control(self)

        return self._is_tpi

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        if "0008" in self._msgs:
            return self._msgs["0008"].payload[self.RELAY_DEMAND]

    @property
    def tpi_params_wip(self) -> Optional[dict]:  # 1100
        return self._msg_payload(self._msgs.get("1100"))

    @property
    def params(self) -> dict:
        return {
            **super().params,
            self.TPI_PARAMS: self.tpi_params_wip,
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.RELAY_DEMAND: self.relay_demand,
        }


class TrvActuator(BatteryState, HeatDemand, Setpoint, Temperature, Device):  # TRV (04):
    """The TRV class, such as a HR92."""

    __dev_class__ = DEVICE_CLASS.TRV  # DEVICE_TYPES = ("00", "04")

    WINDOW_OPEN = ATTR_WINDOW_OPEN  # boolean
    # _STATE = HEAT_DEMAND

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.heat_demand}"

    @property
    def window_open(self) -> Optional[bool]:  # 12B0
        if "12B0" in self._msgs:
            return self._msgs["12B0"].payload[self.WINDOW_OPEN]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.WINDOW_OPEN: self.window_open,
        }


class FanSwitch(BatteryState, Device):  # SWI (39):
    """The FAN (switch) class, such as a 4-way switch.

    The cardinal codes are 22F1, 22F3.
    """

    __dev_class__ = DEVICE_CLASS.SWI  # DEVICE_TYPES = ("39",)

    BOOST_TIMER = "boost_timer"  # minutes, e.g. 10, 20, 30 minutes
    HEATER_MODE = "heater_mode"  # e.g. auto, off
    HEATER_MODES = {9: "off", 10: "auto"}  # TODO:

    FAN_MODE = "fan_mode"  # e.g. low. high
    FAN_MODES = {
        0: "standby",
        1: "auto",
        2: "low",
        3: "medium",
        4: "high",  # a.k.a. boost if timer on
    }
    FAN_RATE = "fan_rate"  # percentage, 0.0 - 1.0

    @property
    def fan_mode(self) -> Optional[str]:
        if "22F1" in self._msgs:
            return self._msgs["22F1"].payload[self.FAN_MODE]

    @property
    def boost_timer(self) -> Optional[int]:
        if "22F3" in self._msgs:
            return self._msgs["22F3"].payload[self.BOOST_TIMER]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.FAN_MODE: self.fan_mode,
            self.BOOST_TIMER: self.boost_timer,
        }


class FanDevice(Device):  # FAN (20/37):
    """The Ventilation class.

    The cardinal code are 31D9, 31DA.
    """

    __dev_class__ = DEVICE_CLASS.FAN  # DEVICE_TYPES = ("20", "37")

    @property
    def fan_rate(self) -> Optional[float]:
        msgs = [m for m in self._msgs.values() if m.code in ("31D9", "31DA")]
        return max(msgs).payload["exhaust_fan_speed"] if msgs else None

    @property
    def boost_timer(self) -> Optional[int]:
        if "31DA" in self._msgs:
            return self._msgs["31DA"].payload["remaining_time"]

    @property
    def relative_humidity(self) -> Optional[float]:
        if "31DA" in self._msgs:
            return self._msgs["31DA"].payload["indoor_humidity"]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "exhaust_fan_speed": self.fan_rate,
            **(
                {
                    k: v
                    for k, v in self._msgs["31D9"].payload.items()
                    if k != "exhaust_fan_speed"
                }
                if "31D9" in self._msgs
                else {}
            ),
            **(
                {
                    k: v
                    for k, v in self._msgs["31DA"].payload.items()
                    if k != "exhaust_fan_speed"
                }
                if "31DA" in self._msgs
                else {}
            ),
        }


class FanSensorHumidity(BatteryState, Device):  # HUM (32) Humidity sensor:
    """The Sensor class for a humidity sensor.

    The cardinal code is 12A0.
    """

    __dev_class__ = DEVICE_CLASS.HUM  # DEVICE_TYPES = ("32")

    REL_HUMIDITY = "relative_humidity"  # percentage
    TEMPERATURE = "temperature"  # celsius
    DEWPOINT_TEMP = "dewpoint_temp"  # celsius

    @property
    def relative_humidity(self) -> Optional[float]:
        if "12A0" in self._msgs:
            return self._msgs["12A0"].payload[self.REL_HUMIDITY]

    @property
    def temperature(self) -> Optional[float]:
        if "12A0" in self._msgs:
            return self._msgs["12A0"].payload[self.TEMPERATURE]

    @property
    def dewpoint_temp(self) -> Optional[float]:
        if "12A0" in self._msgs:
            return self._msgs["12A0"].payload[self.DEWPOINT_TEMP]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.REL_HUMIDITY: self.relative_humidity,
            self.TEMPERATURE: self.temperature,
            self.DEWPOINT_TEMP: self.dewpoint_temp,
        }


CLASS_ATTR = "__dev_class__"
DEVICE_BY_CLASS_ID = {
    getattr(c[1], CLASS_ATTR): c[1]
    for c in getmembers(
        modules[__name__],
        lambda m: isclass(m) and m.__module__ == __name__ and hasattr(m, CLASS_ATTR),
    )
}  # e.g. "CTL": Controller

DEVICE_BY_ID_TYPE = {
    k1: v2
    for k1, v1 in _DEV_TYPE_TO_CLASS.items()
    for k2, v2 in DEVICE_BY_CLASS_ID.items()
    if v1 == k2
}  # e.g. "01": Controller,


def create_device(gwy, dev_addr, dev_class=None, **kwargs) -> Device:
    """Create a device, and optionally perform discovery & start polling."""

    if dev_class is None:
        dev_class = _DEV_TYPE_TO_CLASS.get(dev_addr.type, DEVICE_CLASS.DEV)

    device = DEVICE_BY_CLASS_ID.get(dev_class, Device)(gwy, dev_addr, **kwargs)

    if not gwy.config.disable_discovery:
        schedule_task(device._discover, discover_flag=DISCOVER_SCHEMA)
        schedule_task(device._discover, discover_flag=DISCOVER_PARAMS, delay=14)
        schedule_task(device._discover, discover_flag=DISCOVER_STATUS, delay=15)

    return device
