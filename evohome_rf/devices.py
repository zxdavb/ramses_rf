#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser."""

import logging
from abc import ABCMeta, abstractmethod
from typing import Any, Dict, List, Optional

from .command import Command, Priority
from .const import (
    ATTR_HEAT_DEMAND,
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
)
from .exceptions import CorruptStateError
from .helpers import dev_id_to_hex
from .opentherm import VALUE
from .ramses import RAMSES_DEVICES

MSG_ID = "msg_id"

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Entity:
    """The Device/Zone base class."""

    def __init__(self, gwy) -> None:
        self._loop = gwy._loop

        self._gwy = gwy
        self.id = None

        self._msgs = {}
        self._msgz = {" I": {}, "RQ": {}, "RP": {}, " W": {}}

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
        self._msgz[msg.verb][msg.code] = msg

        if msg.verb == " W":
            # if msg.code in self._msgs and self._msgs[msg.code].verb != msg.verb:
            return
        if msg.verb == "RQ":  # and msg.payload:
            # if msg.code in self._msgs and self._msgs[msg.code].verb != msg.verb:
            return

        self._msgs[msg.code] = msg

    @property
    def _dump_msgs(self) -> List:
        return [msg for msg in self._msgs.values()]

    def _send_cmd(self, code, dest, payload, **kwargs) -> None:
        self._msgs.pop(code, None)  # remove the old one, so we can tell if RP'd rcvd

        self._gwy.send_cmd(
            Command(kwargs.pop("verb", "RQ"), dest, code, payload, **kwargs)
        )

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


class DeviceBase(Entity, metaclass=ABCMeta):
    """The Device base class."""

    def __init__(self, gwy, dev_addr, ctl=None, domain_id=None) -> None:
        _LOGGER.debug("Creating a Device: %s (%s)", dev_addr.id, self.__class__)
        super().__init__(gwy)

        self.id = dev_addr.id
        gwy.devices.append(self)
        gwy.device_by_id[self.id] = self

        self._ctl = None
        if ctl:
            self._set_ctl(ctl)
        self._domain_id = domain_id

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

        self._zone = None
        # self._domain = {}  # TODO

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id})"

    def __str__(self) -> str:
        return f"{self.id} ({DEVICE_TYPES.get(self.id[:2])})"

    def __lt__(self, other) -> bool:
        if not hasattr(other, "id"):
            return NotImplemented
        return self.id < other.id

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # sometimes, battery-powered devices do respond to an RQ (e.g. bind mode)
        # super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA and self.type not in DEVICE_HAS_BATTERY:
            # self._send_cmd("1FC9", retries=3)
            if self.type not in ("13",):
                self._send_cmd("10E0", retries=0)  # TODO: use device hints

        # if discover_flag & DISCOVER_PARAMS and self.type not in DEVICE_HAS_BATTERY:
        #     pass

        # if discover_flag & DISCOVER_STATUS and self.type not in DEVICE_HAS_BATTERY:
        #     self._send_cmd("0016", retries=3)

    def _send_cmd(self, code, **kwargs) -> None:
        dest = kwargs.pop("dest_addr", self.id)
        payload = kwargs.pop("payload", "00")
        super()._send_cmd(code, dest, payload, **kwargs)

    def _set_ctl(self, ctl) -> None:  # self._ctl
        """Set the device's parent controller, after validating it."""

        if self._ctl is None:
            _LOGGER.debug("Setting controller for %s to %s", self, ctl)

            # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5  # has been seen
            if not isinstance(ctl, Controller) and not ctl._is_controller:
                raise TypeError(f"Device {ctl} is not a controller")

            self._ctl = ctl
            self._ctl.devices.append(self)
            self._ctl.device_by_id[self.id] = self

        elif self._ctl is not ctl:
            raise CorruptStateError(
                f"{self} has changed controller: {self._ctl.id} to {ctl.id}"
            )

    def _handle_msg(self, msg) -> None:
        """Check that devices only handle messages they have sent."""
        assert msg.src is self, "Devices should only keep msgs they sent"
        super()._handle_msg(msg)

    @property
    @abstractmethod
    def schema(self) -> dict:
        """Return the fixed attributes of the device (e.g. TODO)."""
        return self._codes if DEV_MODE else {}

    @property
    @abstractmethod
    def params(self) -> dict:
        """Return the configuration of the device (e.g. TODO)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def status(self) -> dict:
        """Return the current state of the device (e.g. TODO)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def zone(self) -> Optional[Entity]:  # should be: Optional[Zone]
        """Return parent zone of the device, if known."""
        raise NotImplementedError

    # @abstractmethod
    # def _set_zone(self, zone: Entity) -> None:  # should be: zone: Zone
    #     """Set the parent zone of the device."""


class Actuator:  # 3EF0, 3EF1

    ACTUATOR_CYCLE = "actuator_cycle"
    ACTUATOR_ENABLED = "actuator_enabled"
    ACTUATOR_STATE = "actuator_state"

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "3EF0" and msg.verb == " I":  # NOT "RP", TODO: why????
            self._send_cmd("3EF1", priority=Priority.LOW, retries=1)

    @property
    def actuator_cycle(self) -> Optional[dict]:  # 3EF1
        return self._msg_payload(self._msgs.get("3EF1"))

    @property
    def actuator_state(self) -> Optional[dict]:  # 3EF0
        return self._msg_payload(self._msgs.get("3EF0"))

    @property
    def enabled(self) -> Optional[bool]:  # 3EF0, 3EF1
        """Return the actuator's current state."""
        msgs = [m for m in self._msgs.values() if m.code in ("3EF0", "3EF1")]
        return max(msgs).payload[self.ACTUATOR_ENABLED] if msgs else None

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.ACTUATOR_CYCLE: self.actuator_cycle,
            self.ACTUATOR_STATE: self.actuator_state,
        }


class BatteryState:  # 1060

    BATTERY_LOW = "battery_low"
    BATTERY_STATE = "battery_state"

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


class Setpoint:  # 2309

    SETPOINT = ATTR_SETPOINT

    @property
    def setpoint(self) -> Optional[float]:  # 2309
        if "2309" in self._msgs:
            return self._msgs["2309"].payload[self.SETPOINT]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.SETPOINT: self.setpoint,
        }


class Temperature:  # 30C9

    TEMPERATURE = ATTR_TEMP

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        if "30C9" in self._msgs:
            return self._msgs["30C9"].payload[self.TEMPERATURE]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            ATTR_TEMP: self.temperature,
        }


class DeviceInfo:  # 10E0

    DEVICE_INFO = "device_info"

    @property
    def device_info(self) -> Optional[dict]:  # 10E0
        return self._msg_payload(self._msgs.get("10E0"))

    @property
    def schema(self) -> dict:
        result = super().schema
        if "10E0" in self._msgs or "10E0" in RAMSES_DEVICES.get(self.type, []):
            result.update({self.DEVICE_INFO: self.device_info})
        return result


class Device(DeviceInfo, DeviceBase):
    """The Device base class - also used for unknown device types."""

    DEVICE_CLASS = "???"  # DEVICE_TYPES = ("??", )

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        # TODO: status updates always, but...
        # TODO: schema updates only if eavesdropping is enabled.
        # if self._ctl is not None and "parent_idx" in msg.payload:
        #     self._set_zone(self._ctl._evo._get_zone(msg.payload["parent_idx"]))

    def _set_parent(self, parent, domain=None) -> None:
        """Set the device's parent zone, after validating it."""

        # NOTE: these imports are here to prevent circular references
        from .systems import System
        from .zones import DhwZone, Zone

        if isinstance(parent, Zone):
            if domain and domain != parent.idx:
                raise TypeError(f"domain can't be: {domain} (must be {parent.idx})")

            self._set_ctl(parent._ctl)
            self._domain_id = parent.idx

        elif isinstance(parent, DhwZone):
            if domain and domain not in ("F9", "FA"):
                raise TypeError(f"domain can't be: {domain}")

            self._set_ctl(parent._ctl)
            self._domain_id = domain

        elif isinstance(parent, System):
            if domain not in ("F9", "FA", "FC", "HW"):
                raise TypeError(f"domain can't be: {domain}")

            self._set_ctl(parent._ctl)
            self._domain_id = domain

        else:
            raise TypeError(f"paren can't be: {parent}")

        if self._zone is not None:
            if self._zone is not parent:
                raise CorruptStateError(
                    f"{self} shouldn't change parent: {self._zone} to {parent}"
                )
            self._zone = parent

    @property
    def zone(self) -> Optional[Entity]:  # should be: Optional[Zone]
        """Return the device's parent zone, if known."""

        return self._zone

    def _set_zone(self, zone: Entity) -> None:  # self._zone
        """Set the device's parent zone, after validating it.

        There are three possible sources for the parent zone of a device:
        1. a 000C packet (from their controller) for actuators only
        2. a message.payload["zone_idx"]
        3. the sensor-matching algorithm for zone sensors only

        All three will set device.zone to this zone.

        Devices don't have parents, rather: Zones have children; a mis-configured
        system could have a device as a child of two domains.
        """

        if not isinstance(zone, Entity):  # should be: zone, Zone)
            raise TypeError(f"Not a zone: {zone}")

        if self._zone is not None:
            if self._zone is not zone:
                raise CorruptStateError(
                    f"Device {self} appears claimed by multiple parent zones: "
                    f"old={self._zone}, new={zone}"
                )
            return

        self._domain_id = zone.idx
        self._zone = zone
        if self._domain_id == "FA":
            # if isinstance(self, DhwSensor):
            #     self._sensor = self
            # else:
            #     self._dhw_valve = self
            pass

        elif self not in self._zone.devices:
            self._zone.devices.append(self)
            self._zone.device_by_id[self.id] = self
        _LOGGER.debug("Device %s: parent zone now set to %s", self.id, self._zone)

    @property
    def description(self) -> Optional[str]:
        return DEVICE_TABLE[self.type]["name"] if self.type in DEVICE_TABLE else None

    @property
    def has_battery(self) -> Optional[bool]:  # 1060
        """Return True if a device is battery powered (excludes battery-backup)."""

        if self._has_battery is not None:
            return self._has_battery

        if "1060" in self._msgs:
            self._has_battery = True

        return self._has_battery

    @property
    def _is_controller(self) -> Optional[bool]:  # 1F09
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
    def _is_present(self) -> bool:
        return any([m.src.id == self.id for m in self._msgs.values()])

    @property
    def schema(self):
        return {
            **super().schema,
        }

    @property
    def params(self):
        return {}

    @property
    def status(self):
        return {}


class Controller(Device):  # CTL: 01
    """The Controller base class."""

    DEVICE_CLASS = "CTL"  # DEVICE_TYPES = ("01", )

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._ctl = self  # or args[1]
        self._domain_id = "FF"
        self._evo = None

        self.devices = list()  # [self]
        self.device_by_id = dict()  # {self.id: self}

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA and self.type not in DEVICE_HAS_BATTERY:
            self._send_cmd("1FC9", retries=3)  # rf_bind

        if discover_flag & DISCOVER_STATUS and self.type not in DEVICE_HAS_BATTERY:
            self._send_cmd("0016", retries=3)  # rf_check


class Programmer(Controller):  # CTL: 23
    """The Controller base class."""

    DEVICE_CLASS = "PRG"  # DEVICE_TYPES = ("23", )


class UfhController(Device):  # UFC: 02
    """The UFC class, the HCE80 that controls the UFH zones."""

    DEVICE_CLASS = "UFC"  # DEVICE_TYPES = ("02", )

    HEAT_DEMAND = ATTR_HEAT_DEMAND

    # 12:27:24.398 067  I --- 02:000921 --:------ 01:191718 3150 002 0360
    # 12:27:24.546 068  I --- 02:000921 --:------ 01:191718 3150 002 065A
    # 12:27:24.693 067  I --- 02:000921 --:------ 01:191718 3150 002 045C
    # 12:27:24.824 059  I --- 01:191718 --:------ 01:191718 3150 002 FC5C
    # 12:27:24.857 067  I --- 02:000921 --:------ 02:000921 3150 006 0060-015A-025C

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.klass = "UFC"

        self._circuits = {}
        self._setpoints = None

        self.devices = list()  # [self]
        self.device_by_id = dict()  # {self.id: self}

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            [  # 000C: used to find evo zone for each configured channel
                self._send_cmd("000C", payload=f"{idx:02X}{dev_type}")
                for dev_type in ("09",)  # CODE_000C_DEVICE_TYPE, also ("00", "04")
                # for dev_type in CODE_000C_DEVICE_TYPE
                for idx in range(8)  # for each possible UFH channel
            ]

        if discover_flag & DISCOVER_PARAMS:
            pass

        if discover_flag & DISCOVER_STATUS:
            pass

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

        # [  # 0005: shows which channels are active - ?no use? (see above)
        #     self._send_cmd("0005", payload=f"00{zone_type}")
        #     # for zone_type in ("09",)  # CODE_0005_ZONE_TYPE, also ("00", "04", "0F")
        #     for zone_type in CODE_0005_ZONE_TYPE
        # ]

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "000C":
            assert "ufh_idx" in msg.payload, "wsdfh"
            if msg.payload["zone_id"] is not None:
                self._circuits[msg.payload["ufh_idx"]] = msg

        elif msg.code == "22C9":
            self._setpoints = msg

        # "0008|FA/FC", "22C9|array", "22D0|none", "3150|ZZ/array(/FC?)"

        # if msg.code in ("22C9",) and not isinstance(msg.payload, list):
        #     pass
        # else:
        #     assert False, "Unknown packet code"

    @property
    def circuits(self) -> Optional[Dict]:  # 000C
        def fix(k):
            return "zone_idx" if k == "zone_id" else k

        return [
            {fix(k): v for k, v in m.payload.items() if k in ("ufh_idx", "zone_id")}
            for m in self._circuits.values()
        ]

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        if "3150" in self._msgs:
            return self._msgs["3150"].payload[self.HEAT_DEMAND]

    @property
    def relay_demand(self) -> Optional[Dict]:  # 0008
        try:
            return self._msgs["0008"].payload["relay_demand"]
        except KeyError:
            return

    @property
    def setpoints(self) -> Optional[Dict]:  # 22C9
        return [
            {k: v for k, v in d.items() if k in ("ufh_idx", "temp_high", "temp_low")}
            for d in (self._setpoints.payload if self._setpoints else [])
        ]

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
            "setpoints": self.setpoints,
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            ATTR_HEAT_DEMAND: self.heat_demand,
            "relay_demand": self.relay_demand,
        }


class DhwSensor(BatteryState, Device):  # DHW: 07
    """The DHW class, such as a CS92."""

    DEVICE_CLASS = "DWH"  # DEVICE_TYPES = ("07", )

    DHW_PARAMS = "dhw_params"
    TEMPERATURE = ATTR_TEMP

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


class OtbGateway(Actuator, Device):  # OTB: 10
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    DEVICE_CLASS = "OTB"  # DEVICE_TYPES = ("10", )

    BOILER_SETPOINT = "boiler_setpoint"
    MODULATION_LEVEL = "modulation_level"
    OPENTHERM_STATUS = "opentherm_status"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._domain_id = "FC"
        self._opentherm_msg = {}

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.rel_modulation_level}"

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            for msg_id in range(0x7C, 0x80):  # From OT v2.2: version numbers
                self._gwy.send_cmd(Command.get_opentherm_data(self.id, msg_id))

        if discover_flag & DISCOVER_PARAMS:
            pass

        if discover_flag & DISCOVER_STATUS:  # TODO: these need to be periodic
            # From OT v2.2, these are mandatory: 00, 01, 03, 0E, 11, 19...
            msg_ids = {0x00, 0x01, 0x03, 0x0E, 0x11, 0x19}

            # and, From evohome: 05, 11, 12, 13, 19, 1A...
            msg_ids |= {0x05, 0x11, 0x12, 0x13, 0x19, 0x1A}
            # 05 - Fault flags & OEM fault code
            # 11 - Relative modulation level
            # 12 - Central heating water pressure
            # 13 - DHW flow rate (litres/minute)
            # 19 - Boiler water temperature
            # 1A - DHW temperature

            # and, others...
            msg_ids |= {0x1B, 0x1C, 0x73}
            # 1B - Outside temperature
            # 1C - Return water temperature
            # 73 - OEM diagnostic code

            for msg_id in msg_ids:
                self._gwy.send_cmd(
                    Command.get_opentherm_data(self.id, msg_id, retries=0)
                )

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "3220" and msg.verb == "RP":  # TODO: what about I/W (or RQ)
            self._opentherm_msg[msg.payload[MSG_ID]] = msg  # TODO: need to expire

    @property
    def boiler_water_temp(self) -> Optional[float]:  # 3220/0x19
        try:
            return self._opentherm_msg["0x19"].payload[VALUE]
        except KeyError:
            return

    @property
    def ch_water_pressure(self) -> Optional[float]:  # 3220/0x12
        try:
            return self._opentherm_msg["0x12"].payload[VALUE]
        except KeyError:
            return

    @property
    def dhw_flow_rate(self) -> Optional[float]:  # 3220/0x13
        try:
            return self._opentherm_msg["0x13"].payload[VALUE]
        except KeyError:
            return

    @property
    def dhw_temp(self) -> Optional[float]:  # 3220/0x1A
        try:
            return self._opentherm_msg["0x1A"].payload[VALUE]
        except KeyError:
            return

    @property
    def rel_modulation_level(self) -> Optional[float]:  # 3220/0x11
        try:
            return self._opentherm_msg["0x11"].payload[VALUE]
        except KeyError:
            return

    @property
    def return_cv_temp(self) -> Optional[float]:  # 3220/0x1C
        try:
            return self._opentherm_msg["0x1C"].payload[VALUE]
        except KeyError:
            return

    @property
    def boiler_setpoint(self) -> Optional[float]:  # 22D9
        if "22D9" in self._msgs:
            return self._msgs["22D9"].payload[self.BOILER_SETPOINT]

    @property
    def modulation_level(self) -> Optional[float]:  # 3EF0/3EF1
        msgs = [m for m in self._msgs.values() if m.code in ("3EF0", "3EF1")]
        return max(msgs).payload[self.MODULATION_LEVEL] if msgs else None

    @property
    def opentherm_status(self) -> dict:
        return {
            "boiler_temp": self.boiler_water_temp,
            "ch_pressure": self.ch_water_pressure,
            "dhw_flow_rate": self.dhw_flow_rate,
            "dhw_temp": self.dhw_temp,
            "rel_modulation_level": self.rel_modulation_level,
            "return_cv_temp": self.return_cv_temp,
        }
        # return {
        #     slugify(self._opentherm_msg[msg_id].payload["msg_name"]): (
        #         self._opentherm_msg[msg_id].payload[VALUE]
        #     )
        #     for msg_id in ("0x11", "0x12", "0x13", "0x19", "0x1A", "0x1C")
        #     if msg_id in self._opentherm_msg
        # }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.BOILER_SETPOINT: self.boiler_setpoint,
            self.MODULATION_LEVEL: self.modulation_level,  # TODO: keep? (is duplicate)
            self.OPENTHERM_STATUS: self.opentherm_status,
        }


class Thermostat(BatteryState, Setpoint, Temperature, Device):  # THM:
    """The THM/STA class, such as a TR87RF."""

    DEVICE_CLASS = "THM"  # DEVICE_TYPES = ("03", "12", "22", "34")

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.temperature}"


class BdrSwitch(Actuator, Device):  # BDR: 13
    """The BDR class, such as a BDR91.

    BDR91s can be used in six disctinct modes, including:
    - x2 boiler controller (FC/TPI): either traditional, or newer heat pump-aware
    - x1 electric heat zones (0x/ELE)
    - x1 zone valve zones (0x/VAL)
    - x2 DHW thingys (F9/DHW, FA/DHW)
    """

    DEVICE_CLASS = "BDR"  # DEVICE_TYPES = ("13", )

    RELAY_DEMAND = "relay_demand"
    TPI_PARAMS = "tpy_params"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._is_tpi = None

        # if kwargs.get("domain_id") == "FC":  # TODO: F9/FA/FC, zone_idx
        #     self._ctl._set_htg_control(self)

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.relay_demand}"

    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        """The BDRs have one of six roles:
         - heater relay *or* a heat pump relay (alternative to an OTB)
         - DHW hot water valve *or* DHW heating valve
         - Zones: Electric relay *or* Zone valve relay

        They all seem to respond thus (TODO heat pump/zone valve relay):
         - all BDR91As will (erractically) RP to these RQs
             0016, 1FC9 & 0008, 1100, 3EF1
         - all BDR91As will *not* RP to these RQs
             0009, 10E0, 3B00, 3EF0
         - a BDR91A will *periodically* send an I/3B00/00CB if it is the heater relay
        """

        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            pass

        if discover_flag & DISCOVER_PARAMS:
            self._send_cmd("1100")

        if discover_flag & DISCOVER_STATUS:
            for code in ("0008", "3EF1"):
                self._send_cmd(code)

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        if msg.code == "3B00" and msg.verb == " I":
            pass  # only a heater_relay will I/3B00
            # for code in ("0008", "3EF1"):
            #     self._send_cmd(code, delay=1)

        elif msg.code == "3EF0" and msg.verb == " I":  # NOT "RP", TODO: why????
            self._send_cmd("0008", priority=Priority.LOW, retries=1)

    @property
    def role(self) -> Optional[str]:
        """Return the role of the BDR91A (there are six possibilities)."""

        if self._domain_id in DOMAIN_TYPE_MAP:
            return DOMAIN_TYPE_MAP[self._domain_id]
        elif self._zone:
            return self._zone.heating_type

    @property
    def _role(self) -> Optional[str]:  # TODO: XXX
        """Return the role of the BDR91A (there are six possibilities)."""

        if self._is_tpi is not None:
            return self._is_tpi

        elif "1FC9" in self._msgs and self._msgs["1FC9"].verb == "RP":
            if "3B00" in self._msgs["1FC9"].raw_payload:
                self._is_tpi = True

        elif "3B00" in self._msgs and self._msgs["3B00"].verb == " I":
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


class TrvActuator(BatteryState, Setpoint, Temperature, Device):  # TRV: 00, 04
    """The TRV class, such as a HR92."""

    DEVICE_CLASS = "TRV"  # DEVICE_TYPES = ("00", "04")

    HEAT_DEMAND = ATTR_HEAT_DEMAND
    WINDOW_OPEN = ATTR_WINDOW_OPEN

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.heat_demand}"

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        if "3150" in self._msgs:
            return self._msgs["3150"].payload[self.HEAT_DEMAND]

    @property
    def window_open(self) -> Optional[bool]:  # 12B0
        if "12B0" in self._msgs:
            return self._msgs["12B0"].payload[self.WINDOW_OPEN]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.HEAT_DEMAND: self.heat_demand,
            self.WINDOW_OPEN: self.window_open,
        }


class FanSwitch(BatteryState, Device):  # SWI: 39
    """The FAN (switch) class, such as a 4-way switch."""

    DEVICE_CLASS = "SWI"  # DEVICE_TYPES = ("39",)

    BOOST_TIMER = "boost_timer"  # e.g. 10, 20, 30 minutes
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
    FAN_RATE = "fan_rate"  # 0.0 - 1.0

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


class FanDevice(Device):  # FAN: 20, 37
    """The Ventilation class."""

    DEVICE_CLASS = "FAN"  # DEVICE_TYPES = ("20", "37")

    BOOST_TIMER = "boost_timer"
    FAN_RATE = "fan_rate"
    RELATIVE_HUMIDITY = "relative_humidity"

    @property
    def fan_rate(self) -> Optional[float]:
        msgs = [m for m in self._msgs.values() if m.code in ("31D9", "31DA")]
        return max(msgs).payload[self.FAN_RATE] if msgs else None

    @property
    def boost_timer(self) -> Optional[int]:
        if "31DA" in self._msgs:
            return self._msgs["31DA"].payload[self.BOOST_TIMER]

    @property
    def relative_humidity(self) -> Optional[float]:
        if "31DA" in self._msgs:
            return self._msgs["31DA"].payload[self.RELATIVE_HUMIDITY]

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.BOOST_TIMER: self.boost_timer,
            self.FAN_RATE: self.fan_rate,
            self.RELATIVE_HUMIDITY: self.relative_humidity,
        }


DEVICES_CLASSES = (
    BdrSwitch,
    FanDevice,
    FanSwitch,
    Controller,
    DhwSensor,
    OtbGateway,
    Programmer,
    Thermostat,
    TrvActuator,
    UfhController,
)

DEVICE_KLASS_TO_CLASS = {k.DEVICE_CLASS: k for k in DEVICES_CLASSES}

DEVICE_TYPE_TO_KLASS = {
    "00": "TRV",
    "01": "CTL",
    "02": "UFC",
    "03": "THM",
    "04": "TRV",
    "07": "DHW",
    "10": "OTB",
    "12": "THM",
    "13": "BDR",
    "18": "HGI",
    "20": "FAN",
    "22": "THM",
    "23": "PRG",
    "30": "GWY",
    "34": "THM",
    "37": "FAN",
    "39": "SWI",
}
DEVICE_CLASSES = {
    k1: v2
    for k1, v1 in DEVICE_TYPE_TO_KLASS.items()
    for k2, v2 in DEVICE_KLASS_TO_CLASS.items()
    if v1 == k2
}  # e.g. "01": Controller,
