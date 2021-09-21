#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import logging
from inspect import getmembers, isclass
from sys import modules
from typing import Dict, Optional

from .const import (
    ATTR_ALIAS,
    ATTR_CLASS,
    ATTR_FAKED,
    DISCOVER_ALL,
    DISCOVER_PARAMS,
    DISCOVER_SCHEMA,
    DISCOVER_STATUS,
)
from .entities import Entity, discovery_filter
from .protocol import Command, Priority  # TODO: constants to const.py
from .protocol.address import (  # TODO: all required?
    NON_DEV_ADDR,
    dev_id_to_hex,
    id_to_address,
)
from .protocol.command import FUNC, TIMEOUT
from .protocol.const import (
    _000C_DEVICE,
    ATTR_HEAT_DEMAND,
    ATTR_RELAY_DEMAND,
    ATTR_SETPOINT,
    ATTR_TEMP,
    ATTR_WINDOW_OPEN,
    DEVICE_CLASS,
    DEVICE_HAS_BATTERY,
    DEVICE_TABLE,
    DEVICE_TYPES,
    DOMAIN_TYPE_MAP,
    NUL_DEVICE_ID,
)
from .protocol.exceptions import CorruptStateError
from .protocol.opentherm import MSG_ID, MSG_NAME, MSG_TYPE, OPENTHERM_MESSAGES, VALUE
from .protocol.ramses import CODE_ONLY_FROM_CTL, RAMSES_DEVICES

from .protocol import I_, RP, RQ, W_, __dev_mode__  # noqa: F401, isort: skip
from .protocol import (  # noqa: F401, isort: skip
    _0001,
    _0002,
    _0004,
    _0005,
    _0006,
    _0008,
    _0009,
    _000A,
    _000C,
    _000E,
    _0016,
    _0100,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _1030,
    _1060,
    _1090,
    _10A0,
    _10E0,
    _1100,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _1F09,
    _1F41,
    _1FC9,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2D49,
    _2E04,
    _30C9,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3220,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)

DEFAULT_BDR_ID = "13:000730"
DEFAULT_EXT_ID = "17:000730"
DEFAULT_THM_ID = "03:000730"

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

_DEV_TYPE_TO_CLASS = {  # TODO: removw
    None: DEVICE_CLASS.GEN,  # a generic, promotable device
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
    "18": DEVICE_CLASS.HGI,
    "20": DEVICE_CLASS.FAN,
    "22": DEVICE_CLASS.STA,  # 22: can act like a DEVICE_CLASS.PRG
    "23": DEVICE_CLASS.PRG,
    "29": DEVICE_CLASS.FAN,
    "30": DEVICE_CLASS.GEN,  # either: RFG/FAN
    "32": DEVICE_CLASS.HUM,  # also: SWI
    "34": DEVICE_CLASS.STA,
    "37": DEVICE_CLASS.FAN,
    "39": DEVICE_CLASS.SWI,
    "42": DEVICE_CLASS.SWI,
    "49": DEVICE_CLASS.SWI,
    "59": DEVICE_CLASS.SWI,
}  # these are the default device classes for common types


class DeviceBase(Entity):
    """The Device base class (good for a generic device)."""

    _class = None
    _types = tuple()

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

        self.devices = []  # [self]
        self.device_by_id = {}  # {self.id: self}
        self._iz_controller = None

        if self.type in DEVICE_TABLE:
            self._has_battery = DEVICE_TABLE[self.addr.type].get("has_battery")
            self._is_actuator = DEVICE_TABLE[self.addr.type].get("is_actuator")
            self._is_sensor = DEVICE_TABLE[self.addr.type].get("is_sensor")
        else:
            self._has_battery = None
            self._is_actuator = None
            self._is_sensor = None

        self._alias = None
        self._faked = None
        if self.id in gwy._include:
            self._alias = gwy._include[self.id].get(ATTR_ALIAS)

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id})"

    def __str__(self) -> str:
        return f"{self.id} ({DEVICE_TYPES.get(self.id[:2])})"

    def __lt__(self, other) -> bool:
        if not hasattr(other, "id"):
            return NotImplemented
        return self.id < other.id

    @discovery_filter
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # sometimes, battery-powered devices would respond to an RQ (e.g. bind mode)

        if discover_flag & DISCOVER_SCHEMA:
            self._send_cmd(_1FC9, retries=3)  # rf_bind

        if discover_flag & DISCOVER_STATUS:
            self._send_cmd(_0016, retries=3)  # rf_check

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
        assert msg.src is self, f"msg inappropriately routed to {self}"
        super()._handle_msg(msg)

        if msg.verb != I_:  # or: if self._iz_controller is not None or...
            return

        if not self._iz_controller and msg.code in CODE_ONLY_FROM_CTL:
            if self._iz_controller is None:
                _LOGGER.info(f"{msg._pkt} # IS_CONTROLLER (00): is TRUE")
                self._iz_controller = msg
                self._make_tcs_controller(msg)
            elif self._iz_controller is False:  # TODO: raise CorruptStateError
                _LOGGER.error(f"{msg._pkt} # IS_CONTROLLER (01): was FALSE, now True")

    @property
    def has_battery(self) -> Optional[bool]:  # 1060
        """Return True if a device is battery powered (excludes battery-backup)."""

        return self.type in DEVICE_HAS_BATTERY or _1060 in self._msgz

    @property
    def _is_controller(self) -> Optional[bool]:

        if self._iz_controller is not None:
            return bool(self._iz_controller)  # True, False, or msg

        if self._ctl is not None:  # TODO: messy
            return self._ctl is self

        return False

    @property
    def _is_present(self) -> bool:
        """Try to exclude ghost devices (as caused by corrupt packet addresses)."""
        return any(
            m.src == self for m in self._msgs.values() if not m._expired
        )  # TODO: needs addressing

    def _make_tcs_controller(self, msg=None):  # CH/DHW
        """Create a TCS, and attach it to this controller."""
        self._iz_controller = msg or True

    @property
    def schema(self) -> dict:
        """Return the fixed attributes of the device (e.g. TODO)."""

        return {
            **(self._codes if DEV_MODE else {}),
            ATTR_ALIAS: self._alias,
            # ATTR_FAKED: self._faked,
            ATTR_CLASS: self._class,
        }

    @property
    def params(self):
        return {}

    @property
    def status(self):
        return {}


class DeviceInfo:  # 10E0

    RF_BIND = "rf_bind"
    DEVICE_INFO = "device_info"

    @discovery_filter
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        if discover_flag & DISCOVER_SCHEMA:
            try:
                if RP in RAMSES_DEVICES[self.type][_10E0]:
                    self._send_cmd(_10E0, retries=3)
            except KeyError:
                pass

    @property
    def device_info(self) -> Optional[dict]:  # 10E0
        return self._msg_value(_10E0)

    @property
    def schema(self) -> dict:
        result = super().schema
        # result.update({self.RF_BIND: self._msg_value(_1FC9)})
        if _10E0 in self._msgs or _10E0 in RAMSES_DEVICES.get(self.type, []):
            result.update({self.DEVICE_INFO: self.device_info})
        return result


class Device(DeviceInfo, DeviceBase):
    """The Device base class - also used for unknown device types."""

    _class = DEVICE_CLASS.GEN
    DEVICE_TYPES = tuple()

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if type(self) is Device and self.type == "30":  # self.__class__ is Device
            # TODO: the RFG codes need checking
            if msg.code in (_31D9, _31DA, _31E0) and msg.verb in (I_, RP):
                self.__class__ = FanDevice
            elif msg.code in (_0006, _0418, _3220) and msg.verb == RQ:
                self.__class__ = RFGateway
            elif msg.code in (_313F,) and msg.verb == W_:
                self.__class__ = RFGateway

        if not msg._gwy.config.enable_eavesdrop:
            return

        if self._ctl is not None and "zone_idx" in msg.payload:
            # TODO: is buggy - remove? how?
            self._set_parent(self._ctl._evo._get_zone(msg.payload["zone_idx"]))

    def _set_parent(self, parent, domain=None) -> None:  # self._parent
        """Set the device's parent zone, after validating it.

        There are three possible sources for the parent zone of a device:
        1. a 000C packet (from their controller) for actuators only
        2. a message.payload["zone_idx"]
        3. the sensor-matching algorithm for zone sensors only

        Devices don't have parents, rather: Zones have children; a mis-configured
        system could have a device as a child of two domains.
        """

        # NOTE: these imports are here to prevent circular references
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


class Actuator:  # 3EF0, 3EF1

    ACTUATOR_CYCLE = "actuator_cycle"
    ACTUATOR_ENABLED = "actuator_enabled"  # boolean
    ACTUATOR_STATE = "actuator_state"
    MODULATION_LEVEL = "modulation_level"  # percentage (0.0-1.0)

    @discovery_filter
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS and not self._faked:
            # NOTE: No need to send periodic RQ/3EF1s to an OTB, use RQ/3220/11s
            self._send_cmd(_3EF1)  # NOTE: No RPs to RQ/3EF0

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == _3EF0 and msg.verb == I_ and not self._faked:
            self._send_cmd(_3EF1, priority=Priority.LOW, retries=1)

    @property
    def actuator_cycle(self) -> Optional[dict]:  # 3EF1
        return self._msg_value(_3EF1)

    @property
    def actuator_state(self) -> Optional[dict]:  # 3EF0
        return self._msg_value(_3EF0)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.ACTUATOR_CYCLE: self.actuator_cycle,
            self.ACTUATOR_STATE: self.actuator_state,
        }


class BatteryState:  # 1060

    BATTERY_LOW = "battery_low"  # boolean
    BATTERY_STATE = "battery_state"  # percentage (0.0-1.0)

    @property
    def battery_low(self) -> Optional[bool]:  # 1060
        if self._faked:
            return False
        return self._msg_value(_1060, key=self.BATTERY_LOW)

    @property
    def battery_state(self) -> Optional[dict]:  # 1060
        if self._faked:
            return
        return self._msg_value(_1060)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.BATTERY_STATE: self.battery_state,
        }


class HeatDemand:  # 3150

    HEAT_DEMAND = ATTR_HEAT_DEMAND  # percentage valve open (0.0-1.0)

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._msg_value(_3150, key=self.HEAT_DEMAND)

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
        return self._msg_value(_2309, key=self.SETPOINT)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.SETPOINT: self.setpoint,
        }


class Fakeable:
    def __init__(self, gwy, *args, **kwargs) -> None:
        super().__init__(gwy, *args, **kwargs)

        if self.id in gwy._include and gwy._include[self.id].get(ATTR_FAKED):
            self._make_fake()

    def _bind(self):
        if not self._faked:
            raise RuntimeError(f"Can't bind {self} (Faking is not enabled)")

    def _make_fake(self, bind=None) -> Device:
        if not self._faked:
            self._faked = True
            self._gwy._include[self.id] = {ATTR_FAKED: True}
            _LOGGER.warning(f"Faking now enabled for {self}")  # TODO: be info/debug
        if bind:
            self._bind()
        return self

    def _bind_waiting(self, code, idx="00", callback=None):
        """Wait for (listen for) a bind handshake."""

        # Bind waiting: BDR set to listen, CTL initiates handshake
        # 19:30:44.749 051  I --- 01:054173 --:------ 01:054173 1FC9 024 FC-0008-04D39D FC-3150-04D39D FB-3150-04D39D FC-1FC9-04D39D
        # 19:30:45.342 053  W --- 13:049798 01:054173 --:------ 1FC9 012 00-3EF0-34C286 00-3B00-34C286
        # 19:30:45.504 049  I --- 01:054173 13:049798 --:------ 1FC9 006 00-FFFF-04D39D

        _LOGGER.warning(f"Binding {self}: waiting for {code}")  # TODO: info/debug
        # SUPPORTED_CODES = (_0008,)

        def bind_confirm(msg, *args) -> None:
            """Process the 3rd/final packet of the handshake."""
            if not msg or msg.code != code:
                return
            self._1fc9_state == "confirm"

            # self._gwy._get_device(self, ctl_id=msg.payload[0][2])
            # self._ctl._evo._get_zone(msg.payload[0][0])._set_sensor(self)
            if callback:
                callback(msg)

        def bind_respond(msg, *args) -> None:
            """Process the 1st, and send the 2nd, packet of the handshake."""
            if not msg:
                return
            self._1fc9_state == "respond"

            # W should be retransmitted until receiving an I; idx is domain_id/zone_idx
            cmd = Command.put_bind(
                W_,
                code,
                self.id,
                idx=idx,
                dst_id=msg.src.id,
                callback={FUNC: bind_confirm, TIMEOUT: 3},
            )
            self._gwy.send_cmd(cmd)

        # assert code in SUPPORTED_CODES, f"Binding: {code} is not supported"
        self._1fc9_state = "waiting"

        self._gwy.msg_transport._add_callback(
            f"{_1FC9}|{I_}|{NUL_DEVICE_ID}", {FUNC: bind_respond, TIMEOUT: 300}
        )

    def _bind_request(self, code, callback=None):
        """Initate a bind handshake: send the 1st packet of the handshake."""

        # Bind request: CTL set to listen, STA initiates handshake (note 3C09/2309)
        # 22:13:52.527 070  I --- 34:021943 --:------ 34:021943 1FC9 024 00-3C09-8855B7 00-30C9-8855B7 00-0008-8855B7 00-1FC9-8855B7
        # 22:13:52.540 052  W --- 01:145038 34:021943 --:------ 1FC9 006 00-2309-06368E
        # 22:13:52.572 071  I --- 34:021943 01:145038 --:------ 1FC9 006 00-2309-8855B7

        # Bind request: CTL set to listen, DHW sensor initiates handshake
        # 19:45:16.733 045  I --- 07:045960 --:------ 07:045960 1FC9 012 00-1260-1CB388 00-1FC9-1CB388
        # 19:45:16.896 045  W --- 01:054173 07:045960 --:------ 1FC9 006 00-10A0-04D39D
        # 19:45:16.919 045  I --- 07:045960 01:054173 --:------ 1FC9 006 00-1260-1CB388

        _LOGGER.warning(f"Binding {self}: requesting {code}")  # TODO: info/debug
        SUPPORTED_CODES = (_0002, _1260, _1290, _30C9)

        def bind_confirm(msg, *args) -> None:
            """Process the 2nd, and send the 3rd/final, packet of the handshake."""
            if not msg or msg.dst is not self:
                return

            self._1fc9_state == "confirm"

            cmd = Command.put_bind(I_, code, self.id, dst_id=msg.src.id)
            self._gwy.send_cmd(cmd)

            if callback:
                callback(msg)

        assert code in SUPPORTED_CODES, f"Binding: {code} is not supported"
        self._1fc9_state = "request"

        cmd = Command.put_bind(
            I_, code, self.id, callback={FUNC: bind_confirm, TIMEOUT: 3}
        )
        self._gwy.send_cmd(cmd)

    @property
    def schema(self) -> dict:
        return {
            **super().schema,
            ATTR_FAKED: self._faked,
        }


class Weather(Fakeable):  # 0002 (fakeable)

    TEMPERATURE = ATTR_TEMP  # degrees Celsius

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        if kwargs.get(ATTR_FAKED) is True or _0002 in kwargs.get(ATTR_FAKED, []):
            self._make_fake()

    def _bind(self):
        # A contrived (but proven viable) packet log...
        #  I --- 17:145039 --:------ 17:145039 1FC9 012 00-0002-46368F 00-1FC9-46368F
        #  W --- 01:054173 17:145039 --:------ 1FC9 006 03-2309-04D39D  # real CTL
        #  I --- 17:145039 01:054173 --:------ 1FC9 006 00-0002-46368F

        super()._bind()
        self._bind_request(_0002)

    @property
    def temperature(self) -> Optional[float]:  # 0002
        return self._msg_value(_0002, key=self.TEMPERATURE)

    @temperature.setter
    def temperature(self, value) -> None:  # 0002
        if not self._faked:
            raise RuntimeError(f"Can't set value for {self} (Faking is not enabled)")

        cmd = Command.put_outdoor_temp(self.id, value)
        # cmd = Command.put_zone_temp(
        #     self._gwy.hgi.id if self == self._gwy.hgi._faked_thm else self.id, value
        # )
        self._gwy.send_cmd(cmd)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class Temperature(Fakeable):  # 30C9 (fakeable)

    TEMPERATURE = ATTR_TEMP  # degrees Celsius

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        if kwargs.get(ATTR_FAKED) is True or _30C9 in kwargs.get(ATTR_FAKED, []):
            self._make_fake()

    def _bind(self):
        # A contrived (but proven viable) packet log... offer should include 2309?
        #  I --- 34:145039 --:------ 34:145039 1FC9 012 00-30C9-8A368F 00-1FC9-8A368F
        #  W --- 01:054173 34:145039 --:------ 1FC9 006 03-2309-04D39D  # real CTL
        #  I --- 34:145039 01:054173 --:------ 1FC9 006 00-30C9-8A368F

        def callback(msg):
            msg.src._evo.zone_by_idx[msg.payload[0][0]]._set_sensor(self)
            self._1fc9_state == "bound"

        super()._bind()
        self._bind_request(_30C9, callback=callback)

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        return self._msg_value(_30C9, key=self.TEMPERATURE)

    @temperature.setter
    def temperature(self, value) -> None:  # 30C9
        if not self._faked:
            raise RuntimeError(f"Can't set value for {self} (Faking is not enabled)")

        self._gwy.send_cmd(Command.put_sensor_temp(self.id, value))
        # lf._gwy.send_cmd(Command.get_zone_temp(self._ctl.id, self.zone.idx))

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class RelayDemand(Fakeable):  # 0008 (fakeable)

    RELAY_DEMAND = ATTR_RELAY_DEMAND  # percentage (0.0-1.0)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        if kwargs.get(ATTR_FAKED) is True or _3EF0 in kwargs.get(ATTR_FAKED, []):
            self._make_fake()

    @discovery_filter
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_STATUS and not self._faked:
            self._send_cmd(_0008)  # NOTE: No RPs to RQ/0009

    def _handle_msg(self, msg) -> None:
        if msg.src.id == self.id:
            super()._handle_msg(msg)
            return

        if (
            not self._faked
            or self._domain_id is None
            or self._domain_id
            not in (v for k, v in msg.payload.items() if k in ("domain_id", "zone_idx"))
        ):
            return

        # TODO: handle relay_failsafe, reply to RQs
        if msg.code == _0008 and msg.verb == RQ:
            # 076  I --- 01:054173 --:------ 01:054173 0008 002 037C
            mod_level = msg.payload[self.RELAY_DEMAND]
            if mod_level is not None:
                mod_level = 1.0 if mod_level > 0 else 0

            cmd = Command.put_actuator_state(self.id, mod_level)
            qos = {"priority": Priority.HIGH, "retries": 3}
            [self._gwy.send_cmd(cmd, **qos) for _ in range(1)]

        elif msg.code == _0009:  # can only be I, from a controller
            pass

        elif msg.code == _3B00 and msg.verb == I_:
            pass

        elif msg.code == _3EF0 and msg.verb == I_:  # NOT RP, TODO: why????
            self._send_cmd(_0008, priority=Priority.LOW, retries=1)

        elif msg.code == _3EF1 and msg.verb == RQ:  # NOTE: WIP
            mod_level = 1.0

            cmd = Command.put_actuator_cycle(self.id, msg.src.id, mod_level, 600, 600)
            qos = {"priority": Priority.HIGH, "retries": 3}
            [self._gwy.send_cmd(cmd, **qos) for _ in range(1)]

        else:
            raise

    def _bind(self):
        # A contrived (but proven viable) packet log...
        #  I --- 01:054173 --:------ 01:054173 1FC9 018 03-0008-04D39D FC-3B00-04D39D 03-1FC9-04D39D
        #  W --- 13:123456 01:054173 --:------ 1FC9 006 00-3EF0-35E240
        #  I --- 01:054173 13:123456 --:------ 1FC9 006 00-FFFF-04D39D

        super()._bind()
        self._bind_waiting(_3EF0)

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return self._msg_value(_0008, key=self.RELAY_DEMAND)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.RELAY_DEMAND: self.relay_demand,
        }


class RFGateway(DeviceInfo, DeviceBase):  # RFG (30:)
    """The RFG100 base class."""

    _class = DEVICE_CLASS.RFG
    _types = ("30",)


class HGInterface(DeviceBase):  # HGI (18:), was GWY
    """The HGI80 base class."""

    _class = DEVICE_CLASS.HGI
    _types = ("18",)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._ctl = None
        self._domain_id = "FF"
        self._evo = None

        self._faked_bdr = None
        self._faked_ext = None
        self._faked_thm = None

        # self. _proc_schema(**kwargs)

    def _set_ctl(self, ctl) -> None:  # self._ctl
        """Set the device's parent controller, after validating it."""
        _LOGGER.debug("%s: can't (really) have a controller %s", self)

    def _proc_schema(self, schema) -> None:
        if schema.get("fake_bdr"):
            self._faked_bdr = self._gwy._get_device(self.id, class_="BDR", faked=True)

        if schema.get("fake_ext"):
            self._fake_ext = self._gwy._get_device(self.id, class_="BDR", faked=True)

        if schema.get("fake_thm"):
            self._fake_thm = self._gwy._get_device(self.id, class_="BDR", faked=True)

    @discovery_filter
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # of no value for a HGI80-compatible device
        return

    def _handle_msg(self, msg) -> None:
        def fake_addrs(msg, faked_dev):
            msg.src == faked_dev if msg.src is self else self
            msg.dst == faked_dev if msg.dst is self else self
            return msg

        super()._handle_msg(msg)

        # the following is for aliased devices (not fully-faked devices)
        if msg.code in (_3EF0,) and self._faked_bdr:
            self._faked_bdr._handle_msg(fake_addrs(msg, self._faked_bdr))

        if msg.code in (_0002,) and self._faked_ext:
            self._faked_ext._handle_msg(fake_addrs(msg, self._faked_ext))

        if msg.code in (_30C9,) and self._faked_thm:
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

        dev = self._get_device(device_id)
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


class Controller(Device):  # CTL (01):
    """The Controller base class."""

    _class = DEVICE_CLASS.CTL
    _types = ("01",)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._ctl = self  # or args[1]
        self._domain_id = "FF"
        self._evo = None

        self._iz_controller = True

    def _handle_msg(self, msg) -> bool:
        super()._handle_msg(msg)

        # Route any messages to their heating systems
        if self._evo:
            self._evo._handle_msg(msg)

    # @discovery_filter
    # def _discover(self, discover_flag=DISCOVER_ALL) -> None:
    #     super()._discover(discover_flag=discover_flag)

    #     if discover_flag & DISCOVER_SCHEMA:
    #         pass  # self._send_cmd(_0000, retries=3)


class Programmer(Controller):  # PRG (23):
    """The Controller base class."""

    _class = DEVICE_CLASS.PRG
    _types = ("23",)


class UfhController(Device):  # UFC (02):
    """The UFC class, the HCE80 that controls the UFH zones."""

    _class = DEVICE_CLASS.UFC
    _types = ("02",)

    HEAT_DEMAND = ATTR_HEAT_DEMAND

    # 12:27:24.398 067  I --- 02:000921 --:------ 01:191718 3150 002 0360
    # 12:27:24.546 068  I --- 02:000921 --:------ 01:191718 3150 002 065A
    # 12:27:24.693 067  I --- 02:000921 --:------ 01:191718 3150 002 045C
    # 12:27:24.824 059  I --- 01:191718 --:------ 01:191718 3150 002 FC5C
    # 12:27:24.857 067  I --- 02:000921 --:------ 02:000921 3150 006 0060-015A-025C

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._circuits = {}
        self._setpoints = None
        self._heat_demand = None

        self._iz_controller = True

    @discovery_filter
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        # TODO: UFC may RP to an RQ/0001

        if discover_flag & DISCOVER_SCHEMA:
            [  # 0005: shows which channels are active - ?no use? (see above)
                self._send_cmd(_0005, payload=f"00{zone_type}")
                for zone_type in ("09",)  # _0005_ZONE_TYPE, also ("00", "04", "0F")
                # for zone_type in _0005_ZONE_TYPE
            ]

            [  # 000C: used to find evo zone for each configured channel
                self._send_cmd(_000C, payload=f"{idx:02X}{_000C_DEVICE.UFH}")
                for idx in range(8)  # for each possible UFH channel/circuit
            ]

        # if discover_flag & DISCOVER_STATUS:
        #     [  # 22C9: no answer
        #         self._send_cmd(_22C9, payload=f"{payload}")
        #         for payload in ("00", "0000", "01", "0100")
        #     ]

        #     [  # 3150: no answer
        #         self._send_cmd(_3150, payload=f"{zone_idx:02X}")
        #         for zone_idx in range(8)
        #     ]

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == _000C:
            assert "ufh_idx" in msg.payload, "wsdfh"
            if msg.payload["zone_id"] is not None:
                self._circuits[msg.payload["ufh_idx"]] = msg

        elif msg.code == _22C9:
            if isinstance(msg.payload, list):
                self._setpoints = msg
            # else:
            #     pass  # update the self._circuits[]

        elif msg.code == _3150:
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
            return self._msgs[_0008].payload[ATTR_RELAY_DEMAND]
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

    _class = DEVICE_CLASS.DHW
    _types = ("07",)

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
        return self._msg_value(_10A0)

    @property
    def temperature(self) -> Optional[float]:  # 1260
        return self._msg_value(_1260, key=self.TEMPERATURE)

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


class ExtSensor(Weather, Device):  # EXT: 17
    """The EXT class (external sensor), such as a HB85/HB95."""

    _class = DEVICE_CLASS.EXT
    _types = ("17",)

    # LUMINOSITY = "luminosity"  # lux
    # WINDSPEED = "windspeed"  # km/h

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.temperature}"


class OtbGateway(Actuator, HeatDemand, Device):  # OTB (10): 22D9, 3220
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    _class = DEVICE_CLASS.OTB
    _types = ("10",)

    BOILER_SETPOINT = "boiler_setpoint"
    OPENTHERM_STATUS = "opentherm_status"
    # _STATE = super().MODULATION_LEVEL

    SCHEMA_MSG_IDS = (
        0x03,  # ..3: "Slave configuration",
        0x06,  # ..6: "Remote boiler parameter flags",                      # 0x38, 0x39
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

        self._msgz[_3220] = {RP: {}}
        self._opentherm_msg = self._msgz[_3220][RP]
        self._supported_msg = {}

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.modulation_level}"  # 3EF0

    @discovery_filter
    def _discover(self, discover_flag=DISCOVER_ALL) -> None:
        # see: https://www.opentherm.eu/request-details/?post_ids=2944

        super()._discover(discover_flag=discover_flag)

        if discover_flag & DISCOVER_SCHEMA:
            [
                self._gwy.send_cmd(Command.get_opentherm_data(self.id, m))
                for m in self.SCHEMA_MSG_IDS  # From OT v2.2: version numbers
                if self._supported_msg.get(m) is not False
                and (not self._opentherm_msg.get(m) or self._opentherm_msg[m]._expired)
            ]

        if discover_flag & DISCOVER_PARAMS:
            [
                self._gwy.send_cmd(Command.get_opentherm_data(self.id, m))
                for m in self.PARAMS_MSG_IDS
                if self._supported_msg.get(m) is not False
                and (not self._opentherm_msg.get(m) or self._opentherm_msg[m]._expired)
            ]

        if discover_flag & DISCOVER_STATUS:
            self._gwy.send_cmd(Command(RQ, _22D9, "00", self.id))
            [
                self._gwy.send_cmd(Command.get_opentherm_data(self.id, m, retries=0))
                for m in self.STATUS_MSG_IDS
                if self._supported_msg.get(m) is not False
                and (not self._opentherm_msg.get(m) or self._opentherm_msg[m]._expired)
            ]

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == _1FD4:  # every 30s
            if msg.payload["ticker"] % 6 in (0, 2):  # twice every 3 mins
                self._discover(discover_flag=DISCOVER_STATUS)
            elif msg.payload["ticker"] % 60 in (1, 3):  # effectively once every 30 mins
                self._discover(discover_flag=DISCOVER_PARAMS)

        elif msg.code == _3220:  # all are RP
            self._supported_msg[msg.payload[MSG_ID]] = msg.payload[MSG_TYPE] not in (
                "Unknown-DataId",
                "-reserved-",
            )

    def _ot_msg_value(self, msg_id) -> Optional[float]:
        try:
            return self._opentherm_msg[f"{msg_id:02X}"].payload[VALUE]
        except KeyError:
            return

    @property
    def modulation_level(self) -> Optional[float]:  # 3EF0/3EF1
        # TODO: for OTB, deprecate in favour of RP/3220/11
        return self._msg_value((_3EF0, _3EF1), key=self.MODULATION_LEVEL)

    @property
    def boiler_water_temperature(self) -> Optional[float]:  # 3220/19
        return self._ot_msg_value(0x19)

    @property
    def ch_water_pressure(self) -> Optional[float]:  # 3220/12
        return self._ot_msg_value(0x12)

    @property
    def dhw_flow_rate(self) -> Optional[float]:  # 3220/13
        return self._ot_msg_value(0x13)

    @property
    def dhw_temperature(self) -> Optional[float]:  # 3220/1A
        return self._ot_msg_value(0x1A)

    @property
    def relative_modulation_level(self) -> Optional[float]:  # 3220/11
        return self._ot_msg_value(0x11)

    @property
    def return_water_temperature(self) -> Optional[float]:  # 3220/1C
        return self._ot_msg_value(0x1C)

    @property
    def boiler_setpoint(self) -> Optional[float]:  # 22D9
        return self._msg_value(_22D9, key=self.BOILER_SETPOINT)

    @staticmethod
    def _msg_name(msg) -> str:
        return (
            msg.payload[MSG_NAME]
            if isinstance(msg.payload[MSG_NAME], str)
            else f"{msg.payload[MSG_ID]:02X}"
        )

    @property
    def opentherm_schema(self) -> dict:
        result = {
            self._msg_name(v): v.payload
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
            self._msg_name(v): v.payload
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
            self._msg_name(v): {
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
            #  grep '47AB ' | grep -vE '(13|1A|1B)47AB'
            "known_msg_ids": {
                f"{k:02X}": OPENTHERM_MESSAGES[k].get("var", f"{k:02X}")
                if k in OPENTHERM_MESSAGES
                else f"{k:02X}"
                for k, v in sorted(self._supported_msg.items())
                if v
            },
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
            self.MODULATION_LEVEL: self.modulation_level,
        }


class Thermostat(BatteryState, Setpoint, Temperature, Device):  # THM (..):
    """The THM/STA class, such as a TR87RF."""

    _class = DEVICE_CLASS.STA
    _types = ("03", "12", "22", "34")

    # _STATE = super().TEMPERATURE

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.temperature}"

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.verb != I_:  # or: if self._iz_controller is not None or...
            return

        # if self._iz_controller is not None:  # TODO: put back in when confident
        #     return

        # NOTE: this has only been tested on a 12:, does it work for a 34: too?
        if all(
            (
                msg._addrs[0] is self.addr,
                msg._addrs[1] is NON_DEV_ADDR,
                msg._addrs[2] is self.addr,
            )
        ):
            if self._iz_controller is None:
                # _LOGGER.info(f"{msg._pkt} # IS_CONTROLLER (10): is FALSE")
                self._iz_controller = False
            elif self._iz_controller:  # TODO: raise CorruptStateError
                _LOGGER.error(f"{msg._pkt} # IS_CONTROLLER (11): was TRUE, now False")

            if msg.code in CODE_ONLY_FROM_CTL:  # TODO: raise CorruptPktError
                _LOGGER.error(f"{msg._pkt} # IS_CONTROLLER (12); is CORRUPT PKT")

        elif all(
            (
                msg._addrs[0] is NON_DEV_ADDR,
                msg._addrs[1] is NON_DEV_ADDR,
                msg._addrs[2] is self.addr,
            )
        ):
            if self._iz_controller is None:
                # _LOGGER.info(f"{msg._pkt} # IS_CONTROLLER (20): is TRUE")
                self._iz_controller = msg
                self._make_tcs_controller(msg)
            elif self._iz_controller is False:  # TODO: raise CorruptStateError
                _LOGGER.error(f"{msg._pkt} # IS_CONTROLLER (21): was FALSE, now True")


class BdrSwitch(Actuator, RelayDemand, Device):  # BDR (13):
    """The BDR class, such as a BDR91.

    BDR91s can be used in six disctinct modes, including:
    - x2 boiler controller (FC/TPI): either traditional, or newer heat pump-aware
    - x1 electric heat zones (0x/ELE)
    - x1 zone valve zones (0x/VAL)
    - x2 DHW thingys (F9/DHW, FA/DHW)
    """

    _class = DEVICE_CLASS.BDR
    _types = ("13",)

    ACTIVE = "active"
    TPI_PARAMS = "tpi_params"
    # _STATE = super().ENABLED, or relay_demand

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # if kwargs.get("domain_id") == "FC":  # TODO: F9/FA/FC, zone_idx
        #     self._ctl._set_htg_control(self)

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.relay_demand}"

    @discovery_filter
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

        if discover_flag & DISCOVER_PARAMS and not self._faked:
            self._send_cmd(_1100)

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        # if msg.code == _1FC9 and msg.verb == RP:
        #     pass  # only a heater_relay will have 3B00

        # elif msg.code == _3B00 and msg.verb == I_:
        #     pass  # only a heater_relay will I/3B00
        #     # for code in (_0008, _3EF1):
        #     #     self._send_cmd(code, delay=1)

    @property
    def active(self) -> Optional[bool]:  # 3EF0, 3EF1
        """Return the actuator's current state."""
        result = self._msg_value((_3EF0, _3EF1), key=self.MODULATION_LEVEL)
        return None if result is None else bool(result)

    @property
    def role(self) -> Optional[str]:
        """Return the role of the BDR91A (there are six possibilities)."""

        if self._domain_id in DOMAIN_TYPE_MAP:
            return DOMAIN_TYPE_MAP[self._domain_id]
        elif self._parent:
            return self._parent.heating_type  # TODO: only applies to zones

        # if _3B00 in self._msgs and self._msgs[_3B00].verb == I_:
        #     self._is_tpi = True
        # if _1FC9 in self._msgs and self._msgs[_1FC9].verb == RP:
        #     if _3B00 in self._msgs[_1FC9].raw_payload:
        #         self._is_tpi = True

    @property
    def tpi_params(self) -> Optional[dict]:  # 1100
        return self._msg_value(_1100)

    @property
    def schema(self) -> dict:
        return {
            **super().schema,
            "role": self.role,
        }

    @property
    def params(self) -> dict:
        return {
            **super().params,
            self.TPI_PARAMS: self.tpi_params,
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.ACTIVE: self.active,
        }


class TrvActuator(BatteryState, HeatDemand, Setpoint, Temperature, Device):  # TRV (04):
    """The TRV class, such as a HR92."""

    _class = DEVICE_CLASS.TRV
    _types = ("00", "04")

    WINDOW_OPEN = ATTR_WINDOW_OPEN  # boolean
    # _STATE = HEAT_DEMAND

    def __repr__(self) -> str:
        return f"{self.id} ({self._domain_id}): {self.heat_demand}"

    @property
    def window_open(self) -> Optional[bool]:  # 12B0
        return self._msg_value(_12B0, key=self.WINDOW_OPEN)

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

    _class = DEVICE_CLASS.SWI
    _types = ("39",)

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
        return self._msg_value(_22F1, key=self.FAN_MODE)

    @property
    def boost_timer(self) -> Optional[int]:
        return self._msg_value(_22F3, key=self.BOOST_TIMER)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.FAN_MODE: self.fan_mode,
            self.BOOST_TIMER: self.boost_timer,
        }


class FanDevice(Device):  # FAN (20/37): I/31D[9A]
    """The Ventilation class.

    The cardinal code are 31D9, 31DA.
    """

    _class = DEVICE_CLASS.FAN
    _types = ("20", "37")

    @property
    def fan_rate(self) -> Optional[float]:
        return self._msg_value((_31D9, _31DA), key="exhaust_fan_speed")

    @property
    def boost_timer(self) -> Optional[int]:
        return self._msg_value(_31DA, key="remaining_time")

    @property
    def relative_humidity(self) -> Optional[float]:
        return self._msg_value(_31DA, key="indoor_humidity")

    @property
    def status(self) -> dict:
        return {
            **super().status,
            "exhaust_fan_speed": self.fan_rate,
            **(
                {
                    k: v
                    for k, v in self._msgs[_31D9].payload.items()
                    if k != "exhaust_fan_speed"
                }
                if _31D9 in self._msgs
                else {}
            ),
            **(
                {
                    k: v
                    for k, v in self._msgs[_31DA].payload.items()
                    if k != "exhaust_fan_speed"
                }
                if _31DA in self._msgs
                else {}
            ),
        }


class FanSensorHumidity(BatteryState, Device):  # HUM (32) Humidity sensor:
    """The Sensor class for a humidity sensor.

    The cardinal code is 12A0.
    """

    _class = DEVICE_CLASS.HUM
    _types = ("32",)

    REL_HUMIDITY = "relative_humidity"  # percentage (0.0-1.0)
    TEMPERATURE = "temperature"  # celsius
    DEWPOINT_TEMP = "dewpoint_temp"  # celsius

    @property
    def relative_humidity(self) -> Optional[float]:
        return self._msg_value(_12A0, key=self.REL_HUMIDITY)

    @property
    def temperature(self) -> Optional[float]:
        return self._msg_value(_12A0, key=self.TEMPERATURE)

    @property
    def dewpoint_temp(self) -> Optional[float]:
        return self._msg_value(_12A0, key=self.DEWPOINT_TEMP)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.REL_HUMIDITY: self.relative_humidity,
            self.TEMPERATURE: self.temperature,
            self.DEWPOINT_TEMP: self.dewpoint_temp,
        }


_CLASS = "_class"
DEVICE_BY_CLASS = {
    getattr(c[1], _CLASS): c[1]
    for c in getmembers(
        modules[__name__],
        lambda m: isclass(m) and m.__module__ == __name__ and hasattr(m, _CLASS),
    )
}  # e.g. "CTL": Controller

DEVICE_BY_ID_TYPE = {
    k1: v2
    for k1, v1 in _DEV_TYPE_TO_CLASS.items()
    for k2, v2 in DEVICE_BY_CLASS.items()
    if v1 == k2
}  # e.g. "01": Controller,


def create_device(gwy, dev_id, dev_class=None, **kwargs) -> Device:
    """Create a device, and optionally perform discovery & start polling."""

    dev_addr = id_to_address(dev_id)

    if dev_class is None:
        if dev_addr.type != "30":  # could be RFG or VNT
            dev_class = _DEV_TYPE_TO_CLASS.get(dev_addr.type, DEVICE_CLASS.GEN)
        else:
            dev_class = DEVICE_CLASS.GEN  # generic

    device = DEVICE_BY_CLASS.get(dev_class, Device)(gwy, dev_addr, **kwargs)

    gwy._add_task(
        device._discover, discover_flag=DISCOVER_SCHEMA, delay=0, period=86400
    )

    if dev_class == DEVICE_CLASS.OTB:
        return device

    gwy._add_task(
        device._discover, discover_flag=DISCOVER_PARAMS, delay=0, period=21600
    )

    gwy._add_task(device._discover, discover_flag=DISCOVER_STATUS, delay=0, period=900)

    return device
