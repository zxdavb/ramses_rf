#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Base for all devices.
"""

import logging
from random import randint
from types import SimpleNamespace
from typing import Optional

from ..const import DEV_KLASS, NUL_DEVICE_ID
from ..protocol import Command, CorruptStateError
from ..protocol.command import FUNC, TIMEOUT
from ..protocol.ramses import (
    CODES_BY_DEV_KLASS,
    CODES_ONLY_FROM_CTL,
    CODES_SCHEMA,
    NAME,
)
from .const import SZ_ALIAS, SZ_CLASS, SZ_DEVICE_ID, SZ_FAKED, Discover, __dev_mode__
from .entity_base import Entity, class_by_attr, discover_decorator

# from .hvac import _CLASS_BY_KLASS as _HVAC_CLASS_BY_KLASS
# from .hvac import _best_hvac_klass

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
)

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
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
    _0150,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _0B04,
    _1030,
    _1060,
    _1081,
    _1090,
    _1098,
    _10A0,
    _10B0,
    _10E0,
    _10E1,
    _1100,
    _11F0,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _12F0,
    _1300,
    _1F09,
    _1F41,
    _1FC9,
    _1FCA,
    _1FD0,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2389,
    _2400,
    _2401,
    _2410,
    _2420,
    _2D49,
    _2E04,
    _2E10,
    _30C9,
    _3110,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3200,
    _3210,
    _3220,
    _3221,
    _3223,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)

DEFAULT_BDR_ID = "13:000730"
DEFAULT_EXT_ID = "17:000730"
DEFAULT_THM_ID = "03:000730"

BindState = SimpleNamespace(
    UNKNOWN=None,
    UNBOUND="unb",  # unbound
    LISTENING="l",  # waiting for offer
    OFFERING="of",  # waiting for accept:              -> sent offer
    ACCEPTING="a",  # waiting for confirm: rcvd offer  -> sent accept
    # NFIRMED="c",  # bound:               rcvd accept -> sent confirm
    BOUND="bound",  # bound:               rcvd confirm
)

#       DHW/THM, TRV -> CTL     (temp, valve_position), or:
#                CTL -> BDR/OTB (heat_demand)

#            REQUEST -> WAITING
#            unbound -- unbound
#            unbound -- listening
#           offering -> listening
#           offering <- accepting
# (confirming) bound -> accepting
#              bound -- bound


DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class DeviceBase(Entity):
    """The Device base class (good for a generic device)."""

    _DEV_KLASS = None
    _DEV_TYPES = ()  # TODO: needed?

    _STATE_ATTR = None

    def __init__(self, gwy, dev_addr, ctl=None, domain_id=None, **kwargs) -> None:
        _LOGGER.debug("Creating a Device: %s (%s)", dev_addr.id, self.__class__)
        super().__init__(gwy)

        self.id: str = dev_addr.id
        if self.id in gwy.device_by_id:
            raise LookupError(f"Duplicate device: {self.id}")

        gwy.device_by_id[self.id] = self
        gwy.devices.append(self)

        self._ctl = self._set_ctl(ctl) if ctl else None

        self._domain_id = domain_id
        self._parent = None

        self.addr = dev_addr
        self.type = dev_addr.type  # DEX  # TODO: remove this attr

        self.devices = []  # [self]
        self.device_by_id = {}  # {self.id: self}
        self._iz_controller = None

        self._alias = None
        self._faked = None
        if self.id in gwy._include:
            self._alias = gwy._include[self.id].get(SZ_ALIAS)

        if msg := kwargs.get("msg"):
            self._loop.call_soon_threadsafe(self._handle_msg, msg)

    def __repr__(self) -> str:
        if self._STATE_ATTR:
            return f"{self.id} ({self._domain_id}): {getattr(self, self._STATE_ATTR)}"
        return f"{self.id} ({self._domain_id})"

    def __str__(self) -> str:
        return self.id if self._klass is DEV_KLASS.DEV else f"{self.id} ({self._klass})"

    def __lt__(self, other) -> bool:
        if not hasattr(other, "id"):
            return NotImplemented
        return self.id < other.id

    def _start_discovery(self) -> None:

        delay = randint(10, 20)

        self._gwy.add_task(  # 10E0/1FC9, 3220 pkts
            self._discover, discover_flag=Discover.SCHEMA, delay=0, period=3600 * 24
        )
        self._gwy.add_task(
            self._discover, discover_flag=Discover.PARAMS, delay=delay, period=3600 * 6
        )
        self._gwy.add_task(
            self._discover, discover_flag=Discover.STATUS, delay=delay + 1, period=60
        )

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        # sometimes, battery-powered devices will respond to an RQ (e.g. bind mode)

        if discover_flag & Discover.SCHEMA:
            self._make_cmd(_1FC9, retries=3)  # rf_bind

        if discover_flag & Discover.STATUS:
            self._make_cmd(_0016, retries=3)  # rf_check

    def _make_cmd(self, code, payload="00", **kwargs) -> None:  # skipcq: PYL-W0221
        super()._make_cmd(code, self.id, payload=payload, **kwargs)

    def _send_cmd(self, cmd, **kwargs) -> None:
        if getattr(self, "has_battery", None) and cmd.dst.id == self.id:
            _LOGGER.info(f"{cmd} < Sending inadvisable for {self} (has a battery)")

        super()._send_cmd(cmd, **kwargs)

    def _set_ctl(self, ctl):  # self._ctl
        """Set the device's parent controller, after validating it."""

        if self._ctl is ctl:
            return self._ctl
        if self._is_controller:
            return  # TODO

        self._ctl = ctl
        ctl.device_by_id[self.id] = self
        ctl.devices.append(self)

        _LOGGER.debug("%s: controller now set to %s", self, self._ctl)
        return self._ctl

    def _handle_msg(self, msg) -> None:
        assert msg.src is self, f"msg inappropriately routed to {self}"
        super()._handle_msg(msg)

        if msg.verb != I_ or self._iz_controller is not None:
            return

        if not self._iz_controller and msg.code in CODES_ONLY_FROM_CTL:
            if self._iz_controller is None:
                _LOGGER.info(f"{msg!r} # IS_CONTROLLER (00): is TRUE")
                self._make_tcs_controller(msg)
            elif self._iz_controller is False:  # TODO: raise CorruptStateError
                _LOGGER.error(f"{msg!r} # IS_CONTROLLER (01): was FALSE, now True")

    # @property
    # def controller(self):  # -> Optional[Controller]:
    #     """Return the entity's controller, if known."""

    #     return self._ctl  # TODO: if the controller is not known, try to find it?

    @property
    def has_battery(self) -> Optional[bool]:  # 1060
        """Return True if a device is battery powered (excludes battery-backup)."""

        return isinstance(self, BatteryState) or _1060 in self._msgz

    @property
    def _is_controller(self) -> Optional[bool]:

        if self._iz_controller is not None:
            return bool(self._iz_controller)  # True, False, or msg

        if self._ctl is not None:  # TODO: messy
            return self._ctl is self

        return False

    # @property
    # def _is_parent(self) -> bool:
    #     """Return True if other devices can bind to this device."""
    #     return self._klass in (DEV_KLASS.CTL, DEV_KLASS.PRG, DEV_KLASS.UFC)

    @property
    def _is_present(self) -> bool:
        """Try to exclude ghost devices (as caused by corrupt packet addresses)."""
        return any(
            m.src == self for m in self._msgs.values() if not m._expired
        )  # TODO: needs addressing

    @property
    def _klass(self) -> str:
        return self._DEV_KLASS

    def _make_tcs_controller(self, msg=None, **kwargs):  # CH/DHW
        """Create a TCS, and attach it to this controller."""
        from ..systems import create_system  # HACK: needs sorting

        self._iz_controller = msg or True
        if self.type in ("01", "12", "22", "23", "34") and self._evo is None:  # DEX
            self._evo = create_system(self._gwy, self, **kwargs)

    @property
    def traits(self) -> dict:
        """Return the traits of the (known) device."""

        return {
            **(self._codes if DEV_MODE else {}),
            SZ_ALIAS: self._alias,
            # SZ_FAKED: self._faked,
            SZ_CLASS: self._klass,
            "supported_msgs": {
                k: (CODES_SCHEMA[k][NAME] if k in CODES_SCHEMA else None)
                for k in sorted(self._msgs)
            },
        }

    @property
    def schema(self):
        """Return the fixed attributes of the device."""
        return {}

    @property
    def params(self):
        """Return the configurable attributes of the device."""
        return {}

    @property
    def status(self):
        """Return the state attributes of the device."""
        return {}


class Device(DeviceBase):  # 10E0
    """The Device base class - also used for unknown device types."""

    RF_BIND = "rf_bind"
    DEVICE_INFO = "device_info"

    _DEV_KLASS = DEV_KLASS.DEV
    _DEV_TYPES = ()

    def _discover(self, discover_flag=Discover.ALL) -> None:
        if discover_flag & Discover.SCHEMA:
            if not self._msgs.get(_10E0) and (
                self._klass not in CODES_BY_DEV_KLASS
                or RP in CODES_BY_DEV_KLASS[self._klass].get(_10E0, {})
            ):
                self._make_cmd(_10E0, retries=3)

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if self._klass == "DEV":
            from .hvac import _CLASS_BY_KLASS, CODES_HVAC_ONLY, _best_hvac_klass

            if (klass := _best_hvac_klass(self.id, msg)) in _CLASS_BY_KLASS:
                self.__class__ = _CLASS_BY_KLASS[klass]
            elif msg.code in CODES_HVAC_ONLY:
                self.__class__ == HvacDevice

            # TODO: split
            # elif self.type == "30":  # self.__class__ is Device, DEX
            #     # TODO: the RFG codes need checking
            #     if msg.code in (_0006, _0418, _3220) and msg.verb == RQ:
            #         self.__class__ = RfgGateway
            #     elif msg.code in (_313F,) and msg.verb == W_:
            #         self.__class__ = RfgGateway

            if self._klass != "DEV":
                _LOGGER.warning(f"Promoted the device class of: {self}")

        if not self._gwy.config.enable_eavesdrop:
            return

        if (
            self._ctl is not None
            and "zone_idx" in msg.payload
            and msg.src.type != "01"  # TODO: DEX, should be: if controller
            # and msg.dst.type != "18"
        ):
            # TODO: is buggy - remove? how?
            self._set_parent(self._ctl._evo._get_zone(msg.payload["zone_idx"]))

    def _set_parent(self, parent, domain=None):
        """Set the device's parent zone, after validating it.

        There are three possible sources for the parent zone of a device:
        1. a 000C packet (from their controller) for actuators only
        2. a message.payload["zone_idx"]
        3. the sensor-matching algorithm for zone sensors only

        Devices don't have parents, rather: Zones have children; a mis-configured
        system could have a device as a child of two domains.
        """

        # NOTE: these imports are here to prevent circular references
        from ..systems import System
        from ..zones import DhwZone, Zone

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

        if hasattr(self._parent, "devices") and self not in self._parent.devices:
            parent.devices.append(self)
            parent.device_by_id[self.id] = self

        if DEV_MODE:
            _LOGGER.debug("Device %s: parent now set to %s", self, self._parent)
        return self._parent

    @property
    def device_info(self) -> Optional[dict]:  # 10E0
        return self._msg_value(_10E0)

    @property
    def traits(self) -> dict:
        result = super().traits
        result.update({f"_{self.RF_BIND}": self._msg_value(_1FC9)})
        if _10E0 in self._msgs or _10E0 in CODES_BY_DEV_KLASS.get(self._klass, []):
            result.update({f"_{self.DEVICE_INFO}": self.device_info})
        return result

    @property
    def zone(self) -> Optional[Entity]:  # should be: Optional[Zone]
        """Return the device's parent zone, if known."""

        return self._parent


class Fakeable(DeviceBase):
    def __init__(self, gwy, *args, **kwargs) -> None:
        super().__init__(gwy, *args, **kwargs)

        self._1fc9_state = {"state": BindState.UNKNOWN}

        if self.id in gwy._include and gwy._include[self.id].get(SZ_FAKED):
            self._make_fake()

        if kwargs.get(SZ_FAKED):
            self._make_fake()

    def _bind(self):
        if not self._faked:
            raise RuntimeError(f"Can't bind {self} (Faking is not enabled)")

        self._1fc9_state["state"] = BindState.UNBOUND

    def _make_fake(self, bind=None) -> Device:
        if not self._faked:
            self._faked = True
            self._gwy._include[self.id] = {SZ_FAKED: True}
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

        # Bind waiting: OTB set to listen, CTL initiates handshake
        # 00:25:02.779 045  I --- 01:145038 --:------ 01:145038 1FC9 024 FC-0008-06368E FC-3150-06368E FB-3150-06368E  FC-1FC9-06368E  # opentherm bridge
        # 00:25:02.792 045  W --- 10:048122 01:145038 --:------ 1FC9 006 00-3EF0-28BBFA
        # 00:25:02.944 045  I --- 01:145038 10:048122 --:------ 1FC9 006 00-FFFF-06368E

        _LOGGER.warning(f"Binding {self}: waiting for {code} for 300 secs")  # info
        # SUPPORTED_CODES = (_0008,)

        def proc_confirm(msg, *args) -> None:
            """Process the 3rd/final packet of the handshake."""
            if not msg or msg.code != code:
                return

            self._1fc9_state["state"] = BindState.BOUND
            if callback:
                callback(msg)

        def proc_offer(msg, *args) -> None:
            """Process the 1st, and send the 2nd, packet of the handshake."""
            if not msg:
                return
            # assert code in SUPPORTED_CODES, f"Binding {self}: {code} is not supported"
            self._1fc9_state["msg"] = msg  # the offer

            self._1fc9_state["state"] = BindState.ACCEPTING
            cmd = Command.put_bind(
                W_,
                code,
                self.id,
                idx=idx,  # zone_idx or domain_id
                dst_id=msg.src.id,
                callback={FUNC: proc_confirm, TIMEOUT: 3},  # re-Tx W until Rx an I
            )
            self._send_cmd(cmd)

        self._1fc9_state["code"] = code
        self._1fc9_state["state"] = BindState.LISTENING
        self._gwy.msg_transport._add_callback(
            f"{_1FC9}|{I_}|{NUL_DEVICE_ID}", {FUNC: proc_offer, TIMEOUT: 300}
        )

    def _bind_request(self, code, callback=None):
        """Initiate a bind handshake: send the 1st packet of the handshake."""

        # Bind request: CTL set to listen, STA initiates handshake (note 3C09/2309)
        # 22:13:52.527 070  I --- 34:021943 --:------ 34:021943 1FC9 024 00-2309-8855B7 00-30C9-8855B7 00-0008-8855B7 00-1FC9-8855B7
        # 22:13:52.540 052  W --- 01:145038 34:021943 --:------ 1FC9 006 00-2309-06368E
        # 22:13:52.572 071  I --- 34:021943 01:145038 --:------ 1FC9 006 00-2309-8855B7

        # Bind request: CTL set to listen, DHW sensor initiates handshake
        # 19:45:16.733 045  I --- 07:045960 --:------ 07:045960 1FC9 012 00-1260-1CB388 00-1FC9-1CB388
        # 19:45:16.896 045  W --- 01:054173 07:045960 --:------ 1FC9 006 00-10A0-04D39D
        # 19:45:16.919 045  I --- 07:045960 01:054173 --:------ 1FC9 006 00-1260-1CB388

        _LOGGER.warning(f"Binding {self}: requesting {code}")  # TODO: info
        SUPPORTED_CODES = (_0002, _1260, _1290, _30C9)

        def proc_accept(msg, *args) -> None:
            """Process the 2nd, and send the 3rd/final, packet of the handshake."""
            if not msg or msg.dst is not self:
                return

            self._1fc9_state["msg"] = msg  # the accept

            self._1fc9_state["state"] = BindState.CONFIRMING
            cmd = Command.put_bind(I_, code, self.id, dst_id=msg.src.id)
            self._send_cmd(cmd)

            self._1fc9_state["state"] = BindState.BOUND
            if callback:
                callback(msg)

        assert code in SUPPORTED_CODES, f"Binding {self}: {code} is not supported"

        self._1fc9_state["code"] = code
        self._1fc9_state["state"] = BindState.OFFERING
        cmd = Command.put_bind(
            I_, code, self.id, callback={FUNC: proc_accept, TIMEOUT: 3}
        )
        self._send_cmd(cmd)

    @property
    def traits(self) -> dict:
        return {
            **super().traits,
            SZ_FAKED: self._faked,
        }


class BatteryState(DeviceBase):  # 1060

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


class HgiGateway(DeviceBase):  # HGI (18:), was GWY
    """The HGI80 base class."""

    _DEV_KLASS = DEV_KLASS.HGI
    _DEV_TYPES = ("18",)

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
        _LOGGER.debug("%s: can't (really) have a controller %s", self, ctl)

    def _proc_schema(self, schema) -> None:
        if schema.get("fake_bdr"):
            self._faked_bdr = self._gwy._get_device(self.id, class_="BDR", faked=True)

        if schema.get("fake_ext"):
            self._faked_ext = self._gwy._get_device(self.id, class_="BDR", faked=True)

        if schema.get("fake_thm"):
            self._faked_thm = self._gwy._get_device(self.id, class_="BDR", faked=True)

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        # of no value for a HGI80-compatible device
        return

    def _handle_msg(self, msg) -> None:
        def fake_addrs(msg, faked_dev):
            msg.src = faked_dev if msg.src is self else self
            msg.dst = faked_dev if msg.dst is self else self
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

        dev = self._gwy._get_device(device_id)
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
            SZ_DEVICE_ID: self.id,
            "faked_bdr": self._faked_bdr and self._faked_bdr.id,
            "faked_ext": self._faked_ext and self._faked_ext.id,
            "faked_thm": self._faked_thm and self._faked_thm.id,
        }


class HeatDevice(Device):  # Honeywell CH/DHW or compatible (incl. UFH, Heatpumps)
    """The Device base class for Honeywell CH/DHW or compatible."""

    _DEV_KLASS: str = DEV_KLASS.DEV
    _DEV_TYPES: tuple[str] = ()

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

    # def _set_ctl(self, ctl):  # self._ctl
    #     """Set the device's parent controller, after validating it."""

    #     if self._ctl is ctl:
    #         return self._ctl
    #     if self._is_controller and not isinstance(self, UfhController):  # HACK: UFC
    #         # HACK: UFC is/binds to a contlr
    #         return  # TODO
    #     if self._ctl is not None and not isinstance(self, UfhController):  # HACK: UFC
    #         raise CorruptStateError(f"{self} changed controller: {self._ctl} to {ctl}")

    #     #  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5  # has been seen
    #     if not isinstance(ctl, Controller) and not ctl._is_controller:
    #         raise TypeError(f"Device {ctl} is not a controller")

    #     self._ctl = ctl
    #     ctl.device_by_id[self.id] = self
    #     ctl.devices.append(self)

    #     _LOGGER.debug("%s: controller now set to %s", self, self._ctl)
    #     return self._ctl


class HvacDevice(Device):  # HVAC (ventilation, PIV, MV/HR)
    """The Device base class for HVAC (ventilation, PIV, MV/HR)."""

    # _DEV_KLASS = DEV_KLASS.DEV
    # _DEV_TYPES = ()

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._domain_id = "HV"

    # TODO: split
    # def _hvac_trick(self):  # a HACK - remove
    #     if not isinstance(self, HvacVentilator) and not randrange(3):
    #         [
    #             self._send_cmd(Command(RQ, _31DA, "00", d.id, retries=0))
    #             for d in self._gwy.devices
    #             if isinstance(d, HvacVentilator) and d is not self
    #         ]

    # def _handle_msg(self, msg) -> None:
    #     super()._handle_msg(msg)

    #     # if type(self) is HvacDevice:
    #     #     if self.type == "30":  # self.__class__ is Device, DEX
    #     #         # TODO: the RFG codes need checking
    #     #         if msg.code in (_31D9, _31DA) and msg.verb in (I_, RP):
    #     #             self.__class__ = HvacVentilator
    #     #         elif msg.code in (_0006, _0418, _3220) and msg.verb == RQ:
    #     #             self.__class__ = RfgGateway
    #     #         elif msg.code in (_313F,) and msg.verb == W_:
    #     #             self.__class__ = RfgGateway
    #     #     if type(self) is not Device:
    #     #         _LOGGER.warning(f"Promoted a device type for: {self}")

    #     if msg.code in (_1298, _12A0, _22F1, _22F3):
    #         self._hvac_trick()


_CLASS_BY_KLASS = class_by_attr(__name__, "_DEV_KLASS")  # e.g. "HGI": HgiGateway
