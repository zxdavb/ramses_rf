#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Base for all devices.
"""

# TODO: refactor polling

import logging
from types import SimpleNamespace
from typing import Optional

from .const import DEV_TYPE, DEV_TYPE_MAP, SZ_DEVICE_ID, __dev_mode__
from .entity_base import Child, Entity, class_by_attr
from .helpers import shrink
from .protocol import Command
from .protocol.address import NUL_DEV_ADDR, Address
from .protocol.const import SZ_FUNC, SZ_TIMEOUT
from .protocol.message import Message
from .protocol.ramses import CODES_BY_DEV_SLUG, CODES_ONLY_FROM_CTL
from .schema import SCHEMA_DEV, SZ_ALIAS, SZ_CLASS, SZ_FAKED, SZ_KNOWN_LIST

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
    #
    #       DHW/THM, TRV -> CTL     (temp, valve_position), or:
    #                CTL -> BDR/OTB (heat_demand)
    #          [ REQUEST -> WAITING ]
    #            unbound -- unbound
    #            unbound -- listening
    #           offering -> listening
    #           offering <- accepting
    # (confirming) bound -> accepting
    #              bound -- bound
    #
    UNKNOWN=None,
    UNBOUND="unb",  # unbound
    LISTENING="l",  # waiting for offer
    OFFERING="of",  # waiting for accept:              -> sent offer
    ACCEPTING="a",  # waiting for confirm: rcvd offer  -> sent accept
    # NFIRMED="c",  # bound:               rcvd accept -> sent confirm
    BOUND="bound",  # bound:               rcvd confirm
)


DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Device(Entity):
    """The Device base class - can also be used for unknown device types."""

    _SLUG: str = DEV_TYPE.DEV  # shouldn't be any of these instantiated

    _STATE_ATTR = None

    def __init__(self, gwy, dev_addr, **kwargs) -> None:
        _LOGGER.debug("Creating a Device: %s (%s)", dev_addr.id, self.__class__)

        # if not check_valid(dev_addr.id):  # TODO
        #     raise ValueError(f"Invalid device id: {dev_addr.id}")
        if dev_addr.id in gwy.device_by_id:
            raise LookupError(f"Duplicate DEV: {dev_addr.id}")
        gwy.device_by_id[dev_addr.id] = self
        gwy.devices.append(self)

        super().__init__(gwy)

        self.id: str = dev_addr.id

        # self.tcs = None  # NOTE: Heat (CH/DHW) devices only
        # self.ctl = None
        # self._child_id = None  # also in Child class

        self.addr = dev_addr
        self.type = dev_addr.type  # DEX  # TODO: remove this attr? use SLUG?

        self._faked: bool = None

    def __str__(self) -> str:
        if self._STATE_ATTR:
            return f"{self.id} ({self._child_id}): {getattr(self, self._STATE_ATTR)}"
        return f"{self.id} ({self._child_id})"

    def __lt__(self, other) -> bool:
        if not hasattr(other, "id"):
            return NotImplemented
        return self.id < other.id

    def _update_traits(self, **traits):
        """Update a device with new schema attrs.

        Raise an exception if the new schema is not a superset of the existing schema.
        """

        traits = shrink(SCHEMA_DEV(traits))

        if traits.get(SZ_FAKED):  # class & alias are done elsewhere
            if not isinstance(self, Fakeable):
                raise TypeError(f"Device is not fakable: {self}")
            self._make_fake()

    @classmethod
    def create_from_schema(cls, gwy, dev_addr: Address, **schema):
        """Create a device (for a GWY) and set its schema attrs (aka traits).

        All devices have traits, but also controllers (CTL, UFC) have a system schema.

        The appropriate Device class should have been determined by a factory.
        Schema attrs include: class (SLUG), alias & faked.
        """

        dev = cls(gwy, dev_addr)
        dev._update_traits(**schema)  # TODO: split traits/schema
        return dev

    def _setup_discovery_tasks(self) -> None:
        # super()._setup_discovery_tasks()
        # sometimes, battery-powered devices will respond to an RQ (e.g. bind mode)

        # if discover_flag & Discover.TRAITS:
        # self._add_discovery_task(Command(RQ, _1FC9, "00", self.id), 60 * 60 * 24)
        # self._add_discovery_task(Command(RQ, _0016, "00", self.id), 60 * 60)

        pass

    def _make_cmd(self, code, payload="00", **kwargs) -> None:  # skipcq: PYL-W0221
        super()._make_cmd(code, self.id, payload=payload, **kwargs)

    def _send_cmd(self, cmd, **kwargs) -> None:
        if getattr(self, "has_battery", None) and cmd.dst.id == self.id:
            _LOGGER.info(f"{cmd} < Sending inadvisable for {self} (it has a battery)")

        super()._send_cmd(cmd, **kwargs)

    def _handle_msg(self, msg: Message) -> None:
        assert msg.src is self, f"msg from {msg.src} inappropriately routed to {self}"

        super()._handle_msg(msg)

        if self._SLUG in DEV_TYPE_MAP.PROMOTABLE_SLUGS:
            # HACK: can get precise class?
            from .devices import best_dev_role

            cls = best_dev_role(
                self.addr, msg=msg, eavesdrop=self._gwy.config.enable_eavesdrop
            )
            if cls._SLUG != self._SLUG and DEV_TYPE.DEV not in (cls._SLUG, self._SLUG):
                _LOGGER.warning(
                    f"Promoting the device class of {self} to {cls._SLUG}"
                    f" - use a {SZ_KNOWN_LIST} to explicitly set this device's"
                    f" {SZ_CLASS} to '{DEV_TYPE_MAP[cls._SLUG]}'"
                )
                self.__class__ = cls

    @property
    def has_battery(self) -> Optional[bool]:  # 1060
        """Return True if a device is battery powered (excludes battery-backup)."""

        return isinstance(self, BatteryState) or _1060 in self._msgz

    @property
    def _is_present(self) -> bool:
        """Try to exclude ghost devices (as caused by corrupt packet addresses)."""
        return any(
            m.src == self for m in self._msgs.values() if not m._expired
        )  # TODO: needs addressing

    @property
    def schema(self) -> dict:
        """Return the fixed attributes of the device."""
        return {}  # SZ_CLASS: DEV_TYPE_MAP[self._SLUG]}

    @property
    def params(self) -> dict:
        """Return the configurable attributes of the device."""
        return {}

    @property
    def status(self) -> dict:
        """Return the state attributes of the device."""
        return {}

    @property
    def traits(self) -> dict:
        """Return the traits of the device."""
        known_dev = self._gwy._include.get(self.id)

        result = super().traits

        result.update(
            {
                SZ_CLASS: DEV_TYPE_MAP[self._SLUG],
                SZ_ALIAS: known_dev.get(SZ_ALIAS) if known_dev else None,
                SZ_FAKED: None,
            }
        )

        if _10E0 in self._msgs or _10E0 in CODES_BY_DEV_SLUG.get(self._SLUG, []):
            result.update({"_info": self.device_info})

        result.update({"_bind": self._msg_value(_1FC9)})

        return result


class DeviceInfo(Device):  # 10E0
    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        # if discover_flag & Discover.SCHEMA:
        if self._SLUG not in CODES_BY_DEV_SLUG or RP in CODES_BY_DEV_SLUG[
            self._SLUG
        ].get(_10E0, {}):
            self._add_discovery_task(Command(RQ, _10E0, "00", self.id), 60 * 60 * 24)

    @property
    def device_info(self) -> Optional[dict]:  # 10E0
        return self._msg_value(_10E0)


class Fakeable(Device):
    def __init__(self, gwy, *args, **kwargs) -> None:
        super().__init__(gwy, *args, **kwargs)

        self._faked = None  # known (schema) attr

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
                callback={
                    SZ_FUNC: proc_confirm,
                    SZ_TIMEOUT: 3,
                },  # re-Tx W until Rx an I
            )
            self._send_cmd(cmd)

        self._1fc9_state["code"] = code
        self._1fc9_state["state"] = BindState.LISTENING
        self._gwy.msg_transport._add_callback(
            f"{_1FC9}|{I_}|{NUL_DEV_ADDR.id}", {SZ_FUNC: proc_offer, SZ_TIMEOUT: 300}
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
            I_, code, self.id, callback={SZ_FUNC: proc_accept, SZ_TIMEOUT: 3}
        )
        self._send_cmd(cmd)

    @property
    def is_faked(self) -> dict:
        return bool(self._faked)

    @property
    def traits(self) -> dict:

        result = super().traits
        result[SZ_FAKED] = self.is_faked
        return result


class BatteryState(Device):  # 1060

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


class HgiGateway(DeviceInfo):  # HGI (18:)
    """The HGI80 base class."""

    _SLUG: str = DEV_TYPE.HGI

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.ctl = None
        self._child_id = "gw"  # TODO
        self.tcs = None

        self._faked_bdr = None
        self._faked_ext = None
        self._faked_thm = None

        # self. _proc_schema(**kwargs)

    # def _proc_schema(self, schema) -> None:
    #     if schema.get("fake_bdr"):
    #         self._faked_bdr = self._gwy.get_device(
    #             self.id, class_=DEV_TYPE.BDR, faked=True
    #         )  # also for THM, OUT

    def _handle_msg(self, msg: Message) -> None:
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

    def _create_fake_dev(self, dev_type, device_id) -> Device:  # TODO:
        if device_id[:2] != dev_type:
            raise TypeError(f"Invalid device ID {device_id} for type '{dev_type}:'")

        dev = self.device_by_id.get(device_id)
        if dev:  # TODO: BUG: is broken
            _LOGGER.warning("Destroying %s", dev)
            if dev._parent:
                del dev._parent.child_by_id[dev.id]
                dev._parent.childs.remove(dev)
                dev._parent = None
            del self.device_by_id[dev.id]
            self.devices.remove(dev)
            dev = None

        dev = self._gwy.get_device(device_id)
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
        device = self._create_fake_dev(DEV_TYPE_MAP.BDR, device_id=device_id)

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
        device = self._create_fake_dev(DEV_TYPE_MAP.OUT, device_id=device_id)

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
        device = self._create_fake_dev(DEV_TYPE_MAP.HCW, device_id=device_id)

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


class DeviceHeat(
    Child, DeviceInfo
):  # Honeywell CH/DHW or compatible (incl. UFH, Heatpumps)
    """The base class for Honeywell CH/DHW-compatible devices.

    Includes UFH and heatpumps (which can also cool).
    """

    _SLUG: str = DEV_TYPE.HEA  # shouldn't be any of these instantiated

    def __init__(self, gwy, dev_addr, **kwargs):
        super().__init__(gwy, dev_addr, **kwargs)

        self.ctl = None
        self.tcs = None
        self._child_id = None  # domain_id, or zone_idx

        self._iz_controller = None  # TODO: deprecate

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        if msg.verb != I_ or self._iz_controller is not None:
            return

        if not self._iz_controller and msg.code in CODES_ONLY_FROM_CTL:
            if self._iz_controller is None:
                _LOGGER.info(f"{msg!r} # IS_CONTROLLER (00): is TRUE")
                self._make_tcs_controller(msg=msg)
            elif self._iz_controller is False:  # TODO: raise CorruptStateError
                _LOGGER.error(f"{msg!r} # IS_CONTROLLER (01): was FALSE, now True")

    def _make_tcs_controller(self, *, msg=None, **schema) -> None:  # CH/DHW
        """Attach a TCS (create/update as required) after passing it any msg."""

        if self.type not in DEV_TYPE_MAP.CONTROLLERS:  # potentially can be controllers
            raise TypeError(f"Invalid device type to be a controller: {self}")

        self._iz_controller = self._iz_controller or msg or True

    # @property
    # def controller(self):  # -> Optional[Controller]:
    #     """Return the entity's controller, if known."""

    #     return self.ctl  # TODO: if the controller is not known, try to find it?

    @property
    def _is_controller(self) -> Optional[bool]:

        if self._iz_controller is not None:
            return bool(self._iz_controller)  # True, False, or msg

        if self.ctl is not None:  # TODO: messy
            return self.ctl is self

        return False

    @property
    def zone(self) -> Optional[Entity]:  # should be: Optional[Zone]
        """Return the device's parent zone, if known."""

        return self._parent


class DeviceHvac(Child, DeviceInfo):  # HVAC (ventilation, PIV, MV/HR)
    """The Device base class for HVAC (ventilation, PIV, MV/HR)."""

    _SLUG: str = DEV_TYPE.HVC  # these may be instantiated, and promoted later on

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._child_id = "hv"  # TODO: domain_id/deprecate

    # def _handle_msg(self, msg: Message) -> None:
    #     super()._handle_msg(msg)

    #     # if type(self) is DeviceHvac:
    #     #     if self.type == DEV_TYPE_MAP.RFG:  # self.__class__ is Device, DEX
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

    pass


BASE_CLASS_BY_SLUG = class_by_attr(__name__, "_SLUG")  # e.g. "HGI": HgiGateway
