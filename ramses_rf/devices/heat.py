#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""

import logging
from random import randint
from typing import Optional

from ..const import (
    _000C_DEVICE,
    _0005_ZONE,
    ATTR_HEAT_DEMAND,
    ATTR_RELAY_DEMAND,
    ATTR_SETPOINT,
    ATTR_TEMP,
    ATTR_WINDOW_OPEN,
    DEV_KLASS,
    DOMAIN_TYPE_MAP,
)
from ..protocol import Command, Priority
from ..protocol.address import NON_DEV_ADDR
from ..protocol.opentherm import (
    MSG_ID,
    MSG_NAME,
    MSG_TYPE,
    OPENTHERM_MESSAGES,
    PARAMS_MSG_IDS,
    SCHEMA_MSG_IDS,
    STATUS_MSG_IDS,
    VALUE,
)
from ..protocol.ramses import CODES_ONLY_FROM_CTL, CODES_SCHEMA, NAME
from .base import BatteryState, Fakeable, HeatDevice
from .const import Discover, __dev_mode__
from .entity_base import class_by_attr, discover_decorator

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


DEV_MODE = __dev_mode__  # and False
OTB_MODE = False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Actuator(HeatDevice):  # 3EF0, 3EF1

    ACTUATOR_CYCLE = "actuator_cycle"
    ACTUATOR_ENABLED = "actuator_enabled"  # boolean
    ACTUATOR_STATE = "actuator_state"
    MODULATION_LEVEL = "modulation_level"  # percentage (0.0-1.0)

    def _handle_msg(self, msg) -> None:  # NOTE: active
        super()._handle_msg(msg)

        if isinstance(self, OtbGateway):
            return

        if (
            msg.code == _3EF0
            and msg.verb == I_
            and not self._faked
            and not self._gwy.config.disable_sending
        ):
            self._make_cmd(_3EF1, priority=Priority.LOW, retries=1)

    @property
    def bit_3_7(self) -> Optional[bool]:  # 3EF0 (byte 3, only OTB)
        return self._msg_flag(_3EF0, "_flags_3", 7)

    @property
    def bit_6_6(self) -> Optional[bool]:  # 3EF0 ?dhw_enabled (byte 3, only R8820A?)
        return self._msg_flag(_3EF0, "_flags_3", 6)

    @property
    def ch_active(self) -> Optional[bool]:  # 3EF0 (byte 3, only R8820A?)
        return self._msg_value(_3EF0, key="ch_active")

    @property
    def ch_enabled(self) -> Optional[bool]:  # 3EF0 (byte 6, only R8820A?)
        return self._msg_value(_3EF0, key="ch_enabled")

    @property
    def dhw_active(self) -> Optional[bool]:  # 3EF0 (byte 3, only OTB)
        return self._msg_value(_3EF0, key="dhw_active")

    @property
    def flame_active(self) -> Optional[bool]:  # 3EF0 (byte 3, only OTB)
        return self._msg_value(_3EF0, key="flame_active")

    @property
    def ch_setpoint(self) -> Optional[float]:  # 3EF0 (byte 7, only R8820A?)
        return self._msg_value(_3EF0, key="ch_setpoint")

    @property
    def max_rel_modulation(self) -> Optional[float]:  # 3EF0 (byte 8, only R8820A?)
        return self._msg_value(_3EF0, key="max_rel_modulation")

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


class HeatDemand(HeatDevice):  # 3150

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


class Setpoint(HeatDevice):  # 2309

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


class Weather(Fakeable):  # 0002

    TEMPERATURE = ATTR_TEMP  # degrees Celsius

    def _bind(self):
        #
        #
        #

        def callback(msg):
            pass

        super()._bind()
        self._bind_request(_0002, callback=callback)

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
        self._send_cmd(cmd)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class RelayDemand(Fakeable):  # 0008

    RELAY_DEMAND = ATTR_RELAY_DEMAND  # percentage (0.0-1.0)

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        super()._discover(discover_flag=discover_flag)

        if discover_flag & Discover.STATUS and not self._faked:
            self._send_cmd(
                Command.get_relay_demand(self.id), priority=Priority.LOW, retries=1
            )

    def _handle_msg(self, msg) -> None:  # NOTE: active
        if msg.src.id == self.id:
            super()._handle_msg(msg)
            return

        if (
            self._gwy.config.disable_sending
            or not self._faked
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
            [self._send_cmd(cmd, **qos) for _ in range(1)]

        elif msg.code == _0009:  # can only be I, from a controller
            pass

        elif msg.code == _3B00 and msg.verb == I_:
            pass

        elif msg.code == _3EF0 and msg.verb == I_:  # NOT RP, TODO: why????
            cmd = Command.get_relay_demand(self.id)
            self._send_cmd(cmd, priority=Priority.LOW, retries=1)

        elif msg.code == _3EF1 and msg.verb == RQ:  # NOTE: WIP
            mod_level = 1.0

            cmd = Command.put_actuator_cycle(self.id, msg.src.id, mod_level, 600, 600)
            qos = {"priority": Priority.HIGH, "retries": 3}
            [self._send_cmd(cmd, **qos) for _ in range(1)]

    def _bind(self):
        # I --- 01:054173 --:------ 01:054173 1FC9 018 03-0008-04D39D FC-3B00-04D39D 03-1FC9-04D39D
        # W --- 13:123456 01:054173 --:------ 1FC9 006 00-3EF0-35E240
        # I --- 01:054173 13:123456 --:------ 1FC9 006 00-FFFF-04D39D

        def callback(msg):
            pass

        super()._bind()
        self._bind_waiting(_3EF0, callback=callback)

    @property
    def relay_demand(self) -> Optional[float]:  # 0008
        return self._msg_value(_0008, key=self.RELAY_DEMAND)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.RELAY_DEMAND: self.relay_demand,
        }


class DhwTemperature(Fakeable):  # 1260

    TEMPERATURE = ATTR_TEMP  # degrees Celsius

    def _bind(self):
        #
        #
        #

        def callback(msg):
            msg.src._evo.dhw._set_sensor(self)

        super()._bind()
        self._bind_request(_1260, callback=callback)

    @property
    def temperature(self) -> Optional[float]:  # 1260
        return self._msg_value(_1260, key=self.TEMPERATURE)

    @temperature.setter
    def temperature(self, value) -> None:  # 1260
        if not self._faked:
            raise RuntimeError(f"Can't set value for {self} (Faking is not enabled)")

        self._send_cmd(Command.put_dhw_temp(value))
        # lf._send_cmd(Command.get_dhw_temp(self._ctl.id, self.zone.idx))

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class Temperature(Fakeable):  # 30C9

    TEMPERATURE = ATTR_TEMP  # degrees Celsius

    def _bind(self):
        # I --- 34:145039 --:------ 34:145039 1FC9 012 00-30C9-8A368F 00-1FC9-8A368F
        # W --- 01:054173 34:145039 --:------ 1FC9 006 03-2309-04D39D  # real CTL
        # I --- 34:145039 01:054173 --:------ 1FC9 006 00-30C9-8A368F

        def callback(msg):
            msg.src._evo.zone_by_idx[msg.payload[0][0]]._set_sensor(self)

        super()._bind()
        self._bind_request(_30C9, callback=callback)

    @property
    def temperature(self) -> Optional[float]:  # 30C9
        return self._msg_value(_30C9, key=self.TEMPERATURE)

    @temperature.setter
    def temperature(self, value) -> None:  # 30C9
        if not self._faked:
            raise RuntimeError(f"Can't set value for {self} (Faking is not enabled)")

        self._send_cmd(Command.put_sensor_temp(self.id, value))
        # lf._send_cmd(Command.get_zone_temp(self._ctl.id, self.zone.idx))

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class RfgGateway(HeatDevice):  # RFG (30:)
    """The RFG100 base class."""

    _DEV_KLASS = DEV_KLASS.RFG
    _DEV_TYPES = ("30",)


class Controller(HeatDevice):  # CTL (01):
    """The Controller base class."""

    _DEV_KLASS = DEV_KLASS.CTL
    _DEV_TYPES = ("01",)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._ctl = self  # or args[1]
        self._domain_id = "FF"
        self._evo = None

        self._make_tcs_controller(**kwargs)

    # def __repr__(self) -> str:  # TODO:
    #     if self._evo:
    #         mode = self._evo._msg_value(_2E04, key="system_mode")
    #         return f"{self.id} ({self._domain_id}): {mode}"
    #     return f"{self.id} ({self._domain_id})"

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == _000C:
            [
                self._gwy._get_device(d, ctl_id=self._ctl.id)
                for d in msg.payload["devices"]
            ]

        # Route any messages to their heating systems, TODO: create dev first?
        if self._evo:
            self._evo._handle_msg(msg)


class Programmer(Controller):  # PRG (23):
    """The Controller base class."""

    _DEV_KLASS = DEV_KLASS.PRG
    _DEV_TYPES = ("23",)


class UfhController(HeatDevice):  # UFC (02):
    """The UFC class, the HCE80 that controls the UFH zones."""

    _DEV_KLASS = DEV_KLASS.UFC
    _DEV_TYPES = ("02",)

    HEAT_DEMAND = ATTR_HEAT_DEMAND

    _STATE_ATTR = "heat_demand"

    # 12:27:24.398 067  I --- 02:000921 --:------ 01:191718 3150 002 0360
    # 12:27:24.546 068  I --- 02:000921 --:------ 01:191718 3150 002 065A
    # 12:27:24.693 067  I --- 02:000921 --:------ 01:191718 3150 002 045C
    # 12:27:24.824 059  I --- 01:191718 --:------ 01:191718 3150 002 FC5C
    # 12:27:24.857 067  I --- 02:000921 --:------ 02:000921 3150 006 0060-015A-025C

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._domain_id = "FA"  # HACK: UFC

        self._circuits = {}
        self._setpoints = None
        self._heat_demand = None
        self._heat_demands = None
        self._relay_demand = None
        self._relay_demand_fa = None

        self._iz_controller = True

    def _start_discovery(self) -> None:

        delay = randint(10, 20)

        self._gwy.add_task(
            self._discover, discover_flag=Discover.SCHEMA, delay=0, period=3600 * 24
        )
        self._gwy.add_task(
            self._discover, discover_flag=Discover.PARAMS, delay=delay, period=600
        )
        self._gwy.add_task(
            self._discover, discover_flag=Discover.STATUS, delay=delay + 1, period=60
        )

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        super()._discover(discover_flag=discover_flag)
        # Only RPs are: 0001, 0005/000C, 10E0, 000A/2309 & 22D0

        if discover_flag & Discover.SCHEMA:
            self._make_cmd(_0005, payload=f"00{_0005_ZONE.UFH}")
            for ufh_idx in range(8):
                self._make_cmd(_000C, payload=f"{ufh_idx:02X}{_000C_DEVICE.UFH}")

        if discover_flag & Discover.PARAMS:  # only 2309 has any potential?
            for ufh_idx in self.circuits:
                self._make_cmd(_000A, payload=ufh_idx)
                self._make_cmd(_2309, payload=ufh_idx)

        # if discover_flag & Discover.STATUS:  # only 2309 has any potential?
        #     [self._make_cmd(_2309, payload=ufh_idx)for ufh_idx in self._circuits_alt]

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == _0005:  # system_zones
            if msg.payload["_device_class"] not in ("00", "04", "09"):
                return  # ALL, SENsor, UFH

            for idx, flag in enumerate(msg.payload["zone_mask"]):
                ufh_idx = f"{idx:02X}"
                if not flag:
                    self._circuits.pop(ufh_idx, None)
                elif "zone_idx" not in self._circuits.get(ufh_idx, {}):
                    self._circuits[ufh_idx] = {"zone_idx": None}
                    self._make_cmd(_000C, payload=f"{ufh_idx}{_000C_DEVICE.UFH}")

        elif msg.code == _0008:  # relay_demand, TODO: use msg DB?
            if msg.payload.get("domain_id") == "FC":
                self._relay_demand = msg
            else:  # FA
                self._relay_demand_fa = msg

        elif msg.code == _000C:  # zone_devices
            if msg.payload["_device_class"] not in ("00", "04", "09"):
                return  # ALL, SENsor, UFH

            ufh_idx = msg.payload["ufh_idx"]

            if not msg.payload["zone_id"]:
                self._circuits.pop(ufh_idx, None)
                return
            self._circuits[ufh_idx] = {"zone_idx": msg.payload["zone_id"]}

            if dev_ids := msg.payload["devices"]:
                # self._circuits[ufh_idx]["devices"] = dev_ids[0]  # or:
                if ctl := self._set_ctl(self._gwy._get_device(dev_ids[0])):
                    # self._circuits[ufh_idx]["devices"] = ctl.id  # better
                    self._set_parent(ctl._evo._get_zone(msg.payload["zone_id"]), msg)

        elif msg.code == _22C9:  # ufh_setpoints
            #  I --- 02:017205 --:------ 02:017205 22C9 024 00076C0A280101076C0A28010...
            #  I --- 02:017205 --:------ 02:017205 22C9 006 04076C0A2801
            self._setpoints = msg

            if self._gwy.config.enable_eavesdrop:  # and...:
                self._eavesdrop_ufc_circuits(msg)

        elif msg.code == _3150:  # heat_demands
            if isinstance(msg.payload, list):  # the circuit demands
                self._heat_demands = msg
            elif msg.payload.get("domain_id") == "FC":
                self._heat_demand = msg
            elif (
                (zone_idx := msg.payload.get("zone_idx"))
                and (evo := msg.dst._evo)
                and (zone := evo.zone_by_idx.get(zone_idx))
            ):
                zone._handle_msg(msg)

        # elif msg.code not in (_10E0, _22D0):
        #     print("AAA")

        # "0008|FA/FC", "22C9|array", "22D0|none", "3150|ZZ/array(/FC?)"

    def _eavesdrop_ufc_circuits(self, msg):
        # assert msg.code == _22C9
        circuits = [c["ufh_idx"] for c in msg.payload]

        for ufh_idx in [f"{x:02X}" for x in range(8)]:
            if ufh_idx not in self._circuits and ufh_idx in circuits:
                self._circuits[ufh_idx] = {"zone_idx": None}
            elif ufh_idx in self._circuits and ufh_idx not in circuits:
                pass  # TODO: ?.pop()

    def _set_parent(self, parent, domain=None) -> None:
        self._set_ctl(parent._ctl)

        if self not in parent.devices:
            parent.devices.append(self)
            parent.device_by_id[self.id] = self

        return parent

    @property
    def circuits(self) -> Optional[dict]:  # 000C
        return self._circuits

    @property
    def heat_demand(self) -> Optional[float]:  # 3150|FC (there is also 3150|FA)
        return self._msg_value_msg(self._heat_demand, key=self.HEAT_DEMAND)

    @property
    def heat_demands(self) -> Optional[dict]:  # 3150|ufh_idx array
        return self._msg_value_msg(self._heat_demands)
        return self._heat_demands.payload if self._heat_demands else None

    @property
    def relay_demand(self) -> Optional[dict]:  # 0008|FC
        return self._msg_value_msg(self._relay_demand, key=ATTR_RELAY_DEMAND)

    @property
    def relay_demand_fa(self) -> Optional[dict]:  # 0008|FA
        return self._msg_value_msg(self._relay_demand_fa, key=ATTR_RELAY_DEMAND)

    @property
    def setpoints(self) -> Optional[dict]:  # 22C9|ufh_idx array
        if self._setpoints is None:
            return

        return {
            c["ufh_idx"]: {k: v for k, v in c.items() if k in ("temp_low", "temp_high")}
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
            "relay_demand_fa": self.relay_demand_fa,
        }


class DhwSensor(DhwTemperature, BatteryState, HeatDevice):  # DHW (07): 10A0, 1260
    """The DHW class, such as a CS92."""

    _DEV_KLASS = DEV_KLASS.DHW
    _DEV_TYPES = ("07",)

    DHW_PARAMS = "dhw_params"
    TEMPERATURE = ATTR_TEMP

    _STATE_ATTR = "temperature"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._domain_id = "FA"

    def _handle_msg(self, msg) -> None:  # NOTE: active
        super()._handle_msg(msg)

        # The following is required, as CTLs don't send such every sync_cycle
        if msg.code == _1260 and self._ctl and not self._gwy.config.disable_sending:
            # update the controller DHW temp
            self._send_cmd(Command.get_dhw_temp(self._ctl.id))

    @property
    def dhw_params(self) -> Optional[dict]:  # 10A0
        return self._msg_value(_10A0)

    @property
    def params(self) -> dict:
        return {
            **super().params,
            self.DHW_PARAMS: self.dhw_params,
        }


class OutSensor(Weather, HeatDevice):  # OUT: 17
    """The OUT class (external sensor), such as a HB85/HB95."""

    _DEV_KLASS = DEV_KLASS.OUT
    _DEV_TYPES = ("17",)

    # LUMINOSITY = "luminosity"  # lux
    # WINDSPEED = "windspeed"  # km/h

    _STATE_ATTR = "temperature"


class OtbGateway(Actuator, HeatDemand, HeatDevice):  # OTB (10): 3220 (22D9, others)
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    _DEV_KLASS = DEV_KLASS.OTB
    _DEV_TYPES = ("10",)

    # BOILER_SETPOINT = "boiler_setpoint"
    # OPENTHERM_STATUS = "opentherm_status"

    _STATE_ATTR = "rel_modulation_level"

    _CODE_MAP = {
        # "00": _3EF0,  # master/slave status (actuator_state)
        "01": _22D9,  # boiler_setpoint
        "11": _3EF0,  # rel_modulation_level (actuator_state, also _3EF1)
        "12": _1300,  # ch_water_pressure
        "13": _12F0,  # dhw_flow_rate
        "19": _3200,  # boiler_output_temp
        "1A": _1260,  # dhw_temp
        "1B": _1290,  # outside_temp
        "1C": _3210,  # boiler_return_temp
        "38": _10A0,  # dhw_setpoint (is a PARAM)
        "39": _1081,  # ch_max_setpoint (is a PARAM)
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._domain_id = "FC"

        self._msgz[_3220] = {RP: {}}  # so later, we can: self._msgz[_3220][RP][msg_id]

        self._msgs_ot = {}
        self._msgs_ot_supported = {}
        # lf._msgs_ot_ctl_polled = {}
        self._msgs_supported = {}

    def _start_discovery(self) -> None:

        delay = randint(10, 20)

        self._gwy.add_task(  # 10E0/1FC9, 3220 pkts
            self._discover, discover_flag=Discover.SCHEMA, delay=240, period=3600 * 24
        )
        self._gwy.add_task(
            self._discover, discover_flag=Discover.PARAMS, delay=delay + 90, period=3600
        )
        self._gwy.add_task(
            self._discover, discover_flag=Discover.STATUS, delay=delay, period=180
        )

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        # see: https://www.opentherm.eu/request-details/?post_ids=2944

        super()._discover(discover_flag=discover_flag)

        if discover_flag & Discover.SCHEMA:
            for m in SCHEMA_MSG_IDS:  # From OT v2.2: version numbers
                if self._msgs_ot_supported.get(m) is not False and (
                    not self._msgs_ot.get(m) or self._msgs_ot[m]._expired
                ):
                    self._send_cmd(Command.get_opentherm_data(self.id, m))

        if discover_flag & Discover.PARAMS and OTB_MODE:
            for m in PARAMS_MSG_IDS:
                if self._msgs_ot_supported.get(m) is not False:
                    self._send_cmd(Command.get_opentherm_data(self.id, m))
            return

        if discover_flag & Discover.PARAMS:
            for code in [v for k, v in self._CODE_MAP.items() if k in PARAMS_MSG_IDS]:
                if self._msgs_supported.get(code) is not False:
                    self._send_cmd(Command(RQ, code, "00", self.id, retries=0))

        if discover_flag & Discover.STATUS:
            self._send_cmd(Command(RQ, _2401, "00", self.id))  # WIP
            self._send_cmd(Command(RQ, _3EF0, "00", self.id))

        if discover_flag & Discover.STATUS and OTB_MODE:
            for msg_id in STATUS_MSG_IDS:
                if self._msgs_ot_supported.get(msg_id) is not False:
                    self._send_cmd(
                        Command.get_opentherm_data(self.id, msg_id, retries=0)
                    )
            return

        if discover_flag & Discover.STATUS:
            self._send_cmd(Command.get_opentherm_data(self.id, "00"))
            self._send_cmd(Command.get_opentherm_data(self.id, "73"))

            for code in [v for k, v in self._CODE_MAP.items() if k in STATUS_MSG_IDS]:
                if self._msgs_supported.get(code) is not False:
                    self._send_cmd(Command(RQ, code, "00", self.id, retries=0))

        if False and DEV_MODE and discover_flag & Discover.STATUS:
            # TODO: these are WIP, and do vary in payload
            for code in (
                # _2401,  # WIP - modulation_level + flags?
                _3221,  # R8810A/20A
                _3223,  # R8810A/20A
            ):
                self._send_cmd(Command(RQ, code, "00", self.id))
            # TODO: these are WIP, appear fixed in payload, to test against BDR91T
            for code in (
                _0150,  # payload always "000000", R8820A only?
                _1098,  # payload always "00C8",   R8820A only?
                _10B0,  # payload always "0000",   R8820A only?
                _1FD0,  # payload always "0000000000000000"
                _2400,  # payload always "0000000F"
                _2410,  # payload always "000000000000000000000000010000000100000C"
                _2420,  # payload always "0000001000000...
            ):
                self._send_cmd(Command(RQ, code, "00", self.id))

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.code == _3220 and msg.payload[MSG_TYPE] != "-reserved-":
            self._handle_3220(msg)
        elif msg.code in self._CODE_MAP.values():
            self._handle_code(msg)

    def _handle_3220(self, msg) -> None:
        msg_id = f"{msg.payload[MSG_ID]:02X}"
        self._msgs_ot[msg_id] = msg

        if DEV_MODE:  # here to follow state changes
            self._send_cmd(Command(RQ, _2401, "00", self.id))  # oem code
            if msg_id != "73":
                self._send_cmd(Command.get_opentherm_data(self.id, "73"))  # oem code

        # TODO: this is development code - will be rationalised, eventually
        if OTB_MODE and (code := self._CODE_MAP.get(msg_id)):
            self._send_cmd(Command(RQ, code, "00", self.id, retries=0))

        if msg._pkt.payload[6:] == "47AB" or msg._pkt.payload[4:] == "121980":
            if msg_id not in self._msgs_ot_supported:
                self._msgs_ot_supported[msg_id] = None

            elif self._msgs_ot_supported[msg_id] is None:
                self._msgs_ot_supported[msg_id] = False
                _LOGGER.warning(
                    f"{msg!r} < OTB: deprecating msg_id "
                    f"0x{msg_id}: it appears unsupported",
                )

        else:
            self._msgs_ot_supported[msg_id] = msg.payload[MSG_TYPE] not in (
                "Data-Invalid",
                "Unknown-DataId",
                "OUT-reserved-",  # TODO: remove
            )

    def _handle_code(self, msg) -> None:
        if DEV_MODE:  # here to follow state changes
            self._send_cmd(Command.get_opentherm_data(self.id, "73"))  # unknown
            if msg.code != _2401:
                self._send_cmd(Command(RQ, _2401, "00", self.id))  # oem code

        if msg.code in (_10A0, _3EF0, _3EF1) or msg.len != 3:
            return

        if msg._pkt.payload[2:] == "7FFF" or (
            msg.code == _1300 and msg._pkt.payload[2:] == "09F6"
        ):
            if msg.code not in self._msgs_supported:
                self._msgs_supported[msg.code] = None

            elif self._msgs_supported[msg.code] is None:
                self._msgs_supported[msg.code] = False
                _LOGGER.warning(
                    f"{msg!r} < OTB: deprecating code "
                    f"0x{msg.code}: it appears unsupported",
                )

        else:
            self._msgs_supported.pop(msg.code, None)

    def _ot_msg_flag(self, msg_id, flag_idx) -> Optional[bool]:
        if flags := self._ot_msg_value(msg_id):
            return bool(flags[flag_idx])
        return None

    @staticmethod
    def _ot_msg_name(msg) -> str:
        return (
            msg.payload[MSG_NAME]
            if isinstance(msg.payload[MSG_NAME], str)
            else f"{msg.payload[MSG_ID]:02X}"
        )

    def _ot_msg_value(self, msg_id) -> Optional[float]:
        if (
            (msg := self._msgs_ot.get(msg_id))
            and self._msgs_ot_supported[msg_id]
            and not msg._expired
        ):
            return msg.payload.get(VALUE)
        return None

    @property
    def bit_2_4(self) -> Optional[bool]:  # 2401 - WIP
        return self._msg_flag(_2401, "_flags_2", 4)

    @property
    def bit_2_5(self) -> Optional[bool]:  # 2401 - WIP
        return self._msg_flag(_2401, "_flags_2", 5)

    @property
    def bit_2_6(self) -> Optional[bool]:  # 2401 - WIP
        return self._msg_flag(_2401, "_flags_2", 6)

    @property
    def bit_2_7(self) -> Optional[bool]:  # 2401 - WIP
        return self._msg_flag(_2401, "_flags_2", 7)

    @property
    def oem_code(self) -> Optional[float]:  # 3220/73
        return self._ot_msg_value("73")

    @property
    def percent(self) -> Optional[float]:  # 2401 - WIP
        return self._msg_value(_2401, key="_percent_3")

    @property
    def value(self) -> Optional[int]:  # 2401 - WIP
        return self._msg_value(_2401, key="_value_2")

    @property
    def boiler_output_temp(self) -> Optional[float]:  # 3200 (3220/19)
        if OTB_MODE:
            return self._ot_msg_value("19")
        return self._msg_value(_3200, key="temperature")

    @property
    def boiler_return_temp(self) -> Optional[float]:  # 3210 (3220/1C)
        if OTB_MODE:
            return self._ot_msg_value("1C")
        return self._msg_value(_3210, key="temperature")

    @property
    def boiler_setpoint(self) -> Optional[float]:  # 22D9 (3220/01)
        if OTB_MODE:
            return self._ot_msg_value("01")
        return self._msg_value(_22D9, key="setpoint")

    @property
    def ch_max_setpoint(self) -> Optional[float]:  # 1081 (3220/39)
        if OTB_MODE:
            return self._ot_msg_value("39")
        return self._msg_value(_1081, key="setpoint")

    @property
    def ch_water_pressure(self) -> Optional[float]:  # 1300 (3220/12)
        if OTB_MODE:
            return self._ot_msg_value("12")
        result = self._msg_value(_1300, key="pressure")
        return None if result == 25.5 else result  # HACK: to make more rigourous

    @property
    def dhw_flow_rate(self) -> Optional[float]:  # 12F0 (3220/13)
        if OTB_MODE:
            return self._ot_msg_value("13")
        return self._msg_value(_12F0, key="dhw_flow_rate")

    @property
    def dhw_setpoint(self) -> Optional[float]:  # 10A0 (3220/38)
        if OTB_MODE:
            return self._ot_msg_value("38")
        return self._msg_value(_10A0, key="setpoint")

    @property
    def dhw_temp(self) -> Optional[float]:  # 1260 (3220/1A)
        if OTB_MODE:
            return self._ot_msg_value("1A")
        return self._msg_value(_1260, key="temperature")

    @property
    def outside_temp(self) -> Optional[float]:  # 1290 (3220/1B)
        if OTB_MODE:
            return self._ot_msg_value("1B")
        return self._msg_value(_1290, key="temperature")

    @property
    def rel_modulation_level(self) -> Optional[float]:  # 3EF0/3EF1
        """Return the relative modulation level from RAMSES_II."""
        return self._msg_value((_3EF0, _3EF1), key=self.MODULATION_LEVEL)

    @property
    def rel_modulation_level_ot(self) -> Optional[float]:  # 3220/11
        """Return the relative modulation level from OpenTherm."""
        return self._ot_msg_value("11")

    @property
    def ch_active(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 8 + 1) if OTB_MODE else super().ch_active

    @property
    def ch_enabled(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 0) if OTB_MODE else super().ch_enabled

    @property
    def dhw_active(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 8 + 2) if OTB_MODE else super().dhw_active

    @property
    def dhw_enabled(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 1)  # if OTB_MODE else None  # TODO: super().xxx

    @property
    def flame_active(self) -> Optional[bool]:  # 3220/00 (flame_on)
        return self._ot_msg_flag("00", 8 + 3) if OTB_MODE else super().flame_active

    @property
    def cooling_active(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 8 + 4)  # if OTB_MODE else None  # TODO: super...

    @property
    def cooling_enabled(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 2)  # if OTB_MODE else None  # TODO: super().xxx

    @property
    def fault_present(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 8)  # if OTB_MODE else None  # TODO: super().xxx

    @property
    def opentherm_schema(self) -> dict:
        result = {
            self._ot_msg_name(v): v.payload
            for k, v in self._msgs_ot.items()
            if self._msgs_ot_supported.get(int(k, 16)) and int(k, 16) in SCHEMA_MSG_IDS
        }
        return {
            m: {k: v for k, v in p.items() if k.startswith(VALUE)}
            for m, p in result.items()
        }

    @property
    def opentherm_counters(self) -> dict:
        # for msg_id in ("71", "72", ...):
        return {
            "burner_hours": self._ot_msg_value("78"),
            "burner_starts": self._ot_msg_value("74"),
            "burner_failed_starts": self._ot_msg_value("71"),
            "ch_pump_hours": self._ot_msg_value("79"),
            "ch_pump_starts": self._ot_msg_value("75"),
            "dhw_burner_hours": self._ot_msg_value("7B"),
            "dhw_burner_starts": self._ot_msg_value("77"),
            "dhw_pump_hours": self._ot_msg_value("7A"),
            "dhw_pump_starts": self._ot_msg_value("76"),
            "flame_signal_low": self._ot_msg_value("72"),
        }

    @property
    def opentherm_params(self) -> dict:
        result = {
            self._ot_msg_name(v): v.payload
            for k, v in self._msgs_ot.items()
            if self._msgs_ot_supported.get(int(k, 16)) and int(k, 16) in PARAMS_MSG_IDS
        }
        return {
            m: {k: v for k, v in p.items() if k.startswith(VALUE)}
            for m, p in result.items()
        }

    @property
    def opentherm_status(self) -> dict:
        return {
            "boiler_output_temp": self._ot_msg_value("19"),
            "boiler_return_temp": self._ot_msg_value("1C"),
            "boiler_setpoint": self._ot_msg_value("01"),
            "ch_max_setpoint": self._ot_msg_value("39"),
            "ch_water_pressure": self._ot_msg_value("12"),
            "dhw_flow_rate": self._ot_msg_value("13"),
            "dhw_setpoint": self._ot_msg_value("38"),
            "dhw_temp": self._ot_msg_value("1A"),
            "outside_temp": self._ot_msg_value("1B"),
            "rel_modulation_level": self.rel_modulation_level_ot,
            #
            "oem_code": self._ot_msg_value("73"),
            #
            "ch_active": self._ot_msg_flag("00", 8 + 1),
            "ch_enabled": self._ot_msg_flag("00", 0),
            "cooling_active": self._ot_msg_flag("00", 8 + 4),
            "cooling_enabled": self._ot_msg_flag("00", 2),
            "dhw_active": self._ot_msg_flag("00", 8 + 2),
            "dhw_enabled": self._ot_msg_flag("00", 1),
            "fault_present": self._ot_msg_flag("00", 8),
            "flame_active": self._ot_msg_flag("00", 8 + 3),
        }

    @property
    def ramses_schema(self) -> dict:
        return {}

    @property
    def ramses_params(self) -> dict:
        return {
            "max_rel_modulation": self.max_rel_modulation,
        }

    @property
    def ramses_status(self) -> dict:
        return {
            "boiler_output_temp": self._msg_value(_3200, key="temperature"),
            "boiler_return_temp": self._msg_value(_3210, key="temperature"),
            "boiler_setpoint": self._msg_value(_22D9, key="setpoint"),
            "ch_max_setpoint": self._msg_value(_1081, key="setpoint"),
            "ch_water_pressure": self._msg_value(_1300, key="pressure"),
            "dhw_flow_rate": self._msg_value(_12F0, key="dhw_flow_rate"),
            "dhw_setpoint": self._msg_value(_1300, key="setpoint"),
            "dhw_temp": self._msg_value(_1260, key="temperature"),
            "outside_temp": self._msg_value(_1290, key="temperature"),
            "rel_modulation_level": self.rel_modulation_level,
            #
            "ch_setpoint": super().ch_setpoint,
            "ch_active": super().ch_active,
            "ch_enabled": super().ch_enabled,
            "dhw_active": super().dhw_active,
            "flame_active": super().flame_active,
        }

    @property
    def _supported_msgs(self) -> dict:
        return {
            k: (CODES_SCHEMA[k][NAME] if k in CODES_SCHEMA else None)
            for k in sorted(self._msgs)
            if self._msgs_supported.get(k) is not False
        }

    @property
    def _supported_ot_msgs(self) -> dict:
        return {
            k: OPENTHERM_MESSAGES[int(k, 16)].get("var", k)
            for k, v in sorted(self._msgs_ot_supported.items())
            if v is not False
        }

    @property
    def traits(self) -> dict:
        return {
            **super().traits,
            "opentherm_traits": self._supported_ot_msgs,
            "ramses_ii_traits": self._supported_msgs,
        }

    @property
    def schema(self) -> dict:
        return {
            **super().schema,
            "opentherm_schema": self.opentherm_schema,
            "ramses_ii_schema": self.ramses_schema,
        }

    @property
    def params(self) -> dict:
        return {
            **super().params,
            "opentherm_params": self.opentherm_params,
            "ramses_ii_params": self.ramses_params,
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,  # incl. actuator_cycle, actuator_state
            "opentherm_status": self.opentherm_status,
            "ramses_ii_status": self.ramses_status,
        }


class Thermostat(BatteryState, Setpoint, Temperature, HeatDevice):  # THM (..):
    """The THM/STA class, such as a TR87RF."""

    _DEV_KLASS = DEV_KLASS.THM
    _DEV_TYPES = ("03", "12", "22", "34")

    _STATE_ATTR = "temperature"

    def _handle_msg(self, msg) -> None:
        super()._handle_msg(msg)

        if msg.verb != I_ or self._iz_controller is not None:
            return

        # NOTE: this has only been tested on a 12:, does it work for a 34: too?
        if all(
            (
                msg._addrs[0] is self.addr,
                msg._addrs[1] is NON_DEV_ADDR,
                msg._addrs[2] is self.addr,
            )
        ):
            if self._iz_controller is None:
                # _LOGGER.info(f"{msg!r} # IS_CONTROLLER (10): is FALSE")
                self._iz_controller = False
            elif self._iz_controller:  # TODO: raise CorruptStateError
                _LOGGER.error(f"{msg!r} # IS_CONTROLLER (11): was TRUE, now False")

            if msg.code in CODES_ONLY_FROM_CTL:  # TODO: raise CorruptPktError
                _LOGGER.error(f"{msg!r} # IS_CONTROLLER (12); is CORRUPT PKT")

        elif all(
            (
                msg._addrs[0] is NON_DEV_ADDR,
                msg._addrs[1] is NON_DEV_ADDR,
                msg._addrs[2] is self.addr,
            )
        ):
            if self._iz_controller is None:
                # _LOGGER.info(f"{msg!r} # IS_CONTROLLER (20): is TRUE")
                self._iz_controller = msg
                self._make_tcs_controller(msg)
            elif self._iz_controller is False:  # TODO: raise CorruptStateError
                _LOGGER.error(f"{msg!r} # IS_CONTROLLER (21): was FALSE, now True")


class BdrSwitch(Actuator, RelayDemand, HeatDevice):  # BDR (13):
    """The BDR class, such as a BDR91.

    BDR91s can be used in six disctinct modes, including:
    - x2 boiler controller (FC/TPI): either traditional, or newer heat pump-aware
    - x1 electric heat zones (0x/ELE)
    - x1 zone valve zones (0x/VAL)
    - x2 DHW thingys (F9/DHW, FA/DHW)
    """

    _DEV_KLASS = DEV_KLASS.BDR
    _DEV_TYPES = ("13",)

    ACTIVE = "active"
    TPI_PARAMS = "tpi_params"

    _STATE_ATTR = "active"

    # def __init__(self, *args, **kwargs) -> None:
    #     super().__init__(*args, **kwargs)

    #     if kwargs.get("domain_id") == "FC":  # TODO: F9/FA/FC, zone_idx
    #         self._ctl._set_htg_control(self)

    @discover_decorator
    def _discover(self, discover_flag=Discover.ALL) -> None:
        """Discover BDRs.

        The BDRs have one of six roles:
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

        if discover_flag & Discover.PARAMS and not self._faked:
            self._send_cmd(Command.get_tpi_params(self.id))  # or: self._ctl.id

        if discover_flag & Discover.STATUS and not self._faked:
            # NOTE: 13: wont RP to an RQ/3EF0
            self._make_cmd(_3EF1)

    # def _handle_msg(self, msg) -> None:
    #     super()._handle_msg(msg)

    #     if msg.code == _1FC9 and msg.verb == RP:
    #         pass  # only a heater_relay will have 3B00

    #     elif msg.code == _3B00 and msg.verb == I_:
    #         pass  # only a heater_relay will I/3B00
    #         # for code in (_0008, _3EF1):
    #         #     self._make_cmd(code, delay=1)

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

        return None

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


class TrvActuator(
    BatteryState, HeatDemand, Setpoint, Temperature, HeatDevice
):  # TRV (04):
    """The TRV class, such as a HR92."""

    _DEV_KLASS = DEV_KLASS.TRV
    _DEV_TYPES = ("00", "04")  # TODO: keep 00?

    WINDOW_OPEN = ATTR_WINDOW_OPEN  # boolean

    _STATE_ATTR = "heat_demand"

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        if (heat_demand := super().heat_demand) is None:
            if self._msg_value(_3150) is None and self.setpoint is False:
                return 0  # instead of None (no 3150s sent when setpoint is False)
        return heat_demand

    @property
    def window_open(self) -> Optional[bool]:  # 12B0
        return self._msg_value(_12B0, key=self.WINDOW_OPEN)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.WINDOW_OPEN: self.window_open,
        }


########################################################################################
########################################################################################

_CLASS_BY_KLASS = class_by_attr(__name__, "_DEV_KLASS")  # e.g. "CTL": Controller

_KLASS_BY_TYPE = {
    None: DEV_KLASS.DEV,  # a generic, promotable device
    "00": DEV_KLASS.TRV,
    "01": DEV_KLASS.CTL,
    "02": DEV_KLASS.UFC,  # could be HVAC(SWI)
    "03": DEV_KLASS.THM,
    "04": DEV_KLASS.TRV,
    "07": DEV_KLASS.DHW,  # could be HVAC
    "10": DEV_KLASS.OTB,
    "12": DEV_KLASS.THM,  # can act like a DEV_KLASS.PRG
    "13": DEV_KLASS.BDR,
    "17": DEV_KLASS.OUT,
    "18": DEV_KLASS.HGI,  # could be HVAC
    "22": DEV_KLASS.THM,  # can act like a DEV_KLASS.PRG
    "23": DEV_KLASS.PRG,
    "30": DEV_KLASS.RFG,  # could be HVAC
    "34": DEV_KLASS.THM,
}  # these are the default device classes for Honeywell (non-HVAC) types


#################################################

_HEAT_VC_PAIR_BY_CLASS = {
    DEV_KLASS.DHW: ((I_, _1260),),
    DEV_KLASS.OTB: ((I_, _3220), (RP, _3220)),
}
