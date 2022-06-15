#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""

import logging
from symtable import Class
from typing import Any, Optional

from .const import (
    DEV_ROLE_MAP,
    DEV_TYPE,
    DEV_TYPE_MAP,
    DOMAIN_TYPE_MAP,
    SZ_DEVICES,
    SZ_DOMAIN_ID,
    SZ_HEAT_DEMAND,
    SZ_NAME,
    SZ_PRESSURE,
    SZ_PRIORITY,
    SZ_RELAY_DEMAND,
    SZ_RETRIES,
    SZ_SETPOINT,
    SZ_TEMPERATURE,
    SZ_UFH_IDX,
    SZ_WINDOW_OPEN,
    SZ_ZONE_IDX,
    SZ_ZONE_MASK,
    SZ_ZONE_TYPE,
    ZON_ROLE_MAP,
    __dev_mode__,
)
from .devices_base import BatteryState, DeviceHeat, Fakeable
from .entity_base import Entity, Parent, class_by_attr
from .helpers import shrink
from .protocol import Address, Command, Message, Priority
from .protocol.address import NON_DEV_ADDR
from .protocol.exceptions import InvalidPayloadError
from .protocol.opentherm import (
    MSG_ID,
    MSG_NAME,
    MSG_TYPE,
    OPENTHERM_MESSAGES,
    PARAMS_MSG_IDS,
    SCHEMA_MSG_IDS,
    STATUS_MSG_IDS,
    VALUE,
    OtMsgType,
)
from .protocol.ramses import CODES_HEAT_ONLY, CODES_ONLY_FROM_CTL, CODES_SCHEMA
from .schema import SCHEMA_SYS, SZ_ACTUATORS, SZ_CIRCUITS

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    F9,
    FA,
    FC,
    FF,
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
_OTB_MODE = False  # use OT (3220s) in favour of RAMSES

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Actuator(Fakeable, DeviceHeat):  # 3EF0, 3EF1

    ACTUATOR_CYCLE = "actuator_cycle"
    ACTUATOR_ENABLED = "actuator_enabled"  # boolean
    ACTUATOR_STATE = "actuator_state"
    MODULATION_LEVEL = "modulation_level"  # percentage (0.0-1.0)

    def _handle_msg(self, msg: Message) -> None:  # NOTE: active
        super()._handle_msg(msg)

        if isinstance(self, OtbGateway):
            return

        if False and (
            msg.code == _3EF0
            and msg.verb == I_
            and not self._faked
            and not self._gwy.config.disable_discovery
            and not self._gwy.config.disable_sending
        ):
            self._make_cmd(_3EF1, qos={SZ_PRIORITY: Priority.LOW, SZ_RETRIES: 1})

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


class HeatDemand(DeviceHeat):  # 3150

    HEAT_DEMAND = SZ_HEAT_DEMAND  # percentage valve open (0.0-1.0)

    @property
    def heat_demand(self) -> Optional[float]:  # 3150
        return self._msg_value(_3150, key=self.HEAT_DEMAND)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.HEAT_DEMAND: self.heat_demand,
        }


class Setpoint(DeviceHeat):  # 2309

    SETPOINT = SZ_SETPOINT  # degrees Celsius

    @property
    def setpoint(self) -> Optional[float]:  # 2309
        return self._msg_value(_2309, key=self.SETPOINT)

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.SETPOINT: self.setpoint,
        }


class Weather(Fakeable, DeviceHeat):  # 0002

    TEMPERATURE = SZ_TEMPERATURE  # degrees Celsius

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


class RelayDemand(Fakeable, DeviceHeat):  # 0008

    RELAY_DEMAND = SZ_RELAY_DEMAND  # percentage (0.0-1.0)

    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        if not self._faked:  # discover_flag & Discover.STATUS and
            self._add_discovery_task(Command.get_relay_demand(self.id), 60 * 60 * 5)

    def _handle_msg(self, msg: Message) -> None:  # NOTE: active
        if msg.src.id == self.id:
            super()._handle_msg(msg)
            return

        if (
            self._gwy.config.disable_sending
            or not self._faked
            or self._child_id is None
            or self._child_id
            not in (
                v for k, v in msg.payload.items() if k in (SZ_DOMAIN_ID, SZ_ZONE_IDX)
            )
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
            self._send_cmd(cmd, qos={SZ_PRIORITY: Priority.LOW, SZ_RETRIES: 1})

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


class DhwTemperature(Fakeable, DeviceHeat):  # 1260

    TEMPERATURE = SZ_TEMPERATURE  # degrees Celsius

    def _bind(self):
        #
        #
        #

        def callback(msg):
            self.set_parent(msg.src, child_id=FA, is_sensor=True)

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
        # lf._send_cmd(Command.get_dhw_temp(self.ctl.id, self.zone.idx))

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class Temperature(Fakeable, DeviceHeat):  # 30C9

    TEMPERATURE = SZ_TEMPERATURE  # degrees Celsius

    def _bind(self):
        # I --- 34:145039 --:------ 34:145039 1FC9 012 00-30C9-8A368F 00-1FC9-8A368F
        # W --- 01:054173 34:145039 --:------ 1FC9 006 03-2309-04D39D  # real CTL
        # I --- 34:145039 01:054173 --:------ 1FC9 006 00-30C9-8A368F

        def callback(msg):
            self.set_parent(msg.src, child_id=msg.payload[0][0], is_sensor=True)

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
        # lf._send_cmd(Command.get_zone_temp(self.ctl.id, self.zone.idx))

    @property
    def status(self) -> dict:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class RfgGateway(DeviceHeat):  # RFG (30:)
    """The RFG100 base class."""

    _SLUG: str = DEV_TYPE.RFG


class Controller(DeviceHeat):  # CTL (01):
    """The Controller base class."""

    _SLUG: str = DEV_TYPE.CTL

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # self.ctl = None
        self.tcs = None  # TODO: = self?
        self._make_tcs_controller(**kwargs)  # NOTE: must create_from_schema first

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        self.tcs._handle_msg(msg)

    def _make_tcs_controller(self, *, msg=None, **schema) -> None:  # CH/DHW
        """Attach a TCS (create/update as required) after passing it any msg."""

        def get_system(*, msg=None, **schema) -> Any:  # System:
            """Return a TCS (temperature control system), create it if required.

            Use the schema to create/update it, then pass it any msg to handle.

            TCSs are uniquely identified by a controller ID.
            If a TCS is created, attach it to this device (which should be a CTL).
            """

            from .systems import zx_system_factory

            schema = shrink(SCHEMA_SYS(schema))

            if not self.tcs:
                self.tcs = zx_system_factory(self, msg=msg, **schema)

            elif schema:
                self.tcs._update_schema(**schema)

            if msg:
                self.tcs._handle_msg(msg)
            return self.tcs

        super()._make_tcs_controller(msg=None, **schema)

        self.tcs = get_system(msg=msg, **schema)


class Programmer(Controller):  # PRG (23):
    """The Controller base class."""

    _SLUG: str = DEV_TYPE.PRG


class UfhController(Parent, DeviceHeat):  # UFC (02):
    """The UFC class, the HCE80 that controls the UFH zones."""

    _SLUG: str = DEV_TYPE.UFC

    HEAT_DEMAND = SZ_HEAT_DEMAND

    _STATE_ATTR = "heat_demand"

    # 12:27:24.398 067  I --- 02:000921 --:------ 01:191718 3150 002 0360
    # 12:27:24.546 068  I --- 02:000921 --:------ 01:191718 3150 002 065A
    # 12:27:24.693 067  I --- 02:000921 --:------ 01:191718 3150 002 045C
    # 12:27:24.824 059  I --- 01:191718 --:------ 01:191718 3150 002 FC5C
    # 12:27:24.857 067  I --- 02:000921 --:------ 02:000921 3150 006 0060-015A-025C

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._child_id = FA  # NOTE: domain_id, HACK: UFC

        self._circuits = {}
        self._setpoints = None
        self._heat_demand = None
        self._heat_demands = None
        self._relay_demand = None
        self._relay_demand_fa = None

        self._iz_controller = True

    def _setup_discovery_tasks(self) -> None:
        super()._setup_discovery_tasks()

        # Only RPs are: 0001, 0005/000C, 10E0, 000A/2309 & 22D0

        self._add_discovery_task(
            Command(RQ, _0005, f"00{DEV_ROLE_MAP.UFH}", self.id), 60 * 60 * 24
        )
        for ufh_idx in range(8):
            payload = f"{ufh_idx:02X}{DEV_ROLE_MAP.UFH}"
            self._add_discovery_task(Command(RQ, _000C, payload, self.id), 60 * 60 * 24)

        # if discover_flag & Discover.PARAMS:  # only 2309 has any potential?
        for ufh_idx in self.circuits:
            self._add_discovery_task(Command(RQ, _000A, ufh_idx, self.id), 60 * 60 * 6)
            self._add_discovery_task(Command(RQ, _2309, ufh_idx, self.id), 60 * 60 * 6)

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        if msg.code == _0005:  # system_zones
            if msg.payload[SZ_ZONE_TYPE] not in (
                ZON_ROLE_MAP.ACT,
                ZON_ROLE_MAP.SEN,
                ZON_ROLE_MAP.UFH,
            ):
                return  # ALL, SENsor, UFH

            for idx, flag in enumerate(msg.payload[SZ_ZONE_MASK]):
                ufh_idx = f"{idx:02X}"
                if not flag:
                    self._circuits.pop(ufh_idx, None)
                elif SZ_ZONE_IDX not in self._circuits.get(ufh_idx, {}):
                    self._circuits[ufh_idx] = {SZ_ZONE_IDX: None}
                    self._make_cmd(_000C, payload=f"{ufh_idx}{DEV_ROLE_MAP.UFH}")

        elif msg.code == _0008:  # relay_demand, TODO: use msg DB?
            if msg.payload.get(SZ_DOMAIN_ID) == FC:
                self._relay_demand = msg
            else:  # FA
                self._relay_demand_fa = msg

        elif msg.code == _000C:  # zone_devices
            if not msg.payload[SZ_DEVICES]:
                return
            if msg.payload[SZ_ZONE_TYPE] not in (
                ZON_ROLE_MAP.ACT,
                ZON_ROLE_MAP.SEN,
                ZON_ROLE_MAP.UFH,
            ):
                return  # ALL, SENsor, UFH

            ufh_idx = msg.payload[SZ_UFH_IDX]

            if not msg.payload[SZ_ZONE_IDX]:
                self._circuits.pop(ufh_idx, None)
                return
            self._circuits[ufh_idx] = {SZ_ZONE_IDX: msg.payload[SZ_ZONE_IDX]}

            # TODO: REFACTOR
            # if dev_ids := msg.payload[SZ_DEVICES]:
            #     # self._circuits[ufh_idx][SZ_DEVICES] = dev_ids[0]  # or:
            #     if ctl := self._set_ctl(self._gwy.get_device(dev_ids[0])):
            #         # self._circuits[ufh_idx][SZ_DEVICES] = ctl.id  # better
            #         self.set_parent(
            #             ctl.tcs.get_htg_zone(msg.payload[SZ_ZONE_IDX]), msg
            #         )

        elif msg.code == _22C9:  # ufh_setpoints
            #  I --- 02:017205 --:------ 02:017205 22C9 024 00076C0A280101076C0A28010...
            #  I --- 02:017205 --:------ 02:017205 22C9 006 04076C0A2801
            self._setpoints = msg

        elif msg.code == _3150:  # heat_demands
            if isinstance(msg.payload, list):  # the circuit demands
                self._heat_demands = msg
            elif msg.payload.get(SZ_DOMAIN_ID) == FC:
                self._heat_demand = msg
            elif (
                (zone_idx := msg.payload.get(SZ_ZONE_IDX))
                and (tcs := msg.dst.tcs)
                and (zone := tcs.zone_by_idx.get(zone_idx))
            ):
                zone._handle_msg(msg)

        # elif msg.code not in (_10E0, _22D0):
        #     print("xxx")

        # "0008|FA/FC", "22C9|array", "22D0|none", "3150|ZZ/array(/FC?)"

    def get_circuit(self, cct_idx, *, msg=None, **schema) -> Any:
        """Return a UFH circuit, create it if required.

        First, use the schema to create/update it, then pass it any msg to handle.

        Circuits are uniquely identified by a UFH controller ID|cct_idx pair.
        If a circuit is created, attach it to this UFC.
        """

        schema = {}  # shrink(SCHEMA_CCT(schema))

        cct = self.child_by_id.get(cct_idx)
        if not cct:
            cct = UfhCircuit(self, cct_idx)
            self.child_by_id[cct_idx] = cct
            self.childs.append(cct)

        elif schema:
            cct._update_schema(**schema)

        if msg:
            cct._handle_msg(msg)
        return cct

    @property
    def circuits(self) -> Optional[dict]:  # 000C
        return self._circuits

    @property
    def heat_demand(self) -> Optional[float]:  # 3150|FC (there is also 3150|FA)
        return self._msg_value_msg(self._heat_demand, key=self.HEAT_DEMAND)

    @property
    def heat_demands(self) -> Optional[dict]:  # 3150|ufh_idx array
        # return self._heat_demands.payload if self._heat_demands else None
        return self._msg_value_msg(self._heat_demands)

    @property
    def relay_demand(self) -> Optional[dict]:  # 0008|FC
        return self._msg_value_msg(self._relay_demand, key=SZ_RELAY_DEMAND)

    @property
    def relay_demand_fa(self) -> Optional[dict]:  # 0008|FA
        return self._msg_value_msg(self._relay_demand_fa, key=SZ_RELAY_DEMAND)

    @property
    def setpoints(self) -> Optional[dict]:  # 22C9|ufh_idx array
        if self._setpoints is None:
            return

        return {
            c[SZ_UFH_IDX]: {
                k: v for k, v in c.items() if k in ("temp_low", "temp_high")
            }
            for c in self._setpoints.payload
        }

    @property  # id, type
    def schema(self) -> dict:
        return {
            **super().schema,
            SZ_CIRCUITS: self.circuits,
        }

    @property  # setpoint, config, mode (not schedule)
    def params(self) -> dict:
        return {
            **super().params,
            SZ_CIRCUITS: self.setpoints,
        }

    @property
    def status(self) -> dict:
        return {
            **super().status,
            SZ_HEAT_DEMAND: self.heat_demand,
            SZ_RELAY_DEMAND: self.relay_demand,
            f"{SZ_RELAY_DEMAND}_fa": self.relay_demand_fa,
        }


class DhwSensor(DhwTemperature, BatteryState):  # DHW (07): 10A0, 1260
    """The DHW class, such as a CS92."""

    _SLUG: str = DEV_TYPE.DHW

    DHW_PARAMS = "dhw_params"
    TEMPERATURE = SZ_TEMPERATURE

    _STATE_ATTR = SZ_TEMPERATURE

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._child_id = FA  # NOTE: domain_id

    def _handle_msg(self, msg: Message) -> None:  # NOTE: active
        super()._handle_msg(msg)

        # The following is required, as CTLs don't send such every sync_cycle
        if msg.code == _1260 and self.ctl and not self._gwy.config.disable_sending:
            # update the controller DHW temp
            self._send_cmd(Command.get_dhw_temp(self.ctl.id))

    @property
    def dhw_params(self) -> Optional[dict]:  # 10A0
        return self._msg_value(_10A0)

    @property
    def params(self) -> dict:
        return {
            **super().params,
            self.DHW_PARAMS: self.dhw_params,
        }


class OutSensor(Weather):  # OUT: 17
    """The OUT class (external sensor), such as a HB85/HB95."""

    _SLUG: str = DEV_TYPE.OUT

    # LUMINOSITY = "luminosity"  # lux
    # WINDSPEED = "windspeed"  # km/h

    _STATE_ATTR = SZ_TEMPERATURE


class OtbGateway(Actuator, HeatDemand):  # OTB (10): 3220 (22D9, others)
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    _SLUG: str = DEV_TYPE.OTB

    _STATE_ATTR = "rel_modulation_level"

    OT_TO_RAMSES = {
        # "00": _3EF0,  # master/slave status (actuator_state)
        "01": _22D9,  # boiler_setpoint
        "0E": _3EF0,  # max_rel_modulation_level (is a PARAM?)
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

        self._child_id = FC  # NOTE: domain_id

        self._msgz[_3220] = {RP: {}}  # so later, we can: self._msgz[_3220][RP][msg_id]

        self._msgs_ot = {}
        self._msgs_ot_supported = {}
        # lf._msgs_ot_ctl_polled = {}
        self._msgs_supported = {}

    def _setup_discovery_tasks(self) -> None:
        # see: https://www.opentherm.eu/request-details/?post_ids=2944
        super()._setup_discovery_tasks()

        # the following are test/dev
        if DEV_MODE:
            for code in (
                _2401,  # WIP - modulation_level + flags?
                _3221,  # R8810A/20A
                _3223,  # R8810A/20A
            ):  # TODO: these are WIP, but do vary in payload
                self._add_discovery_task(Command(RQ, code, "00", self.id), 60)

        for m in SCHEMA_MSG_IDS:  # From OT v2.2: version numbers
            if _OTB_MODE or m not in self.OT_TO_RAMSES:
                self._add_discovery_task(
                    Command.get_opentherm_data(self.id, m), 60 * 60 * 24, delay=60 * 3
                )

        for m in PARAMS_MSG_IDS:  # or L/T state
            if _OTB_MODE or m not in self.OT_TO_RAMSES:
                self._add_discovery_task(
                    Command.get_opentherm_data(self.id, m), 60 * 60, delay=90
                )

        for msg_id in STATUS_MSG_IDS:
            if _OTB_MODE or m not in self.OT_TO_RAMSES:
                self._add_discovery_task(
                    Command.get_opentherm_data(self.id, msg_id), 60 * 5, delay=15
                )

        # TODO: both modulation level?
        self._add_discovery_task(Command(RQ, _2401, "00", self.id), 60 * 5)
        self._add_discovery_task(Command(RQ, _3EF0, "00", self.id), 60 * 5)

        if _OTB_MODE:
            return

        for code in [v for k, v in self.OT_TO_RAMSES.items() if k in PARAMS_MSG_IDS]:
            self._add_discovery_task(
                Command(RQ, code, "00", self.id), 60 * 60, delay=90
            )

        for code in [v for k, v in self.OT_TO_RAMSES.items() if k in STATUS_MSG_IDS]:
            self._add_discovery_task(Command(RQ, code, "00", self.id), 60 * 5)

        if False and DEV_MODE:
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
                self._add_discovery_task(
                    Command(RQ, code, "00", self.id), 60 * 5, delay=60 * 5
                )

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        if msg.code == _3220 and msg.payload[MSG_TYPE] != OtMsgType.RESERVED:
            self._handle_3220(msg)
        elif msg.code in self.OT_TO_RAMSES.values():
            self._handle_code(msg)

    def _handle_3220(self, msg: Message) -> None:
        msg_id = f"{msg.payload[MSG_ID]:02X}"
        self._msgs_ot[msg_id] = msg

        if DEV_MODE:  # here to follow state changes
            self._send_cmd(Command(RQ, _2401, "00", self.id))  # oem code
            if msg_id != "73":
                self._send_cmd(Command.get_opentherm_data(self.id, "73"))  # oem code

        # TODO: this is development code - will be rationalised, eventually
        if _OTB_MODE and (code := self.OT_TO_RAMSES.get(msg_id)):
            self._send_cmd(Command(RQ, code, "00", self.id))

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
            # 18:50:32.524 ... RQ --- 18:013393 10:048122 --:------ 3220 005 0080730000
            # 18:50:32.547 ... RP --- 10:048122 18:013393 --:------ 3220 005 00B0730000  # -reserved-
            # 18:55:32.601 ... RQ --- 18:013393 10:048122 --:------ 3220 005 0080730000
            # 18:55:32.630 ... RP --- 10:048122 18:013393 --:------ 3220 005 00C07300CB  # Read-Ack, 'value': 203
            self._msgs_ot_supported[msg_id] = msg.payload[MSG_TYPE] not in (
                OtMsgType.DATA_INVALID,
                OtMsgType.UNKNOWN_DATAID,
                # OtMsgType.RESERVED,  # some always reserved, others sometimes so
            )

    def _handle_code(self, msg: Message) -> None:
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
        if _OTB_MODE:
            return self._ot_msg_value("19")
        return self._msg_value(_3200, key=SZ_TEMPERATURE)

    @property
    def boiler_return_temp(self) -> Optional[float]:  # 3210 (3220/1C)
        if _OTB_MODE:
            return self._ot_msg_value("1C")
        return self._msg_value(_3210, key=SZ_TEMPERATURE)

    @property
    def boiler_setpoint(self) -> Optional[float]:  # 22D9 (3220/01)
        if _OTB_MODE:
            return self._ot_msg_value("01")
        return self._msg_value(_22D9, key=SZ_SETPOINT)

    @property
    def ch_max_setpoint(self) -> Optional[float]:  # 1081 (3220/39)
        if _OTB_MODE:
            return self._ot_msg_value("39")
        return self._msg_value(_1081, key=SZ_SETPOINT)

    @property
    def ch_water_pressure(self) -> Optional[float]:  # 1300 (3220/12)
        if _OTB_MODE:
            return self._ot_msg_value("12")
        result = self._msg_value(_1300, key=SZ_PRESSURE)
        return None if result == 25.5 else result  # HACK: to make more rigourous

    @property
    def dhw_flow_rate(self) -> Optional[float]:  # 12F0 (3220/13)
        if _OTB_MODE:
            return self._ot_msg_value("13")
        return self._msg_value(_12F0, key="dhw_flow_rate")

    @property
    def dhw_setpoint(self) -> Optional[float]:  # 10A0 (3220/38)
        if _OTB_MODE:
            return self._ot_msg_value("38")
        return self._msg_value(_10A0, key=SZ_SETPOINT)

    @property
    def dhw_temp(self) -> Optional[float]:  # 1260 (3220/1A)
        if _OTB_MODE:
            return self._ot_msg_value("1A")
        return self._msg_value(_1260, key=SZ_TEMPERATURE)

    @property
    def outside_temp(self) -> Optional[float]:  # 1290 (3220/1B)
        if _OTB_MODE:
            return self._ot_msg_value("1B")
        return self._msg_value(_1290, key=SZ_TEMPERATURE)

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
        return self._ot_msg_flag("00", 8 + 1) if _OTB_MODE else super().ch_active

    @property
    def ch_enabled(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 0) if _OTB_MODE else super().ch_enabled

    @property
    def dhw_active(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 8 + 2) if _OTB_MODE else super().dhw_active

    @property
    def dhw_enabled(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 1)  # if _OTB_MODE else None  # TODO: super().xxx

    @property
    def flame_active(self) -> Optional[bool]:  # 3220/00 (flame_on)
        return self._ot_msg_flag("00", 8 + 3) if _OTB_MODE else super().flame_active

    @property
    def cooling_active(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag(
            "00", 8 + 4
        )  # if _OTB_MODE else None  # TODO: super...

    @property
    def cooling_enabled(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 2)  # if _OTB_MODE else None  # TODO: super().xxx

    @property
    def fault_present(self) -> Optional[bool]:  # 3220/00
        return self._ot_msg_flag("00", 8)  # if _OTB_MODE else None  # TODO: super().xxx

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
        }  # 0x73 is OEM diagnostic code...

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
            "boiler_output_temp": self._msg_value(_3200, key=SZ_TEMPERATURE),
            "boiler_return_temp": self._msg_value(_3210, key=SZ_TEMPERATURE),
            "boiler_setpoint": self._msg_value(_22D9, key=SZ_SETPOINT),
            "ch_max_setpoint": self._msg_value(_1081, key=SZ_SETPOINT),
            "ch_water_pressure": self._msg_value(_1300, key=SZ_PRESSURE),
            "dhw_flow_rate": self._msg_value(_12F0, key="dhw_flow_rate"),
            "dhw_setpoint": self._msg_value(_1300, key=SZ_SETPOINT),
            "dhw_temp": self._msg_value(_1260, key=SZ_TEMPERATURE),
            "outside_temp": self._msg_value(_1290, key=SZ_TEMPERATURE),
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
            k: (CODES_SCHEMA[k][SZ_NAME] if k in CODES_SCHEMA else None)
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


class Thermostat(BatteryState, Setpoint, Temperature):  # THM (..):
    """The THM/STA class, such as a TR87RF."""

    _SLUG: str = DEV_TYPE.THM

    _STATE_ATTR = SZ_TEMPERATURE

    def _handle_msg(self, msg: Message) -> None:
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
                self._make_tcs_controller(msg=msg)
            elif self._iz_controller is False:  # TODO: raise CorruptStateError
                _LOGGER.error(f"{msg!r} # IS_CONTROLLER (21): was FALSE, now True")


class BdrSwitch(Actuator, RelayDemand):  # BDR (13):
    """The BDR class, such as a BDR91.

    BDR91s can be used in six disctinct modes, including:
    - x2 boiler controller (FC/TPI): either traditional, or newer heat pump-aware
    - x1 electric heat zones (0x/ELE)
    - x1 zone valve zones (0x/VAL)
    - x2 DHW thingys (F9/DHW, FA/DHW)
    """

    _SLUG: str = DEV_TYPE.BDR

    ACTIVE = "active"
    TPI_PARAMS = "tpi_params"

    _STATE_ATTR = "active"

    # def __init__(self, *args, **kwargs) -> None:
    #     super().__init__(*args, **kwargs)

    #     if kwargs.get(SZ_DOMAIN_ID) == FC:  # TODO: F9/FA/FC, zone_idx
    #         self.ctl._set_app_cntrl(self)

    def _setup_discovery_tasks(self) -> None:
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

        super()._setup_discovery_tasks()

        if self._faked:
            return

        # discover_flag & Discover.PARAMS and
        self._add_discovery_task(
            Command.get_tpi_params(self.id), 60 * 60 * 6
        )  # also: self.ctl.id

        # discover_flag & Discover.STATUS and
        self._add_discovery_task(Command(RQ, _3EF1, "00", self.id), 60 * 60 * 5)

    @property
    def active(self) -> Optional[bool]:  # 3EF0, 3EF1
        """Return the actuator's current state."""
        result = self._msg_value((_3EF0, _3EF1), key=self.MODULATION_LEVEL)
        return None if result is None else bool(result)

    @property
    def role(self) -> Optional[str]:
        """Return the role of the BDR91A (there are six possibilities)."""

        # TODO: use self._parent?
        if self._child_id in DOMAIN_TYPE_MAP:
            return DOMAIN_TYPE_MAP[self._child_id]
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


class TrvActuator(BatteryState, HeatDemand, Setpoint, Temperature):  # TRV (04):
    """The TRV class, such as a HR92."""

    _SLUG: str = DEV_TYPE.TRV

    WINDOW_OPEN = SZ_WINDOW_OPEN  # boolean

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


class JimDevice(Actuator):  # BDR (08):
    _SLUG: str = DEV_TYPE.JIM


class JstDevice(RelayDemand):  # BDR (31):
    _SLUG: str = DEV_TYPE.JST


class UfhCircuit(Entity):
    """The UFH circuit class (UFC:circuit is much like CTL/TCS:zone).

    NOTE: for circuits, there's a difference between :
     - `self.ctl`: the UFH controller, and
     - `self.tcs.ctl`: the Evohome controller
    """

    _SLUG: str = None  # is not a zone

    def __init__(self, ufc, ufh_idx: str) -> None:
        super().__init__(ufc._gwy)

        self.id: str = f"{ufc.id}_{ufh_idx}"

        self.ufc: UfhController = ufc
        self._child_id = ufh_idx

        self._ctl: Controller = None  # TODO: should be: .ufc? .ctl?
        self._zone = None

    # def __str__(self) -> str:
    #     return f"{self.id} ({self._zone and self._zone._child_id})"

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        # FIXME:
        if msg.code == _000C and msg.payload[SZ_DEVICES]:  # zone_devices

            if not (dev_ids := msg.payload[SZ_DEVICES]):
                return
            if len(dev_ids) != 1:
                raise InvalidPayloadError("No devices")

            # ctl = self._gwy.device_by_id.get(dev_ids[0])
            ctl = self._gwy.get_device(dev_ids[0])
            if not ctl or (self._ctl and self._ctl is not ctl):
                raise InvalidPayloadError("No CTL")
            self._ctl = ctl

            ctl._make_tcs_controller()
            # self.set_parent(ctl.tcs)

            zon = ctl.tcs.get_htg_zone(msg.payload[SZ_ZONE_IDX])
            if not zon or (self._zone and self._zone is not zon):
                raise InvalidPayloadError("No Zone")
            self._zone = zon

            if self not in self._zone.actuators:
                schema = {SZ_ACTUATORS: [self.ufc.id], SZ_CIRCUITS: [self.id]}
                self._zone._update_schema(**schema)

    @property
    def ufx_idx(self) -> str:
        return self._child_id

    @property
    def zone_idx(self) -> str:
        return self._zone_idx


HEAT_CLASS_BY_SLUG = class_by_attr(__name__, "_SLUG")  # e.g. CTL: Controller

_HEAT_VC_PAIR_BY_CLASS = {
    DEV_TYPE.DHW: ((I_, _1260),),
    DEV_TYPE.OTB: ((I_, _3220), (RP, _3220)),
}


def class_dev_heat(
    dev_addr: Address, *, msg: Message = None, eavesdrop: bool = False
) -> Class:
    """Return a device class, but only if the device must be from the CH/DHW group.

    May return a device class, DeviceHeat (which will need promotion).
    """

    if dev_addr.type in DEV_TYPE_MAP.THM_DEVICES:
        return HEAT_CLASS_BY_SLUG[DEV_TYPE.THM]

    try:
        slug = DEV_TYPE_MAP.slug(dev_addr.type)
    except KeyError:
        pass
    else:
        return HEAT_CLASS_BY_SLUG[slug]

    if not eavesdrop:
        raise TypeError(f"No CH/DHW class for: {dev_addr} (no eavesdropping)")

    if msg and msg.code in CODES_HEAT_ONLY:
        return DeviceHeat

    raise TypeError(f"No CH/DHW class for: {dev_addr} (unknown type: {dev_addr.type})")
