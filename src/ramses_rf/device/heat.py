#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Final

from ramses_rf import exceptions as exc
from ramses_rf.const import (
    DEV_ROLE_MAP,
    DEV_TYPE_MAP,
    DOMAIN_TYPE_MAP,
    SZ_DEVICES,
    SZ_DOMAIN_ID,
    SZ_HEAT_DEMAND,
    SZ_PRESSURE,
    SZ_RELAY_DEMAND,
    SZ_SETPOINT,
    SZ_TEMPERATURE,
    SZ_UFH_IDX,
    SZ_WINDOW_OPEN,
    SZ_ZONE_IDX,
    SZ_ZONE_MASK,
    SZ_ZONE_TYPE,
    ZON_ROLE_MAP,
    DevType,
)
from ramses_rf.entity_base import Entity, Parent, class_by_attr
from ramses_rf.helpers import shrink
from ramses_rf.schemas import SCH_TCS, SZ_ACTUATORS, SZ_CIRCUITS
from ramses_tx.address import NON_DEV_ADDR
from ramses_tx.command import Command, Priority
from ramses_tx.const import SZ_NUM_REPEATS, SZ_PRIORITY
from ramses_tx.opentherm import (
    PARAMS_MSG_IDS,
    SCHEMA_MSG_IDS,
    STATUS_MSG_IDS,
    SZ_MSG_ID,
    SZ_MSG_NAME,
    SZ_MSG_TYPE,
    SZ_VALUE,
    OtMsgType,
)
from ramses_tx.ramses import CODES_OF_HEAT_DOMAIN_ONLY, CODES_ONLY_FROM_CTL

from .base import BatteryState, Device, DeviceHeat, Fakeable

from ramses_rf.const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    F9,
    FA,
    FC,
    FF,
)

from ramses_rf.const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:
    from ramses_rf.system import Zone
    from ramses_tx import Address, Message, Packet


SZ_BURNER_HOURS: Final[str] = "burner_hours"
SZ_BURNER_STARTS: Final[str] = "burner_starts"
SZ_BURNER_FAILED_STARTS: Final[str] = "burner_failed_starts"
SZ_CH_PUMP_HOURS: Final[str] = "ch_pump_hours"
SZ_CH_PUMP_STARTS: Final[str] = "ch_pump_starts"
SZ_DHW_BURNER_HOURS: Final[str] = "dhw_burner_hours"
SZ_DHW_BURNER_STARTS: Final[str] = "dhw_burner_starts"
SZ_DHW_PUMP_HOURS: Final[str] = "dhw_pump_hours"
SZ_DHW_PUMP_STARTS: Final[str] = "dhw_pump_starts"
SZ_FLAME_SIGNAL_LOW: Final[str] = "flame_signal_low"

SZ_BOILER_OUTPUT_TEMP: Final[str] = "boiler_output_temp"
SZ_BOILER_RETURN_TEMP: Final[str] = "boiler_return_temp"
SZ_BOILER_SETPOINT: Final[str] = "boiler_setpoint"
SZ_CH_MAX_SETPOINT: Final[str] = "ch_max_setpoint"
SZ_CH_SETPOINT: Final[str] = "ch_setpoint"
SZ_CH_WATER_PRESSURE: Final[str] = "ch_water_pressure"
SZ_DHW_FLOW_RATE: Final[str] = "dhw_flow_rate"
SZ_DHW_SETPOINT: Final[str] = "dhw_setpoint"
SZ_DHW_TEMP: Final[str] = "dhw_temp"
SZ_MAX_REL_MODULATION: Final[str] = "max_rel_modulation"
SZ_OEM_CODE: Final[str] = "oem_code"
SZ_OUTSIDE_TEMP: Final[str] = "outside_temp"
SZ_REL_MODULATION_LEVEL: Final[str] = "rel_modulation_level"

SZ_CH_ACTIVE: Final[str] = "ch_active"
SZ_CH_ENABLED: Final[str] = "ch_enabled"
SZ_COOLING_ACTIVE: Final[str] = "cooling_active"
SZ_COOLING_ENABLED: Final[str] = "cooling_enabled"
SZ_DHW_ACTIVE: Final[str] = "dhw_active"
SZ_DHW_BLOCKING: Final[str] = "dhw_blocking"
SZ_DHW_ENABLED: Final[str] = "dhw_enabled"
SZ_FAULT_PRESENT: Final[str] = "fault_present"
SZ_FLAME_ACTIVE: Final[str] = "flame_active"
SZ_SUMMER_MODE: Final[str] = "summer_mode"
SZ_OTC_ACTIVE: Final[str] = "otc_active"


QOS_LOW = {SZ_PRIORITY: Priority.LOW}  # FIXME:  deprecate QoS in kwargs
QOS_MID = {SZ_PRIORITY: Priority.HIGH}  # FIXME: deprecate QoS in kwargs
QOS_MAX = {SZ_PRIORITY: Priority.HIGH, SZ_NUM_REPEATS: 3}  # FIXME: deprecate QoS...


DEV_MODE = False

_DBG_ENABLE_DEPRECATION = False

_LOGGER = logging.getLogger(__name__)


class Actuator(DeviceHeat):  # 3EF0, 3EF1 (for 10:/13:)
    # .I --- 13:109598 --:------ 13:109598 3EF0 003 00C8FF                # event-driven, 00/C8
    # RP --- 13:109598 18:002563 --:------ 0008 002 00C8                  # 00/C8, as abobe
    # RP --- 13:109598 18:002563 --:------ 3EF1 007 0000BF-00BFC8FF       # 00/C8, as above

    # RP --- 10:048122 18:140805 --:------ 3EF1 007 007FFF-003C2A10       # 10:s only RP, always 7FFF
    # RP --- 13:109598 18:199952 --:------ 3EF1 007 0001B8-01B800FF       # 13:s only RP

    # RP --- 10:047707 18:199952 --:------ 3EF0 009 001110-0A00FF-033100  # 10:s only RP
    # RP --- 10:138926 34:010253 --:------ 3EF0 006 002E11-0000FF         # 10:s only RP
    # .I --- 13:209679 --:------ 13:209679 3EF0 003 00C8FF                # 13:s only  I

    ACTUATOR_CYCLE = "actuator_cycle"
    ACTUATOR_ENABLED = "actuator_enabled"  # boolean
    ACTUATOR_STATE = "actuator_state"
    MODULATION_LEVEL = "modulation_level"  # percentage (0.0-1.0)

    def _handle_msg(self, msg: Message) -> None:  # NOTE: active
        super()._handle_msg(msg)

        if isinstance(self, OtbGateway):
            return

        if (
            msg.code == Code._3EF0
            and msg.verb == I_  # will be a 13:
            and not self.is_faked
            and not self._gwy._disable_sending
            and not self._gwy.config.disable_discovery
        ):
            # lf._make_and_send_cmd(
            #     Code._0008, qos=QOS_LOW
            # )  # FIXME: deprecate QoS in kwargs
            self._make_and_send_cmd(
                Code._3EF1, qos=QOS_LOW
            )  # FIXME: deprecate QoS in kwargs

    @property
    def actuator_cycle(self) -> dict | None:  # 3EF1
        return self._msg_value(Code._3EF1)

    @property
    def actuator_state(self) -> dict | None:  # 3EF0
        return self._msg_value(Code._3EF0)

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            self.ACTUATOR_CYCLE: self.actuator_cycle,
            self.ACTUATOR_STATE: self.actuator_state,
        }


class HeatDemand(DeviceHeat):  # 3150
    HEAT_DEMAND = SZ_HEAT_DEMAND  # percentage valve open (0.0-1.0)

    @property
    def heat_demand(self) -> float | None:  # 3150
        return self._msg_value(Code._3150, key=self.HEAT_DEMAND)

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            self.HEAT_DEMAND: self.heat_demand,
        }


class Setpoint(DeviceHeat):  # 2309
    SETPOINT = SZ_SETPOINT  # degrees Celsius

    @property
    def setpoint(self) -> float | None:  # 2309
        return self._msg_value(Code._2309, key=self.SETPOINT)

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            self.SETPOINT: self.setpoint,
        }


class Weather(DeviceHeat):  # 0002
    TEMPERATURE = SZ_TEMPERATURE  # TODO: deprecate

    @property
    def temperature(self) -> float | None:  # 0002
        return self._msg_value(Code._0002, key=SZ_TEMPERATURE)

    @temperature.setter
    def temperature(self, value: float | None) -> None:
        if not self.is_faked:
            raise RuntimeError(f"Faking is not enabled for {self}")
        self._send_cmd(Command.put_outdoor_temp(self.id, value))

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class RelayDemand(DeviceHeat):  # 0008
    # .I --- 01:054173 --:------ 01:054173 1FC9 018 03-0008-04D39D FC-3B00-04D39D 03-1FC9-04D39D
    # .W --- 13:123456 01:054173 --:------ 1FC9 006 00-3EF0-35E240
    # .I --- 01:054173 13:123456 --:------ 1FC9 006 00-FFFF-04D39D

    # Some either 00/C8, others 00-C8
    # .I --- 01:145038 --:------ 01:145038 0008 002 0314  # ZON valve zone (ELE too?)
    # .I --- 01:145038 --:------ 01:145038 0008 002 F914  # HTG valve
    # .I --- 01:054173 --:------ 01:054173 0008 002 FA00  # DHW valve
    # .I --- 01:145038 --:------ 01:145038 0008 002 FC14  # appliance_relay

    # RP --- 13:109598 18:199952 --:------ 0008 002 0000
    # RP --- 13:109598 18:199952 --:------ 0008 002 00C8

    RELAY_DEMAND = SZ_RELAY_DEMAND  # percentage (0.0-1.0)

    def _setup_discovery_cmds(self) -> None:
        super()._setup_discovery_cmds()

        if not self.is_faked:  # discover_flag & Discover.STATUS and
            self._add_discovery_cmd(Command.get_relay_demand(self.id), 60 * 15)

    @property
    def relay_demand(self) -> float | None:  # 0008
        return self._msg_value(Code._0008, key=self.RELAY_DEMAND)

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            self.RELAY_DEMAND: self.relay_demand,
        }


class DhwTemperature(DeviceHeat):  # 1260
    TEMPERATURE = SZ_TEMPERATURE  # TODO: deprecate

    async def initiate_binding_process(self) -> Packet:
        return await super().initiate_binding_process(Code._1260)

    @property
    def temperature(self) -> float | None:  # 1260
        return self._msg_value(Code._1260, key=SZ_TEMPERATURE)

    @temperature.setter
    def temperature(self, value: float | None) -> None:
        if not self.is_faked:
            raise RuntimeError(f"Faking is not enabled for {self}")
        self._send_cmd(Command.put_dhw_temp(self.id, value))

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            self.TEMPERATURE: self.temperature,
        }


class Temperature(DeviceHeat):  # 30C9
    # .I --- 34:145039 --:------ 34:145039 1FC9 012 00-30C9-8A368F 00-1FC9-8A368F
    # .W --- 01:054173 34:145039 --:------ 1FC9 006 03-2309-04D39D  # real CTL
    # .I --- 34:145039 01:054173 --:------ 1FC9 006 00-30C9-8A368F
    @property
    def temperature(self) -> float | None:  # 30C9
        return self._msg_value(Code._30C9, key=SZ_TEMPERATURE)

    @temperature.setter
    def temperature(self, value: float | None) -> None:
        if not self.is_faked:
            raise RuntimeError(f"Faking is not enabled for {self}")
        self._send_cmd(Command.put_sensor_temp(self.id, value))

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            SZ_TEMPERATURE: self.temperature,
        }


class RfgGateway(DeviceHeat):  # RFG (30:)
    """The RFG100 base class."""

    _SLUG: str = DevType.RFG


class Controller(DeviceHeat):  # CTL (01):
    """The Controller base class."""

    _SLUG: str = DevType.CTL

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

            from ramses_rf.system import system_factory

            schema = shrink(SCH_TCS(schema))

            if not self.tcs:
                self.tcs = system_factory(self, msg=msg, **schema)

            elif schema:
                self.tcs._update_schema(**schema)

            if msg:
                self.tcs._handle_msg(msg)
            return self.tcs

        super()._make_tcs_controller(msg=None, **schema)

        self.tcs = get_system(msg=msg, **schema)


class Programmer(Controller):  # PRG (23):
    """The Controller base class."""

    _SLUG: str = DevType.PRG


class UfhController(Parent, DeviceHeat):  # UFC (02):
    """The UFC class, the HCE80 that controls the UFH zones."""

    _SLUG: str = DevType.UFC

    HEAT_DEMAND = SZ_HEAT_DEMAND

    _STATE_ATTR = SZ_HEAT_DEMAND

    # 12:27:24.398 067  I --- 02:000921 --:------ 01:191718 3150 002 0360
    # 12:27:24.546 068  I --- 02:000921 --:------ 01:191718 3150 002 065A
    # 12:27:24.693 067  I --- 02:000921 --:------ 01:191718 3150 002 045C
    # 12:27:24.824 059  I --- 01:191718 --:------ 01:191718 3150 002 FC5C
    # 12:27:24.857 067  I --- 02:000921 --:------ 02:000921 3150 006 0060-015A-025C

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._child_id = FA  # NOTE: domain_id, UFC

        self.circuit_by_id = {f"{i:02X}": {} for i in range(8)}

        self._setpoints: Message = None  # type: ignore[assignment]
        self._heat_demand: Message = None  # type: ignore[assignment]
        self._heat_demands: Message = None  # type: ignore[assignment]
        self._relay_demand: Message = None  # type: ignore[assignment]
        self._relay_demand_fa: Message = None  # type: ignore[assignment]

        self._iz_controller = True

    def _setup_discovery_cmds(self) -> None:
        super()._setup_discovery_cmds()

        # Only RPs are: 0001, 0005/000C, 10E0, 000A/2309 & 22D0

        cmd = Command.from_attrs(RQ, self.id, Code._0005, f"00{DEV_ROLE_MAP.UFH}")
        self._add_discovery_cmd(cmd, 60 * 60 * 24)

        # TODO: this needs work
        # if discover_flag & Discover.PARAMS:  # only 2309 has any potential?
        for ufc_idx in self.circuit_by_id:
            cmd = Command.get_zone_config(self.id, ufc_idx)
            self._add_discovery_cmd(cmd, 60 * 60 * 6)

            cmd = Command.get_zone_setpoint(self.id, ufc_idx)
            self._add_discovery_cmd(cmd, 60 * 60 * 6)

        for ufc_idx in range(8):  # type: ignore[assignment]
            payload = f"{ufc_idx:02X}{DEV_ROLE_MAP.UFH}"
            cmd = Command.from_attrs(RQ, self.id, Code._000C, payload)
            self._add_discovery_cmd(cmd, 60 * 60 * 24)

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        # Several assumptions ar emade, regarding 000C pkts:
        # - UFC bound only to CTL (not, e.g. SEN)
        # - all circuits bound to the same controller

        if msg.code == Code._0005:  # system_zones
            # {'zone_type': '09', 'zone_mask': [1, 1, 1, 1, 1, 0, 0, 0], 'zone_class': 'underfloor_heating'}

            if msg.payload[SZ_ZONE_TYPE] not in (ZON_ROLE_MAP.ACT, ZON_ROLE_MAP.UFH):
                return  # ignoring ZON_ROLE_MAP.SEN for now

            for idx, flag in enumerate(msg.payload[SZ_ZONE_MASK]):
                ufh_idx = f"{idx:02X}"
                if not flag:
                    self.circuit_by_id[ufh_idx] = {SZ_ZONE_IDX: None}
                elif SZ_ZONE_IDX not in self.circuit_by_id[ufh_idx]:
                    self._make_and_send_cmd(
                        Code._000C, payload=f"{ufh_idx}{DEV_ROLE_MAP.UFH}"
                    )

        elif msg.code == Code._0008:  # relay_demand, TODO: use msg DB?
            if msg.payload.get(SZ_DOMAIN_ID) == FC:
                self._relay_demand = msg
            else:  # FA
                self._relay_demand_fa = msg

        elif msg.code == Code._000C:  # zone_devices
            # {'zone_type': '09', 'ufh_idx': '00', 'zone_idx': '09', 'device_role': 'ufh_actuator', 'devices': ['01:095421']}
            # {'zone_type': '09', 'ufh_idx': '07', 'zone_idx': None, 'device_role': 'ufh_actuator', 'devices': []}

            if msg.payload[SZ_ZONE_TYPE] not in (ZON_ROLE_MAP.ACT, ZON_ROLE_MAP.UFH):
                return  # ignoring ZON_ROLE_MAP.SEN for now

            ufh_idx = msg.payload[SZ_UFH_IDX]  # circuit idx
            self.circuit_by_id[ufh_idx] = {SZ_ZONE_IDX: msg.payload[SZ_ZONE_IDX]}
            if msg.payload[SZ_ZONE_IDX] is not None:  # [SZ_DEVICES][0] will be the CTL
                self.set_parent(
                    self._gwy.get_device(msg.payload[SZ_DEVICES][0]).tcs,
                    # child_id=msg.payload[SZ_ZONE_IDX],
                )

        elif msg.code == Code._22C9:  # setpoint_bounds
            # .I --- 02:017205 --:------ 02:017205 22C9 024 00076C0A280101076C0A28010...
            # .I --- 02:017205 --:------ 02:017205 22C9 006 04076C0A2801
            self._setpoints = msg

        elif msg.code == Code._3150:  # heat_demands
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

        # elif msg.code not in (Code._10E0, Code._22D0):
        #     print("xxx")

        # "0008|FA/FC", "22C9|array", "22D0|none", "3150|ZZ/array(/FC?)"

    def get_circuit(self, cct_idx, *, msg=None, **schema) -> Any:
        """Return a UFH circuit, create it if required.

        First, use the schema to create/update it, then pass it any msg to handle.

        Circuits are uniquely identified by a UFH controller ID|cct_idx pair.
        If a circuit is created, attach it to this UFC.
        """

        schema = {}  # shrink(SCH_CCT(schema))

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

    # @property
    # def circuits(self) -> dict:  # 000C
    #     return self.circuit_by_id

    @property
    def heat_demand(self) -> float | None:  # 3150|FC (there is also 3150|FA)
        return self._msg_value_msg(self._heat_demand, key=self.HEAT_DEMAND)

    @property
    def heat_demands(self) -> dict | None:  # 3150|ufh_idx array
        # return self._heat_demands.payload if self._heat_demands else None
        return self._msg_value_msg(self._heat_demands)

    @property
    def relay_demand(self) -> dict | None:  # 0008|FC
        return self._msg_value_msg(self._relay_demand, key=SZ_RELAY_DEMAND)

    @property
    def relay_demand_fa(self) -> dict | None:  # 0008|FA
        return self._msg_value_msg(self._relay_demand_fa, key=SZ_RELAY_DEMAND)

    @property
    def setpoints(self) -> dict | None:  # 22C9|ufh_idx array
        if self._setpoints is None:
            return

        return {
            c[SZ_UFH_IDX]: {
                k: v for k, v in c.items() if k in ("temp_low", "temp_high")
            }
            for c in self._setpoints.payload
        }

    @property  # id, type
    def schema(self) -> dict[str, Any]:
        return {
            **super().schema,
            SZ_CIRCUITS: self.circuit_by_id,
        }

    @property  # setpoint, config, mode (not schedule)
    def params(self) -> dict[str, Any]:
        return {
            **super().params,
            SZ_CIRCUITS: self.setpoints,
        }

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            SZ_HEAT_DEMAND: self.heat_demand,
            SZ_RELAY_DEMAND: self.relay_demand,
            f"{SZ_RELAY_DEMAND}_fa": self.relay_demand_fa,
        }


class DhwSensor(DhwTemperature, BatteryState, Fakeable):  # DHW (07): 10A0, 1260
    """The DHW class, such as a CS92."""

    _SLUG: str = DevType.DHW

    DHW_PARAMS = "dhw_params"
    TEMPERATURE = SZ_TEMPERATURE

    _STATE_ATTR = SZ_TEMPERATURE

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._child_id = FA  # NOTE: domain_id

    def _handle_msg(self, msg: Message) -> None:  # NOTE: active
        super()._handle_msg(msg)

        # The following is required, as CTLs don't send such every sync_cycle
        if msg.code == Code._1260 and self.ctl and not self._gwy._disable_sending:
            # update the controller DHW temp
            self._send_cmd(Command.get_dhw_temp(self.ctl.id))

    @property
    def dhw_params(self) -> dict | None:  # 10A0
        return self._msg_value(Code._10A0)

    @property
    def params(self) -> dict[str, Any]:
        return {
            **super().params,
            self.DHW_PARAMS: self.dhw_params,
        }


class OutSensor(Weather, Fakeable):  # OUT: 17
    """The OUT class (external sensor), such as a HB85/HB95."""

    _SLUG: str = DevType.OUT

    # LUMINOSITY = "luminosity"  # lux
    # WINDSPEED = "windspeed"  # km/h

    _STATE_ATTR = SZ_TEMPERATURE


# NOTE: config.use_native_ot should enforces sends, but not reads from ._msgz DB
class OtbGateway(Actuator, HeatDemand):  # OTB (10): 3220 (22D9, others)
    """The OTB class, specifically an OpenTherm Bridge (R8810A Bridge)."""

    # see: https://www.opentherm.eu/request-details/?post_ids=2944
    # see: https://www.automatedhome.co.uk/vbulletin/showthread.php?6400-(New)-cool-mode-in-Evohome

    _SLUG: str = DevType.OTB

    _STATE_ATTR = SZ_REL_MODULATION_LEVEL

    OT_TO_RAMSES: dict[str, Code] = {  # TODO: move to opentherm.py
        "00": Code._3EF0,  # master/slave status (actuator_state)
        "01": Code._22D9,  # boiler_setpoint
        "0E": Code._3EF0,  # max_rel_modulation_level (is a PARAM?)
        "11": Code._3EF0,  # rel_modulation_level (actuator_state, also Code._3EF1)
        "12": Code._1300,  # ch_water_pressure
        "13": Code._12F0,  # dhw_flow_rate
        "19": Code._3200,  # boiler_output_temp
        "1A": Code._1260,  # dhw_temp
        "1B": Code._1290,  # outside_temp
        "1C": Code._3210,  # boiler_return_temp
        "38": Code._10A0,  # dhw_setpoint (is a PARAM)
        "39": Code._1081,  # ch_max_setpoint (is a PARAM)
    }
    RAMSES_TO_OT: dict[Code, str] = {
        v: k for k, v in OT_TO_RAMSES.items() if v != Code._3EF0
    }  # also 10A0?

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._child_id = FC  # NOTE: domain_id

        self._msgz[str(Code._3220)] = {RP: {}}  # self._msgz[Code._3220][RP][msg_id]

        # lf._use_ot = self._gwy.config.use_native_ot
        self._msgs_ot: dict[str, Message] = {}
        # lf._msgs_ot_ctl_polled = {}

    def _setup_discovery_cmds(self) -> None:
        def which_cmd(use_native_ot: str, msg_id: str) -> Command | None:
            """Create a OT cmd, or its RAMSES equivalent, depending."""
            # we know RQ|3220 is an option, question is: use that, or RAMSES or nothing?
            if use_native_ot in ("always", "prefer"):
                return Command.get_opentherm_data(self.id, msg_id)
            if msg_id in self.OT_TO_RAMSES:  # is: in ("avoid", "never")
                return Command.from_attrs(RQ, self.id, self.OT_TO_RAMSES[msg_id], "00")
            if use_native_ot == "avoid":
                return Command.get_opentherm_data(self.id, msg_id)
            return None  # use_native_ot == "never"

        super()._setup_discovery_cmds()

        # always send at least one of RQ|3EF0 or RQ|3220|00 (status)
        if self._gwy.config.use_native_ot != "never":
            self._add_discovery_cmd(Command.get_opentherm_data(self.id, "00"), 60)

        if self._gwy.config.use_native_ot != "always":
            self._add_discovery_cmd(
                Command.from_attrs(RQ, self.id, Code._3EF0, "00"), 60
            )

        for _msg_id in SCHEMA_MSG_IDS:  # From OT v2.2: version numbers
            if cmd := which_cmd(self._gwy.config.use_native_ot, f"{_msg_id:02X}"):
                self._add_discovery_cmd(cmd, 6 * 3600, delay=180)

        for _msg_id in PARAMS_MSG_IDS:  # params or L/T state
            if cmd := which_cmd(self._gwy.config.use_native_ot, f"{_msg_id:02X}"):
                self._add_discovery_cmd(cmd, 3600, delay=90)

        for _msg_id in STATUS_MSG_IDS:  # except "00", see above
            if _msg_id == 0x00:
                continue
            if cmd := which_cmd(self._gwy.config.use_native_ot, f"{_msg_id:02X}"):
                self._add_discovery_cmd(cmd, 300, delay=15)

        if False and DEV_MODE:  # TODO: these are WIP, but do vary in payload
            for code in (
                Code._2401,  # WIP - modulation_level + flags?
                Code._3221,  # R8810A/20A
                Code._3223,  # R8810A/20A
            ):
                self._add_discovery_cmd(Command.from_attrs(RQ, self.id, code, "00"), 60)

        if False and DEV_MODE:  # TODO: these are WIP, appear FIXED in payload
            for code in (
                Code._0150,  # payload always "000000", R8820A only?
                Code._1098,  # payload always "00C8",   R8820A only?
                Code._10B0,  # payload always "0000",   R8820A only?
                Code._1FD0,  # payload always "0000000000000000"
                Code._2400,  # payload always "0000000F"
                Code._2410,  # payload always "000000000000000000000000010000000100000C"
                Code._2420,  # payload always "0000001000000...
            ):  # TODO: to test against BDR91T
                self._add_discovery_cmd(
                    Command.from_attrs(RQ, self.id, code, "00"), 300
                )

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        if msg.verb not in (I_, RP):
            return

        if msg.code == Code._3220:
            self._handle_3220(msg)
        elif msg.code in self.RAMSES_TO_OT:
            self._handle_code(msg)

    def _handle_3220(self, msg: Message) -> None:
        """Handle 3220-based messages."""

        # NOTE: Reserved msgs have null data, but that msg_id may later be OK!
        if msg.payload[SZ_MSG_TYPE] == OtMsgType.RESERVED:
            return

        # NOTE: Some msgs have invalid data, but that msg_id may later be OK!
        if msg.payload.get(SZ_VALUE) is None:
            return

        msg_id: int = msg.payload[SZ_MSG_ID]  # msg_id is int in payload/opentherm.py
        self._msgs_ot[f"{msg_id:02X}"] = msg  # but is str is in this module

        if not _DBG_ENABLE_DEPRECATION:  # FIXME: data gaps
            return

        reset = msg.payload[SZ_MSG_TYPE] not in (
            OtMsgType.DATA_INVALID,
            OtMsgType.UNKNOWN_DATAID,
            OtMsgType.RESERVED,  # but some are ?always reserved
        )
        self.deprecate_code_ctx(msg._pkt, ctx=msg_id, reset=reset)

    def _handle_code(self, msg: Message) -> None:
        """Handle non-3220-based messages."""

        if msg.code == Code._3EF0 and msg.verb == I_:
            # NOTE: this is development/discovery code  # chasing flags
            # self._send_cmd(
            #     Command.get_opentherm_data(self.id, "00"), **QOS_MID
            # )  # FIXME: deprecate QoS in kwargs
            return

        if msg.code in (Code._10A0, Code._3EF1):
            return

        if not _DBG_ENABLE_DEPRECATION:  # FIXME: data gaps
            return

        # TODO: can be temporarily 7FFF?
        if msg._pkt.payload[2:] == "7FFF" or (
            msg.code == Code._1300 and msg._pkt.payload[2:] == "09F6"
        ):  # latter is CH water pressure
            self.deprecate_code_ctx(msg._pkt)
        else:
            self.deprecate_code_ctx(msg._pkt, reset=True)

    def _ot_msg_flag(self, msg_id: str, flag_idx: int) -> bool | None:
        if flags := self._ot_msg_value(msg_id):
            return bool(flags[flag_idx])
        return None

    @staticmethod
    def _ot_msg_name(msg) -> str:  # TODO: remove
        return (
            msg.payload[SZ_MSG_NAME]
            if isinstance(msg.payload[SZ_MSG_NAME], str)
            else f"{msg.payload[SZ_MSG_ID]:02X}"
        )

    def _ot_msg_value(self, msg_id: str) -> int | float | list | None:
        # data_id = int(msg_id, 16)
        if (msg := self._msgs_ot.get(msg_id)) and not msg._expired:
            return msg.payload.get(SZ_VALUE)  # TODO: value_hb/_lb

    def _result_by_callback(
        self, cbk_ot: Callable | None, cbk_ramses: Callable | None
    ) -> Any | None:
        """Return a value using OpenTherm or RAMSES as per `config.use_native_ot`."""

        if self._gwy.config.use_native_ot == "always":
            return cbk_ot() if cbk_ot else None
        if self._gwy.config.use_native_ot == "prefer":
            if cbk_ot and (result := cbk_ot()) is not None:
                return result

        result_ramses = cbk_ramses() if cbk_ramses is not None else None
        if self._gwy.config.use_native_ot == "avoid" and result_ramses is None:
            return cbk_ot() if cbk_ot else None
        return result_ramses  # incl. use_native_ot == "never"

    def _result_by_lookup(
        self,
        code,
        /,
        *,
        key: str,
    ) -> Any | None:
        """Return a value using OpenTherm or RAMSES as per `config.use_native_ot`."""
        # assert code in self.RAMSES_TO_OT and kwargs.get("key"):

        if self._gwy.config.use_native_ot == "always":
            return self._ot_msg_value(self.RAMSES_TO_OT[code])

        if self._gwy.config.use_native_ot == "prefer":
            if (result_ot := self._ot_msg_value(self.RAMSES_TO_OT[code])) is not None:
                return result_ot

        result_ramses = self._msg_value(code, key=key)
        if self._gwy.config.use_native_ot == "avoid" and result_ramses is None:
            return self._ot_msg_value(self.RAMSES_TO_OT[code])

        return result_ramses  # incl. use_native_ot == "never"

    def _result_by_value(
        self, result_ot: Any | None, result_ramses: Any | None
    ) -> Any | None:
        """Return a value using OpenTherm or RAMSES as per `config.use_native_ot`."""
        #

        if self._gwy.config.use_native_ot == "always":
            return result_ot

        if self._gwy.config.use_native_ot == "prefer":
            if result_ot is not None:
                return result_ot

        #
        elif self._gwy.config.use_native_ot == "avoid" and result_ramses is None:
            return result_ot

        return result_ramses  # incl. use_native_ot == "never"

    @property  # TODO
    def bit_2_4(self) -> bool | None:  # 2401 - WIP
        return self._msg_flag(Code._2401, "_flags_2", 4)

    @property  # TODO
    def bit_2_5(self) -> bool | None:  # 2401 - WIP
        return self._msg_flag(Code._2401, "_flags_2", 5)

    @property  # TODO
    def bit_2_6(self) -> bool | None:  # 2401 - WIP
        return self._msg_flag(Code._2401, "_flags_2", 6)

    @property  # TODO
    def bit_2_7(self) -> bool | None:  # 2401 - WIP
        return self._msg_flag(Code._2401, "_flags_2", 7)

    @property  # TODO
    def bit_3_7(self) -> bool | None:  # 3EF0 (byte 3, only OTB)
        return self._msg_flag(Code._3EF0, "_flags_3", 7)

    @property  # TODO
    def bit_6_6(self) -> bool | None:  # 3EF0 ?dhw_enabled (byte 3, only R8820A?)
        return self._msg_flag(Code._3EF0, "_flags_6", 6)

    @property  # TODO
    def percent(self) -> float | None:  # 2401 - WIP (~3150|FC)
        return self._msg_value(Code._2401, key=SZ_HEAT_DEMAND)

    @property  # TODO
    def value(self) -> int | None:  # 2401 - WIP
        return self._msg_value(Code._2401, key="_value_2")

    @property
    def boiler_output_temp(self) -> float | None:  # 3220|19, or 3200
        # _LOGGER.warning(
        #     "code=%s, 3220=%s, both=%s",
        #     self._msg_value(Code._3200, key=SZ_TEMPERATURE),
        #     self._ot_msg_value(str(self.RAMSES_TO_OT[Code._3200])),
        #     self._result_by_lookup(Code._3200, key=SZ_TEMPERATURE),
        # )

        return self._result_by_lookup(Code._3200, key=SZ_TEMPERATURE)

    @property
    def boiler_return_temp(self) -> float | None:  # 3220|1C, or 3210
        return self._result_by_lookup(Code._3210, key=SZ_TEMPERATURE)

    @property
    def boiler_setpoint(self) -> float | None:  # 3220|01, or 22D9
        return self._result_by_lookup(Code._22D9, key=SZ_SETPOINT)

    @property
    def ch_max_setpoint(self) -> float | None:  # 3220|39, or 1081
        return self._result_by_lookup(Code._1081, key=SZ_SETPOINT)

    @property  # TODO: no OT equivalent
    def ch_setpoint(self) -> float | None:  # 3EF0 (byte 7, only R8820A?)
        return self._result_by_value(
            None, self._msg_value(Code._3EF0, key=SZ_CH_SETPOINT)
        )

    @property
    def ch_water_pressure(self) -> float | None:  # 3220|12, or 1300
        return self._result_by_lookup(Code._1300, key=SZ_PRESSURE)

    @property
    def dhw_flow_rate(self) -> float | None:  # 3220|13, or 12F0
        return self._result_by_lookup(Code._12F0, key=SZ_DHW_FLOW_RATE)

    @property
    def dhw_setpoint(self) -> float | None:  # 3220|38, or 10A0
        return self._result_by_lookup(Code._10A0, key=SZ_SETPOINT)

    @property
    def dhw_temp(self) -> float | None:  # 3220|1A, or 1260
        return self._result_by_lookup(Code._1260, key=SZ_TEMPERATURE)

    @property  # TODO: no reliable OT equivalent?
    def max_rel_modulation(self) -> float | None:  # 3220|0E, or 3EF0 (byte 8)
        if self._gwy.config.use_native_ot == "prefer":  # HACK: there'll always be 3EF0
            return self._msg_value(Code._3EF0, key=SZ_MAX_REL_MODULATION)
        return self._result_by_value(
            self._ot_msg_value("0E"),  # NOTE: not reliable?
            self._msg_value(Code._3EF0, key=SZ_MAX_REL_MODULATION),
        )

    @property
    def oem_code(self) -> float | None:  # 3220|73, no known RAMSES equivalent
        return self._ot_msg_value("73")

    @property
    def outside_temp(self) -> float | None:  # 3220|1B, 1290
        return self._result_by_lookup(Code._1290, key=SZ_TEMPERATURE)

    @property  # TODO: no reliable OT equivalent?
    def rel_modulation_level(self) -> float | None:  # 3220|11, or 3EF0/3EF1
        if self._gwy.config.use_native_ot == "prefer":  # HACK: there'll always be 3EF0
            return self._msg_value((Code._3EF0, Code._3EF1), key=self.MODULATION_LEVEL)
        return self._result_by_value(
            self._ot_msg_value("11"),  # NOTE: not reliable?
            self._msg_value((Code._3EF0, Code._3EF1), key=self.MODULATION_LEVEL),
        )

    @property  # TODO: no reliable OT equivalent?
    def ch_active(self) -> bool | None:  # 3220|00, or 3EF0 (byte 3)
        if self._gwy.config.use_native_ot == "prefer":  # HACK: there'll always be 3EF0
            return self._msg_value(Code._3EF0, key=SZ_CH_ACTIVE)
        return self._result_by_value(
            self._ot_msg_flag("00", 8 + 1),  # NOTE: not reliable?
            self._msg_value(Code._3EF0, key=SZ_CH_ACTIVE),
        )

    @property  # TODO: no reliable OT equivalent?
    def ch_enabled(self) -> bool | None:  # 3220|00, or 3EF0 (byte 6)
        if self._gwy.config.use_native_ot == "prefer":  # HACK: there'll always be 3EF0
            return self._msg_value(Code._3EF0, key=SZ_CH_ENABLED)
        return self._result_by_value(
            self._ot_msg_flag("00", 0),  # NOTE: not reliable?
            self._msg_value(Code._3EF0, key=SZ_CH_ENABLED),
        )

    @property
    def cooling_active(self) -> bool | None:  # 3220|00, TODO: no known RAMSES
        return self._result_by_value(self._ot_msg_flag("00", 8 + 4), None)

    @property
    def cooling_enabled(self) -> bool | None:  # 3220|00, TODO: no known RAMSES
        return self._result_by_value(self._ot_msg_flag("00", 2), None)

    @property  # TODO: no reliable OT equivalent?
    def dhw_active(self) -> bool | None:  # 3220|00, or 3EF0 (byte 3)
        if self._gwy.config.use_native_ot == "prefer":  # HACK: there'll always be 3EF0
            return self._msg_value(Code._3EF0, key=SZ_DHW_ACTIVE)
        return self._result_by_value(
            self._ot_msg_flag("00", 8 + 2),  # NOTE: not reliable?
            self._msg_value(Code._3EF0, key=SZ_DHW_ACTIVE),
        )

    @property
    def dhw_blocking(self) -> bool | None:  # 3220|00, TODO: no known RAMSES
        return self._result_by_value(self._ot_msg_flag("00", 6), None)

    @property
    def dhw_enabled(self) -> bool | None:  # 3220|00, TODO: no known RAMSES
        return self._result_by_value(self._ot_msg_flag("00", 1), None)

    @property
    def fault_present(self) -> bool | None:  # 3220|00, TODO: no known RAMSES
        return self._result_by_value(self._ot_msg_flag("00", 8), None)

    @property  # TODO: no reliable OT equivalent?
    def flame_active(self) -> bool | None:  # 3220|00, or 3EF0 (byte 3)
        if self._gwy.config.use_native_ot == "prefer":  # HACK: there'll always be 3EF0
            return self._msg_value(Code._3EF0, key="flame_on")
        return self._result_by_value(
            self._ot_msg_flag("00", 8 + 3),  # NOTE: not reliable?
            self._msg_value(Code._3EF0, key="flame_on"),
        )

    @property
    def otc_active(self) -> bool | None:  # 3220|00, TODO: no known RAMSES
        return self._result_by_value(self._ot_msg_flag("00", 3), None)

    @property
    def summer_mode(self) -> bool | None:  # 3220|00, TODO: no known RAMSES
        return self._result_by_value(self._ot_msg_flag("00", 5), None)

    @property
    def opentherm_schema(self) -> dict:
        result = {
            self._ot_msg_name(v): v.payload
            for k, v in self._msgs_ot.items()
            if self._supported_cmds_ctx.get(int(k, 16)) and int(k, 16) in (3, 6, 127)
        }
        return {
            m: {k: v for k, v in p.items() if k.startswith(SZ_VALUE)}
            for m, p in result.items()
        }

    @property
    def opentherm_counters(self) -> dict:
        # for msg_id in ("71", "72", ...):
        return {
            SZ_BURNER_HOURS: self._ot_msg_value("78"),
            SZ_BURNER_STARTS: self._ot_msg_value("74"),
            SZ_BURNER_FAILED_STARTS: self._ot_msg_value("71"),
            SZ_CH_PUMP_HOURS: self._ot_msg_value("79"),
            SZ_CH_PUMP_STARTS: self._ot_msg_value("75"),
            SZ_DHW_BURNER_HOURS: self._ot_msg_value("7B"),
            SZ_DHW_BURNER_STARTS: self._ot_msg_value("77"),
            SZ_DHW_PUMP_HOURS: self._ot_msg_value("7A"),
            SZ_DHW_PUMP_STARTS: self._ot_msg_value("76"),
            SZ_FLAME_SIGNAL_LOW: self._ot_msg_value("72"),
        }  # 0x73 is OEM diagnostic code...

    @property
    def opentherm_params(self) -> dict:
        result = {
            self._ot_msg_name(v): v.payload
            for k, v in self._msgs_ot.items()
            if self._supported_cmds_ctx.get(k) and k in PARAMS_MSG_IDS
        }
        return {
            m: {k: v for k, v in p.items() if k.startswith(SZ_VALUE)}
            for m, p in result.items()
        }

    @property
    def opentherm_status(self) -> dict:
        return {  # most these are in: STATUS_MSG_IDS
            SZ_BOILER_OUTPUT_TEMP: self._ot_msg_value("19"),
            SZ_BOILER_RETURN_TEMP: self._ot_msg_value("1C"),
            SZ_BOILER_SETPOINT: self._ot_msg_value("01"),
            # SZ_CH_MAX_SETPOINT: self._ot_msg_value("39"),  # in PARAMS_MSG_IDS
            SZ_CH_WATER_PRESSURE: self._ot_msg_value("12"),
            SZ_DHW_FLOW_RATE: self._ot_msg_value("13"),
            # SZ_DHW_SETPOINT: self._ot_msg_value("38"),  # in PARAMS_MSG_IDS
            SZ_DHW_TEMP: self._ot_msg_value("1A"),
            SZ_OEM_CODE: self._ot_msg_value("73"),
            SZ_OUTSIDE_TEMP: self._ot_msg_value("1B"),
            SZ_REL_MODULATION_LEVEL: self._ot_msg_value("11"),
            #
            # SZ...: self._ot_msg_value("05"),  # in STATUS_MSG_IDS
            # SZ...: self._ot_msg_value("18"),  # in STATUS_MSG_IDS
            #
            SZ_CH_ACTIVE: self._ot_msg_flag("00", 8 + 1),
            SZ_CH_ENABLED: self._ot_msg_flag("00", 0),
            SZ_COOLING_ACTIVE: self._ot_msg_flag("00", 8 + 4),
            SZ_COOLING_ENABLED: self._ot_msg_flag("00", 2),
            SZ_DHW_ACTIVE: self._ot_msg_flag("00", 8 + 2),
            SZ_DHW_BLOCKING: self._ot_msg_flag("00", 6),
            SZ_DHW_ENABLED: self._ot_msg_flag("00", 1),
            SZ_FAULT_PRESENT: self._ot_msg_flag("00", 8),
            SZ_FLAME_ACTIVE: self._ot_msg_flag("00", 8 + 3),
            SZ_SUMMER_MODE: self._ot_msg_flag("00", 5),
            SZ_OTC_ACTIVE: self._ot_msg_flag("00", 3),
        }

    @property
    def ramses_schema(self) -> dict:
        return {}

    @property
    def ramses_params(self) -> dict:
        return {
            SZ_MAX_REL_MODULATION: self.max_rel_modulation,
        }

    @property
    def ramses_status(self) -> dict:
        return {
            SZ_BOILER_OUTPUT_TEMP: self._msg_value(Code._3200, key=SZ_TEMPERATURE),
            SZ_BOILER_RETURN_TEMP: self._msg_value(Code._3210, key=SZ_TEMPERATURE),
            SZ_BOILER_SETPOINT: self._msg_value(Code._22D9, key=SZ_SETPOINT),
            SZ_CH_MAX_SETPOINT: self._msg_value(Code._1081, key=SZ_SETPOINT),
            SZ_CH_SETPOINT: self._msg_value(Code._3EF0, key=SZ_CH_SETPOINT),
            SZ_CH_WATER_PRESSURE: self._msg_value(Code._1300, key=SZ_PRESSURE),
            SZ_DHW_FLOW_RATE: self._msg_value(Code._12F0, key=SZ_DHW_FLOW_RATE),
            SZ_DHW_SETPOINT: self._msg_value(Code._1300, key=SZ_SETPOINT),
            SZ_DHW_TEMP: self._msg_value(Code._1260, key=SZ_TEMPERATURE),
            SZ_OUTSIDE_TEMP: self._msg_value(Code._1290, key=SZ_TEMPERATURE),
            SZ_REL_MODULATION_LEVEL: self._msg_value(
                (Code._3EF0, Code._3EF1), key=self.MODULATION_LEVEL
            ),
            #
            SZ_CH_ACTIVE: self._msg_value(Code._3EF0, key=SZ_CH_ACTIVE),
            SZ_CH_ENABLED: self._msg_value(Code._3EF0, key=SZ_CH_ENABLED),
            SZ_DHW_ACTIVE: self._msg_value(Code._3EF0, key=SZ_DHW_ACTIVE),
            SZ_FLAME_ACTIVE: self._msg_value(Code._3EF0, key=SZ_FLAME_ACTIVE),
        }

    @property
    def traits(self) -> dict[str, Any]:
        return {
            **super().traits,
            "opentherm_traits": self.supported_cmds_ot,
            "ramses_ii_traits": self.supported_cmds,
        }

    @property
    def schema(self) -> dict[str, Any]:
        return {
            **super().schema,
            "opentherm_schema": self.opentherm_schema,
            "ramses_ii_schema": self.ramses_schema,
        }

    @property
    def params(self) -> dict[str, Any]:
        return {
            **super().params,
            "opentherm_params": self.opentherm_params,
            "ramses_ii_params": self.ramses_params,
        }

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,  # incl. actuator_cycle, actuator_state
            #
            SZ_BOILER_OUTPUT_TEMP: self.boiler_output_temp,
            SZ_BOILER_RETURN_TEMP: self.boiler_return_temp,
            SZ_BOILER_SETPOINT: self.boiler_setpoint,
            SZ_CH_SETPOINT: self.ch_setpoint,
            SZ_CH_MAX_SETPOINT: self.ch_max_setpoint,
            SZ_CH_WATER_PRESSURE: self.ch_water_pressure,
            SZ_DHW_FLOW_RATE: self.dhw_flow_rate,
            SZ_DHW_SETPOINT: self.dhw_setpoint,
            SZ_DHW_TEMP: self.dhw_temp,
            SZ_OEM_CODE: self.oem_code,
            SZ_OUTSIDE_TEMP: self.outside_temp,
            SZ_REL_MODULATION_LEVEL: self.rel_modulation_level,
            #
            SZ_CH_ACTIVE: self.ch_active,
            SZ_CH_ENABLED: self.ch_enabled,
            SZ_COOLING_ACTIVE: self.cooling_active,
            SZ_COOLING_ENABLED: self.cooling_enabled,
            SZ_DHW_ACTIVE: self.dhw_active,
            SZ_DHW_BLOCKING: self.dhw_blocking,
            SZ_DHW_ENABLED: self.dhw_enabled,
            SZ_FAULT_PRESENT: self.fault_present,
            SZ_FLAME_ACTIVE: self.flame_active,
            SZ_SUMMER_MODE: self.summer_mode,
            SZ_OTC_ACTIVE: self.otc_active,
            #
            # "status_opentherm": self.opentherm_status,
            # "status_ramses_ii": self.ramses_status,
        }


class Thermostat(BatteryState, Setpoint, Temperature, Fakeable):  # THM (..):
    """The THM/STA class, such as a TR87RF."""

    _SLUG: str = DevType.THM

    _STATE_ATTR = SZ_TEMPERATURE

    async def initiate_binding_process(self) -> Packet:
        return await super().initiate_binding_process(
            [Code._2309, Code._30C9, Code._0008]
        )

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

    _SLUG: str = DevType.BDR

    ACTIVE = "active"
    TPI_PARAMS = "tpi_params"

    _STATE_ATTR = "active"

    # def __init__(self, *args, **kwargs) -> None:
    #     super().__init__(*args, **kwargs)

    #     if kwargs.get(SZ_DOMAIN_ID) == FC:  # TODO: F9/FA/FC, zone_idx
    #         self.ctl._set_app_cntrl(self)

    def _setup_discovery_cmds(self) -> None:
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

        super()._setup_discovery_cmds()

        if self.is_faked:
            return

        self._add_discovery_cmd(Command.get_tpi_params(self.id), 6 * 3600)  # params
        self._add_discovery_cmd(
            Command.from_attrs(RQ, self.id, Code._3EF1, "00"),
            60 if self._child_id in (F9, FA, FC) else 300,
        )  # status

    @property
    def active(self) -> bool | None:  # 3EF0, 3EF1
        """Return the actuator's current state."""
        result = self._msg_value((Code._3EF0, Code._3EF1), key=self.MODULATION_LEVEL)
        return None if result is None else bool(result)

    @property
    def role(self) -> str | None:
        """Return the role of the BDR91A (there are six possibilities)."""

        # TODO: use self._parent?
        if self._child_id in DOMAIN_TYPE_MAP:
            return DOMAIN_TYPE_MAP[self._child_id]
        elif self._parent:
            return self._parent.heating_type  # TODO: only applies to zones

        # if Code._3B00 in self._msgs and self._msgs[Code._3B00].verb == I_:
        #     self._is_tpi = True
        # if Code._1FC9 in self._msgs and self._msgs[Code._1FC9].verb == RP:
        #     if Code._3B00 in self._msgs[Code._1FC9].raw_payload:
        #         self._is_tpi = True

        return None

    @property
    def tpi_params(self) -> dict | None:  # 1100
        return self._msg_value(Code._1100)

    @property
    def schema(self) -> dict[str, Any]:
        return {
            **super().schema,
            "role": self.role,
        }

    @property
    def params(self) -> dict[str, Any]:
        return {
            **super().params,
            self.TPI_PARAMS: self.tpi_params,
        }

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            self.ACTIVE: self.active,
        }


class TrvActuator(BatteryState, HeatDemand, Setpoint, Temperature):  # TRV (04):
    """The TRV class, such as a HR92."""

    _SLUG: str = DevType.TRV

    WINDOW_OPEN = SZ_WINDOW_OPEN  # boolean

    _STATE_ATTR = SZ_HEAT_DEMAND

    @property
    def heat_demand(self) -> float | None:  # 3150
        if (heat_demand := super().heat_demand) is None:
            if self._msg_value(Code._3150) is None and self.setpoint is False:
                return 0  # instead of None (no 3150s sent when setpoint is False)
        return heat_demand

    @property
    def window_open(self) -> bool | None:  # 12B0
        return self._msg_value(Code._12B0, key=self.WINDOW_OPEN)

    @property
    def status(self) -> dict[str, Any]:
        return {
            **super().status,
            self.WINDOW_OPEN: self.window_open,
        }


class JimDevice(Actuator):  # BDR (08):
    _SLUG: str = DevType.JIM


class JstDevice(RelayDemand):  # BDR (31):
    _SLUG: str = DevType.JST


class UfhCircuit(Entity):
    """The UFH circuit class (UFC:circuit is much like CTL/TCS:zone).

    NOTE: for circuits, there's a difference between :
     - `self.ctl`: the UFH controller, and
     - `self.tcs.ctl`: the Evohome controller
    """

    _SLUG: str = None  # type: ignore[assignment]

    def __init__(self, ufc, ufh_idx: str) -> None:
        super().__init__(ufc._gwy)

        self.id: str = f"{ufc.id}_{ufh_idx}"

        self.ufc: UfhController = ufc
        self._child_id = ufh_idx

        # TODO: _ctl should be: .ufc? .ctl?
        self._ctl: Controller = None  # type: ignore[assignment]
        self._zone: Zone | None = None

    # def __str__(self) -> str:
    #     return f"{self.id} ({self._zone and self._zone._child_id})"

    def _handle_msg(self, msg: Message) -> None:
        super()._handle_msg(msg)

        # FIXME:
        if msg.code == Code._000C and msg.payload[SZ_DEVICES]:  # zone_devices
            if not (dev_ids := msg.payload[SZ_DEVICES]):
                return
            if len(dev_ids) != 1:
                raise exc.PacketPayloadInvalid("No devices")

            # ctl = self._gwy.device_by_id.get(dev_ids[0])
            ctl = self._gwy.get_device(dev_ids[0])
            if not ctl or (self._ctl and self._ctl is not ctl):
                raise exc.PacketPayloadInvalid("No CTL")
            self._ctl = ctl

            ctl._make_tcs_controller()
            # self.set_parent(ctl.tcs)

            zon = ctl.tcs.get_htg_zone(msg.payload[SZ_ZONE_IDX])
            if not zon:
                raise exc.PacketPayloadInvalid("No Zone")
            if self._zone and self._zone is not zon:
                raise exc.PacketPayloadInvalid("Wrong Zone")
            self._zone = zon

            if self not in self._zone.actuators:
                schema = {SZ_ACTUATORS: [self.ufc.id], SZ_CIRCUITS: [self.id]}
                self._zone._update_schema(**schema)

    @property
    def ufx_idx(self) -> str:
        return self._child_id

    @property
    def zone_idx(self) -> str | None:
        if self._zone:
            return self._zone._child_id


HEAT_CLASS_BY_SLUG = class_by_attr(__name__, "_SLUG")  # e.g. CTL: Controller

_HEAT_VC_PAIR_BY_CLASS = {
    DevType.DHW: ((I_, Code._1260),),
    DevType.OTB: ((I_, Code._3220), (RP, Code._3220)),
}


def class_dev_heat(
    dev_addr: Address, *, msg: Message = None, eavesdrop: bool = False
) -> type[Device]:
    """Return a device class, but only if the device must be from the CH/DHW group.

    May return a device class, DeviceHeat (which will need promotion).
    """

    if dev_addr.type in DEV_TYPE_MAP.THM_DEVICES:
        return HEAT_CLASS_BY_SLUG[DevType.THM]

    try:
        slug = DEV_TYPE_MAP.slug(dev_addr.type)
    except KeyError:
        pass
    else:
        return HEAT_CLASS_BY_SLUG[slug]

    if not eavesdrop:
        raise TypeError(f"No CH/DHW class for: {dev_addr} (no eavesdropping)")

    if msg and msg.code in CODES_OF_HEAT_DOMAIN_ONLY:
        return DeviceHeat

    raise TypeError(f"No CH/DHW class for: {dev_addr} (unknown type: {dev_addr.type})")
