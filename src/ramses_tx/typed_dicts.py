# We use typed dicts rather than data classes because we migrated from dicts

from typing import Literal, NotRequired, TypeAlias, TypedDict

from ramses_tx.const import FaultDeviceClass, FaultState, FaultType
from ramses_tx.schemas import DeviceIdT

_HexToTempT: TypeAlias = float | None


__all__ = ["PayDictT"]


class _empty(TypedDict):
    pass


class _0004(TypedDict):
    name: NotRequired[str | None]


class _0006(TypedDict):
    change_counter: NotRequired[int | None]


class _0008(TypedDict):
    relay_demand: float | None


class _0100(TypedDict):
    language: str
    _unknown_0: str


# fmt: off
LogIdxT = Literal[
    '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0A', '0B', '0C', '0D', '0E', '0F',
    '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1A', '1B', '1C', '1D', '1E', '1F',
    '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2A', '2B', '2C', '2D', '2E', '2F',
    '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3A', '3B', '3C', '3D', '3E', '3F',
]
# fmt: on


# NOTE: can have only log_idx, only log_entry, both
class _0418(TypedDict):  # NOTE: not identical to FaultLogEntry
    log_idx: LogIdxT  # "00" to ?"3F"
    # TODO: = namedtuple("Fault", "timestamp fault_state ...")
    log_entry: NotRequired[tuple[str, ...] | None]


class _1060(TypedDict):
    battery_low: bool
    battery_level: float | None


class _1090(TypedDict):
    temperature_0: float | None
    temperature_1: float | None


class _10d0(TypedDict):
    days_remaining: int | None
    days_lifetime: NotRequired[int | None]
    percent_remaining: NotRequired[float | None]


class _10e1(TypedDict):
    device_id: DeviceIdT


class _12b0(TypedDict):
    window_open: bool | None


class _1f09(TypedDict):
    remaining_seconds: float
    _next_sync: str


class _1fd4(TypedDict):
    ticker: int


class _22b0(TypedDict):
    enabled: bool


class _2d49(TypedDict):
    state: bool | None


class _2e04(TypedDict):
    system_mode: str
    until: NotRequired[str | None]


class _3110(TypedDict):
    mode: str
    demand: NotRequired[float | None]


class _FlowRate(TypedDict):
    dhw_flow_rate: _HexToTempT


class _Pressure(TypedDict):
    pressure: _HexToTempT


class _Setpoint(TypedDict):
    setpoint: _HexToTempT


class _Temperature(TypedDict):
    temperature: _HexToTempT


class FaultLogEntry(TypedDict):  # NOTE: not identical to _0418
    _log_idx: LogIdxT  # "00" to ?"3F"

    timestamp: str
    fault_state: FaultState
    fault_type: FaultType
    domain_idx: str
    device_class: FaultDeviceClass
    device_id: DeviceIdT | None

    _unknown_3: str
    _unknown_7: str
    _unknown_15: str


# These are from 31DA...
class AirQuality(TypedDict):
    air_quality: float | None
    air_quality_basis: NotRequired[str]


class Co2Level(TypedDict):
    co2_level: float | None


class IndoorHumidity(TypedDict):
    indoor_humidity: _HexToTempT
    temperature: NotRequired[float | None]
    dewpoint_temp: NotRequired[float | None]


class OutdoorHumidity(TypedDict):
    outdoor_humidity: _HexToTempT
    temperature: NotRequired[float | None]
    dewpoint_temp: NotRequired[float | None]


class ExhaustTemp(TypedDict):
    exhaust_temp: _HexToTempT


class SupplyTemp(TypedDict):
    supply_temp: _HexToTempT


class IndoorTemp(TypedDict):
    indoor_temp: _HexToTempT


class OutdoorTemp(TypedDict):
    outdoor_temp: _HexToTempT


class Capabilities(TypedDict):
    speed_capabilities: list[str] | None


class BypassPosition(TypedDict):
    bypass_position: float | None


class FanInfo(TypedDict):
    fan_info: str
    _unknown_fan_info_flags: list[int]


class ExhaustFanSpeed(TypedDict):
    exhaust_fan: float | None


class SupplyFanSpeed(TypedDict):
    supply_fan: float | None


class RemainingMins(TypedDict):
    remaining_mins: int | None


class PostHeater(TypedDict):
    post_heater: float | None


class PreHeater(TypedDict):
    pre_heater: float | None


class SupplyFlow(TypedDict):
    supply_flow: float | None


class ExhaustFlow(TypedDict):
    exhaust_flow: float | None


class _VentilationState(
    AirQuality,
    Co2Level,
    ExhaustTemp,
    SupplyTemp,
    IndoorTemp,
    OutdoorTemp,
    Capabilities,
    BypassPosition,
    FanInfo,
    ExhaustFanSpeed,
    SupplyFanSpeed,
    RemainingMins,
    PostHeater,
    PreHeater,
    SupplyFlow,
    ExhaustFlow,
):
    indoor_humidity: _HexToTempT
    outdoor_humidity: _HexToTempT


class PayDictT:
    """Payload dict types."""

    EMPTY: TypeAlias = _empty

    # command codes
    _0004: TypeAlias = _0004
    _0006: TypeAlias = _0006
    _0008: TypeAlias = _0008
    _0100: TypeAlias = _0100
    _0418: TypeAlias = _0418
    _1060: TypeAlias = _1060
    _1081: TypeAlias = _Setpoint
    _1090: TypeAlias = _1090
    _10D0: TypeAlias = _10d0
    _10E1: TypeAlias = _10e1
    _1260: TypeAlias = _Temperature
    _1280: TypeAlias = OutdoorHumidity
    _1290: TypeAlias = OutdoorTemp
    _1298: TypeAlias = Co2Level
    _12A0: TypeAlias = IndoorHumidity
    _12B0: TypeAlias = _12b0
    _12C8: TypeAlias = AirQuality
    _12F0: TypeAlias = _FlowRate
    _1300: TypeAlias = _Pressure
    _1F09: TypeAlias = _1f09
    _1FD4: TypeAlias = _1fd4
    _22B0: TypeAlias = _22b0
    _22D9: TypeAlias = _Setpoint
    _2D49: TypeAlias = _2d49
    _2E04: TypeAlias = _2e04
    _3110: TypeAlias = _3110
    _31DA: TypeAlias = _VentilationState
    _3200: TypeAlias = _Temperature
    _3210: TypeAlias = _Temperature

    FAULT_LOG_ENTRY: TypeAlias = FaultLogEntry
    TEMPERATURE: TypeAlias = _Temperature

    # 31DA primitives
    AIR_QUALITY: TypeAlias = AirQuality
    CO2_LEVEL: TypeAlias = Co2Level
    EXHAUST_TEMP: TypeAlias = ExhaustTemp
    SUPPLY_TEMP: TypeAlias = SupplyTemp
    INDOOR_HUMIDITY: TypeAlias = IndoorHumidity
    OUTDOOR_HUMIDITY: TypeAlias = OutdoorHumidity
    INDOOR_TEMP: TypeAlias = IndoorTemp
    OUTDOOR_TEMP: TypeAlias = OutdoorTemp
    CAPABILITIES: TypeAlias = Capabilities
    BYPASS_POSITION: TypeAlias = BypassPosition
    FAN_INFO: TypeAlias = FanInfo
    EXHAUST_FAN_SPEED: TypeAlias = ExhaustFanSpeed
    SUPPLY_FAN_SPEED: TypeAlias = SupplyFanSpeed
    REMAINING_MINUTES: TypeAlias = RemainingMins
    POST_HEATER: TypeAlias = PostHeater
    PRE_HEATER: TypeAlias = PreHeater
    SUPPLY_FLOW: TypeAlias = SupplyFlow
    EXHAUST_FLOW: TypeAlias = ExhaustFlow
