# We use typed dicts rather than data classes because we migrated from dicts

from typing import NotRequired, TypeAlias, TypedDict

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
    device_id: str


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
