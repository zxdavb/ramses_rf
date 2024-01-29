# We use typed dicts rather than data classes because we migrated from dicts

from typing import TypeAlias, TypedDict

from .const import (
    SZ_DHW_FLOW_RATE,
    SZ_PRESSURE,
    SZ_SETPOINT,
    SZ_TEMPERATURE,
)
from .helpers import hex_to_temp

_HexToTempT: TypeAlias = float | None


class _flow_rate(TypedDict):
    dhw_flow_rate: _HexToTempT


class _pressure(TypedDict):
    pressure: _HexToTempT


class _setpoint(TypedDict):
    setpoint: _HexToTempT


class _temperature(TypedDict):
    temperature: _HexToTempT


class PayDictT:
    """Payload dict types."""

    temperature: TypeAlias = _temperature

    _1081: TypeAlias = _setpoint
    _1260: TypeAlias = _temperature
    _1290: TypeAlias = _temperature
    _12F0: TypeAlias = _flow_rate
    _1300: TypeAlias = _pressure
    _22D9: TypeAlias = _setpoint
    _3200: TypeAlias = _temperature
    _3210: TypeAlias = _temperature


def parse_1081(payload: str) -> PayDictT._1081:
    """Return the max CH setpoint."""
    res: PayDictT._1081 = {SZ_SETPOINT: hex_to_temp(payload[2:])}
    return res


def parse_1260(payload: str) -> PayDictT._1260:
    """Return the DHW cylinder temp ('C)."""
    res: PayDictT._1260 = {SZ_TEMPERATURE: hex_to_temp(payload[2:])}
    return res


def parse_1290(payload: str) -> PayDictT._1290:
    """Return the outside temp ('C)."""
    res: PayDictT._1260 = {SZ_TEMPERATURE: hex_to_temp(payload[2:])}
    return res


def parse_12F0(payload: str) -> PayDictT._12F0:
    """Return the DHW flow rate."""
    res: PayDictT._12F0 = {SZ_DHW_FLOW_RATE: hex_to_temp(payload[2:])}
    return res


def parse_1300(payload: str) -> PayDictT._1300:
    """Return the CV pressure (bar)."""

    # 0x9F6 (2550 dec = 2.55 bar) appears to be a sentinel value
    temp = None if payload[2:] == "09F6" else hex_to_temp(payload[2:])

    res: PayDictT._1300 = {SZ_PRESSURE: temp}
    return res


def parse_22D9(payload: str) -> PayDictT._22D9:
    """Return the desired boiler setpoint."""
    res: PayDictT._22D9 = {SZ_SETPOINT: hex_to_temp(payload[2:])}
    return res


def parse_3200(payload: str) -> PayDictT._3200:
    """Return the supplied boiler water (flow) temp."""
    res: PayDictT._3200 = {SZ_TEMPERATURE: hex_to_temp(payload[2:])}
    return res


def parse_3210(payload: str) -> PayDictT._3210:
    """Return the boiler water temp."""
    res: PayDictT._3210 = {SZ_TEMPERATURE: hex_to_temp(payload[2:])}
    return res
