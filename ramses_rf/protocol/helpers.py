#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Protocol/Transport layer.

Helper functions.
"""
# from __future__ import annotations  # incompatible with @typechecked

import ctypes
import sys
import time
from datetime import datetime as dt
from typing import (  # typeguard doesn't support PEP604 on 3.9.x
    Iterable,
    Literal,
    Optional,
    Union,
)

from .const import SZ_AIR_QUALITY, SZ_AIR_QUALITY_BASIS, SZ_CO2_LEVEL

try:
    from typeguard import typechecked  # type: ignore[reportMissingImports]

except ImportError:

    def typechecked(fnc):  # type: ignore[no-redef]
        def wrapper(*args, **kwargs):
            return fnc(*args, **kwargs)

        return wrapper


# fmt: off
HexByte = Literal[
    '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0A', '0B', '0C', '0D', '0E', '0F',
    '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1A', '1B', '1C', '1D', '1E', '1F',
    '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2A', '2B', '2C', '2D', '2E', '2F',
    '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3A', '3B', '3C', '3D', '3E', '3F',
    '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4A', '4B', '4C', '4D', '4E', '4F',
    '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5A', '5B', '5C', '5D', '5E', '5F',
    '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6A', '6B', '6C', '6D', '6E', '6F',
    '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7A', '7B', '7C', '7D', '7E', '7F',
    '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8A', '8B', '8C', '8D', '8E', '8F',
    '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9A', '9B', '9C', '9D', '9E', '9F',
    'A0', 'A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'AA', 'AB', 'AC', 'AD', 'AE', 'AF',
    'B0', 'B1', 'B2', 'B3', 'B4', 'B5', 'B6', 'B7', 'B8', 'B9', 'BA', 'BB', 'BC', 'BD', 'BE', 'BF',
    'C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'CA', 'CB', 'CC', 'CD', 'CE', 'CF',
    'D0', 'D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8', 'D9', 'DA', 'DB', 'DC', 'DD', 'DE', 'DF',
    'E0', 'E1', 'E2', 'E3', 'E4', 'E5', 'E6', 'E7', 'E8', 'E9', 'EA', 'EB', 'EC', 'ED', 'EE', 'EF',
    'F0', 'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'FA', 'FB', 'FC', 'FD', 'FE', 'FF'
]
# fmt: on


HexStr2 = str  # two characters, one byte
HexStr4 = str
HexStr8 = str
HexStr12 = str
HexStr14 = str


class _FILE_TIME(ctypes.Structure):
    """Data structure for GetSystemTimePreciseAsFileTime()."""

    _fields_ = [("dwLowDateTime", ctypes.c_uint), ("dwHighDateTime", ctypes.c_uint)]


file_time = _FILE_TIME()


@typechecked
def timestamp() -> float:
    """Return the number of seconds since the Unix epoch.

    Return an accurate value, even for Windows-based systems.
    """  # see: https://www.python.org/dev/peps/pep-0564/
    if sys.platform != "win32":
        return time.time_ns() / 1e9  # since 1970-01-01T00:00:00Z, time.gmtime(0)
    ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(file_time))
    _time = (file_time.dwLowDateTime + (file_time.dwHighDateTime << 32)) / 1e7
    return _time - 134774 * 24 * 60 * 60  # otherwise, is since 1601-01-01T00:00:00Z


@typechecked
def dt_now() -> dt:
    """Return the current datetime as a local/naive datetime object.

    This is slower, but potentially more accurate, than dt.now(), and is used mainly for
    packet timestamps.
    """
    if sys.platform == "win32":
        return dt.fromtimestamp(timestamp())
    return dt.now()


@typechecked
def dt_str() -> str:
    """Return the current datetime as a isoformat string."""
    return dt_now().isoformat(timespec="microseconds")


@typechecked
def bool_from_hex(value: HexStr2) -> Optional[bool]:  # either False, True or None
    """Convert a 2-char hex string into a boolean."""
    if not isinstance(value, str) or len(value) != 2:
        raise ValueError(f"Invalid value: {value}, is not a 2-char hex string")
    if value == "FF":
        return None
    return {"00": False, "C8": True}[value]


@typechecked
def bool_to_hex(value: Optional[bool]) -> HexStr2:  # either 00, C8 or FF
    """Convert a boolean into a 2-char hex string."""
    if value is None:
        return "FF"
    if not isinstance(value, bool):
        raise ValueError(f"Invalid value: {value}, is not bool")
    return {False: "00", True: "C8"}[value]


@typechecked
def date_from_hex(value: HexStr8) -> Optional[str]:  # YY-MM-DD
    """Convert am 8-char hex string into a date, format YY-MM-DD."""
    if not isinstance(value, str) or len(value) != 8:
        raise ValueError(f"Invalid value: {value}, is not an 8-char hex string")
    if value == "FFFFFFFF":
        return None
    return dt(
        year=int(value[4:8], 16),
        month=int(value[2:4], 16),
        day=int(value[:2], 16) & 0b11111,  # 1st 3 bits: DayOfWeek
    ).strftime("%Y-%m-%d")


@typechecked  # FIXME: factor=1 should return an int
def double_from_hex(value: HexStr4, factor: int = 1) -> Optional[float]:
    """Convert a 4-char hex string into a double."""
    if not isinstance(value, str) or len(value) != 4:
        raise ValueError(f"Invalid value: {value}, is not a 4-char hex string")
    if value == "7FFF":
        return None
    return int(value, 16) / factor


@typechecked
def double_to_hex(value: Optional[float], factor: int = 1) -> HexStr4:
    """Convert a double into 4-char hex string."""
    if value is None:
        return "7FFF"
    if not isinstance(value, float):
        raise ValueError(f"Invalid value: {value}, is not a double (a float)")
    return f"{int(value * factor):04X}"


@typechecked
def dtm_from_hex(value: HexStr12 | HexStr14) -> Optional[str]:  # from parsers
    """Convert a 12/14-char hex string to an isoformat datetime (naive, local)."""
    #        00141B0A07E3  (...HH:MM:00)    for system_mode, zone_mode (schedules?)
    #      0400041C0A07E3  (...HH:MM:SS)    for sync_datetime

    if not isinstance(value, str) or len(value) not in (12, 14):
        raise ValueError(f"Invalid value: {value}, is not a 12/14-char hex string")
    if value[-12:] == "FF" * 6:
        return None
    if len(value) == 12:
        value = f"00{value}"
    return dt(
        year=int(value[10:14], 16),
        month=int(value[8:10], 16),
        day=int(value[6:8], 16),
        hour=int(value[4:6], 16) & 0b11111,  # 1st 3 bits: DayOfWeek
        minute=int(value[2:4], 16),
        second=int(value[:2], 16) & 0b1111111,  # 1st bit: used for DST
    ).isoformat(timespec="seconds")


@typechecked
def dtm_to_hex(
    dtm: Union[None, dt, str], is_dst=False, incl_seconds=False
) -> HexStr12 | HexStr14:
    """Convert a datetime (isoformat str, or naive dtm) to a 12/14-char hex str."""

    def _dtm_to_hex(tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, *args):
        return (
            f"{tm_sec:02X}{tm_min:02X}{tm_hour:02X}"
            f"{tm_mday:02X}{tm_mon:02X}{tm_year:04X}"
        )

    if dtm is None:
        return "FF" * (7 if incl_seconds else 6)
    if isinstance(dtm, str):
        dtm = dt.fromisoformat(dtm)
    dtm_str = _dtm_to_hex(*dtm.timetuple())  # TODO: add DST for tm_isdst
    if is_dst:
        dtm_str = f"{int(dtm_str[:2], 16) | 0x80:02X}" + dtm_str[2:]
    return dtm_str if incl_seconds else dtm_str[2:]


@typechecked
def dts_from_hex(value: HexStr12) -> Optional[str]:
    """YY-MM-DD HH:MM:SS."""
    if not isinstance(value, str) or len(value) != 12:
        raise ValueError(f"Invalid value: {value}, is not a 12-char hex string")
    if value == "00000000007F":
        return None
    _seqx = int(value, 16)
    return dt(
        year=(_seqx & 0b1111111 << 24) >> 24,
        month=(_seqx & 0b1111 << 36) >> 36,
        day=(_seqx & 0b11111 << 31) >> 31,
        hour=(_seqx & 0b11111 << 19) >> 19,
        minute=(_seqx & 0b111111 << 13) >> 13,
        second=(_seqx & 0b111111 << 7) >> 7,
    ).strftime("%y-%m-%dT%H:%M:%S")


@typechecked
def dts_to_hex(dtm: Union[None, dt, str]) -> HexStr12:  # TODO: WIP
    """Convert a datetime (isoformat str, or dtm) to a packed 12-char hex str."""
    """YY-MM-DD HH:MM:SS."""
    if dtm is None:
        return "00000000007F"
    if isinstance(dtm, str):
        dtm = dt.fromisoformat(dtm)  # TODO: YY-MM-DD, not YYYY-MM-DD
    (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, *_) = dtm.timetuple()
    result = sum(
        (
            tm_year % 100 << 24,
            tm_mon << 36,
            tm_mday << 31,
            tm_hour << 19,
            tm_min << 13,
            tm_sec << 7,
        )
    )
    return f"{result:012X}"


@typechecked
def flag8_from_hex(byte: HexByte, lsb: bool = False) -> list[int]:  # TODO: use tuple
    """Split a hex str (a byte) into a list of 8 bits, MSB as first bit by default.

    If lsb==True, then the LSB is first.
    The `lsb` boolean is used so that flag[0] is `zone_idx["00"]`, etc.
    """
    if not isinstance(byte, str) or len(byte) != 2:
        raise ValueError(f"Invalid value: '{byte}', is not a 2-char hex string")
    if lsb:  # make LSB is first bit
        return list((int(byte, 16) & (1 << x)) >> x for x in range(8))
    return list((int(byte, 16) & (1 << x)) >> x for x in reversed(range(8)))


@typechecked
def flag8_to_hex(flags: Iterable[int], lsb: bool = False) -> HexByte:
    """Convert a list of 8 bits, MSB as first bit by default, into an ASCII hex string.

    The `lsb` boolean is used so that flag[0] is `zone_idx["00"]`, etc.
    """
    if not isinstance(flags, list) or len(flags) != 8:
        raise ValueError(f"Invalid value: '{flags}', is not a list of 8 bits")
    if lsb:  # LSB is first bit
        return f"{sum(x<<idx for idx, x in enumerate(flags)):02X}"
    return f"{sum(x<<idx for idx, x in enumerate(reversed(flags))):02X}"


# TODO: add a wrapper for EF, & 0xF0
@typechecked
def percent_from_hex(
    value: HexStr2, high_res: bool = True
) -> Optional[float]:  # c.f. valve_demand
    """Convert a 2-char hex string into a percentage.

    The range is 0-100%, with resolution of 0.5% (high_res, 00-C8) or 1% (00-64).
    """
    if not isinstance(value, str) or len(value) != 2:
        raise ValueError(f"Invalid value: {value}, is not a 2-char hex string")
    if value == "EF":  # TODO: when EF, when 7F?
        return None  # TODO: raise NotImplementedError
    if (raw_result := int(value, 16)) & 0xF0 == 0xF0:
        return None  # TODO: raise errors
    result = float(raw_result) / (200 if high_res else 100)
    if result > 1.0:  # move to outer wrapper
        raise ValueError(f"Invalid result: {result} (0x{value}) is > 1")
    return result


@typechecked
def str_from_hex(value: str) -> Optional[str]:  # printable ASCII characters
    """Return a string of printable ASCII characters."""
    # result = bytearray.fromhex(value).split(b"\x7F")[0]  # TODO: needs checking
    if not isinstance(value, str):
        raise ValueError(f"Invalid value: {value}, is not a string")
    result = bytearray([x for x in bytearray.fromhex(value) if 31 < x < 127])
    return result.decode("ascii").strip() if result else None


@typechecked
def str_to_hex(value: str) -> str:
    """Convert a string to a variable-length ASCII hex string."""
    if not isinstance(value, str):
        raise ValueError(f"Invalid value: {value}, is not a string")
    return "".join(f"{ord(x):02X}" for x in value)  # or: value.encode().hex()


@typechecked
def temp_from_hex(value: HexStr2) -> Union[None, bool, float]:
    """Convert a 2's complement 4-byte hex string to an float."""
    if not isinstance(value, str) or len(value) != 4:
        raise ValueError(f"Invalid value: {value}, is not a 4-char hex string")
    if value == "31FF":  # means: N/A (== 127.99, 2s complement), signed?
        return None
    if value == "7EFF":  # possibly only for setpoints? unsigned?
        return False
    if value == "7FFF":  # also: FFFF?, means: N/A (== 327.67)
        return None
    temp = int(value, 16)
    return (temp if temp < 2**15 else temp - 2**16) / 100


@typechecked
def temp_to_hex(value: Optional[float]) -> HexStr2:
    """Convert a float to a 2's complement 4-byte hex string."""
    if value is None:
        return "7FFF"  # or: "31FF"?
    if value is False:
        return "7EFF"
    if not isinstance(value, (float, int)):
        raise TypeError(f"Invalid temp: {value} is not a float")
    if not -(2**7) <= value < 2**7:  # TODO: tighten range
        raise ValueError(f"Invalid temp: {value} is out of range")
    temp = int(value * 100)
    return f"{temp if temp >= 0 else temp + 2 ** 16:04X}"


########################################################################################


@typechecked
def valve_demand(value: HexStr2) -> Optional[dict]:  # c.f. percent_from_hex()
    """Convert a 2-char hex string into a percentage.

    The range is 0-100%, with resolution of 0.5% (high_res) or 1%.
    """  # for a damper (restricts flow), or a valve (permits flow)
    if not isinstance(value, str) or len(value) != 2:
        raise ValueError(f"Invalid value: {value}, is not a 2-char hex string")
    if value == "EF":
        return None  # TODO: raise NotImplementedError
    result = int(value, 16)
    if result & 0xF0 == 0xF0:
        STATE_3150 = {
            "F0": "open_circuit",
            "F1": "short_circuit",
            "FD": "valve_stuck",  # damper/valve stuck
            "FE": "actuator_stuck",
        }
        return {
            "heat_demand": None,
            "fault": STATE_3150.get(value, "malfunction"),
        }
    result = result / 200  # type: ignore[assignment]
    if result > 1:
        raise ValueError(f"Invalid result: {result} (0x{value}) is > 1")
    return {"heat_demand": result}


@typechecked  # 31DA[2:6] and 12C8[2:6]
def air_quality(value: HexStr4) -> dict[str, None | float | str]:
    """Return the air quality level, from poor (0%) to excellent (100%).

    The basis of the air quality level should be one of: VOC, CO2 or relative humidity.
    If air_quality is EF, air_quality_basis should be 00.
    """  # VOC: Volatile organic compounds

    # TODO: remove me
    if not isinstance(value, str) or len(value) != 4:
        raise ValueError(f"Invalid value: {value}, is not a 4-char hex string")

    FAULT_CODES = {}

    assert value[:2] != "EF" or value[2:] == "00", value
    if value == "EF00":  # Not implemented
        return {SZ_AIR_QUALITY: None}

    assert int(value[:2], 16) <= 200 or int(value[:2], 16) & 0xF0 == 0xF0, value[:2]
    level = percent_from_hex(value[:2])

    if level is None:
        fault = FAULT_CODES.get(value[:2], f"sensor_error_{value[:2]}")
        return {SZ_AIR_QUALITY: None, f"{SZ_AIR_QUALITY}_fault": fault}

    assert value[2:] in ("10", "20", "40"), value[2:]
    basis = {
        "10": "voc",  # volatile compounds
        "20": "co2",  # carbdon dioxide
        "40": "rel_humidity",  # relative humidity
    }.get(value[2:], f"unknown_{value[2:]}")

    return {SZ_AIR_QUALITY: level, SZ_AIR_QUALITY_BASIS: basis}


@typechecked  # 31DA[6:10] and 1298[2:6]
def co2_level(value: HexStr4) -> dict[str, None | int | str]:
    """Return the co2 level, in ppm."""

    # TODO: remove this...
    if not isinstance(value, str) or len(value) != 4:
        raise ValueError(f"Invalid value: {value}, is not a 4-char hex string")

    FAULT_CODES = {
        "80": "sensor_short_circuit",
        "81": "sensor_open_circuit",
        "83": "sensor_value_too_high",
        "84": "sensor_value_too_low",
        "85": "sensor_unreliable",
    }

    if value == "7FFF":  # Not implemented
        return {SZ_CO2_LEVEL: None}

    level = int(value, 16)  # was: double_from_hex(value)  # is 2's complement?

    if level >= 0x8000:
        fault = FAULT_CODES.get(value[:2], f"sensor_error_{value[:2]}")
        return {SZ_CO2_LEVEL: None, f"{SZ_CO2_LEVEL}_fault": fault}

    # assert int(value[:2], 16) <= 0x8000, value
    return {SZ_CO2_LEVEL: level}


# @typechecked
# def pre_heat(value: HexStr2) -> dict[str, None | float | str]:
#     try:
#         return {
#             "pre_heat": percent_from_hex(value, high_res=False),
#         }  # incl. EF -> None?
#     except ValueError:
#         return {
#             "pre_heat": None,
#             "fault_code": None,
#             "_raw_value": None,
#         }


# @typechecked
# def bypass_position(value: HexStr2) -> Optional[float]:
#     """Convert a 2-char hex string into a bypass position."""
#     SENTINEL_VALUES = {
#         "EF": None,  # Feature is not implemented
#         # "00": "closed",  # Fully closed
#         # "C8": "open",  # Fully open
#         "F0": "open_circuit",  # Actuator Open Circuit
#         "F1": "short_circuit",  # Actuator Short Circuit
#         "F2": "unavailable",  # Not available (but should be)
#         "FD": "jammed_valve",  # Damper/Valve Jam
#         "FE": "jammed_actuator",  # Actuator Jam
#         "FF": "other_fault",  # Non-specific fault
#         # MODE: "FF": "auto",  # Auto
#     }


# @typechecked  # indoor/outdoor rel. humidity
# def humidity(value: HexStr2) -> Optional[float]:
#     """Convert a 2-char hex string into a relative humidity."""
#     SENTINEL_VALUES = {
#         "EF": None,  # Feature is not implemented
#         "F0": "shorted_sensor",  # Shorted sensor
#         "F1": "open_sensor",  # Open sensor
#         "F2": "unavailable",  # Not available (but should be)
#         "F3": "high_range",  # Out of range high
#         "F4": "low_range",  # Out of range low
#         "F5": "unreliable",  # Not reliable
#         "FF": "other_fault",  # Non-specific fault
#     }


# @typechecked  # inlet/exhaust flow level
# def flow_level(value: HexStr4) -> Optional[float]:
#     """Convert a 4-char hex string into a flow rate/level."""
#     SENTINEL_VALUES = {
#         "7FFF": None,  # Feature is not implemented
#         "8000-85FF": "sensor_error",  # Sensor error
#     }
