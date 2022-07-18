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
from typing import Optional, Union  # typeguard doesn't support PEP604 on 3.9.x

try:
    from typeguard import typechecked  # type: ignore[reportMissingImports]

except ImportError:

    def typechecked(fnc):  # type: ignore[no-redef]
        def wrapper(*args, **kwargs):
            return fnc(*args, **kwargs)

        return wrapper


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
def bool_from_hex(value: str) -> Optional[bool]:  # either False, True or None
    """Convert a 2-char hex string into a boolean."""
    if not isinstance(value, str) or len(value) != 2:
        raise ValueError(f"Invalid value: {value}, is not a 2-char hex string")
    if value == "FF":
        return None
    return {"00": False, "C8": True}[value]


@typechecked
def bool_to_hex(value: Optional[bool]) -> str:  # either 00, C8 or FF
    """Convert a boolean into a 2-char hex string."""
    if value is None:
        return "FF"
    if not isinstance(value, bool):
        raise ValueError(f"Invalid value: {value}, is not bool")
    return {False: "00", True: "C8"}[value]


@typechecked
def date_from_hex(value: str) -> Optional[str]:  # YY-MM-DD
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


@typechecked
def double_from_hex(value: str, factor: int = 1) -> Optional[float]:
    """Convert a 4-char hex string into a double."""
    if not isinstance(value, str) or len(value) != 4:
        raise ValueError(f"Invalid value: {value}, is not a 4-char hex string")
    if value == "7FFF":
        return None
    return int(value, 16) / factor


@typechecked
def double_to_hex(value: Optional[float], factor: int = 1) -> str:
    """Convert a double into 4-char hex string."""
    if value is None:
        return "7FFF"
    if not isinstance(value, float):
        raise ValueError(f"Invalid value: {value}, is not a double (a float)")
    return f"{int(value * factor):04X}"


@typechecked
def dtm_from_hex(value: str) -> Optional[str]:  # from parsers
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
def dtm_to_hex(dtm: Union[None, dt, str], is_dst=False, incl_seconds=False) -> str:
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
def dts_from_hex(value: str) -> Optional[str]:
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
def dts_to_hex(dtm: Union[None, dt, str]) -> str:  # TODO: WIP
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
def flag8(byte: str, lsb: bool = False) -> list:  # TODO: should be tuple
    """Split a hex str (a byte) into a list of 8 bits, MSB as first bit by default.

    The `lsb` boolean is used so that flag[0] is `zone_idx["00]`, etc.
    """
    # the following might need to be 02X, 04X, etc.
    # assert "61" == f"{sum(b<<i for i, b in enumerate(flag8('61', lsb=True))):02X}"
    # assert "61" == f"{sum(b<<i for i, b in enumerate(reversed(flag8('61')))):02X}"
    if not isinstance(byte, str) or len(byte) != 2:
        raise ValueError(f"Invalid value: '{byte}', is not a 2-char hex string")
    # bits = len(byte) * 4  # TODO: use 2, 4 (or more) char next strings
    if lsb:  # LSB is first bit
        # [(int("C001", 16) & (1 << x)) >> x for x in range(16)]
        # [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]
        return [(int(byte, 16) & (1 << x)) >> x for x in range(8)]
    # [(int("C001", 16) & (1 << x)) >> x for x in reversed(range(16))]
    # [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    return [(int(byte, 16) & (1 << x)) >> x for x in reversed(range(8))]


# TODO: add a wrapper for EF, & 0xF0
@typechecked
def percent_from_hex(
    value: str, high_res: bool = True
) -> Optional[float]:  # c.f. valve_demand
    """Convert a 2-char hex string into a percentage.

    The range is 0-100%, with resolution of 0.5% (high_res) or 1%.
    """
    if not isinstance(value, str) or len(value) != 2:
        raise ValueError(f"Invalid value: {value}, is not a 2-char hex string")
    if value == "EF":  # TODO: when EF, when 7F?
        return None  # TODO: raise NotImplementedError
    if (raw_result := int(value, 16)) & 0xF0 == 0xF0:
        return None  # TODO: raise errors
    result = float(raw_result) / (200 if high_res else 100)
    if result > 1.0:
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
def temp_from_hex(value: str) -> Union[None, bool, float]:
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
def temp_to_hex(value: Optional[float]) -> str:
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


@typechecked
def valve_demand(value: str) -> Optional[dict]:  # c.f. percent_from_hex()
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


def _precision_v_cost():
    import math

    #
    LOOPS = 10**6
    #
    print("time.time_ns(): %s" % time.time_ns())
    print("time.time():    %s\r\n" % time.time())
    #
    starts = time.time_ns()
    min_dt = [abs(time.time_ns() - time.time_ns()) for _ in range(LOOPS)]
    min_dt = min(filter(bool, min_dt))
    print("min delta   time_ns(): %s ns" % min_dt)
    print("duration    time_ns(): %s ns\r\n" % (time.time_ns() - starts))
    #
    starts = time.time_ns()
    min_dt = [abs(time.time() - time.time()) for _ in range(LOOPS)]
    min_dt = min(filter(bool, min_dt))
    print("min delta      time(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration       time(): %s ns\r\n" % (time.time_ns() - starts))
    #
    starts = time.time_ns()
    min_dt = [abs(timestamp() - timestamp()) for _ in range(LOOPS)]
    min_dt = min(filter(bool, min_dt))
    print("min delta timestamp(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  timestamp(): %s ns\r\n" % (time.time_ns() - starts))
    #
    LOOPS = 10**4
    #
    starts = time.time_ns()
    min_td = [abs(dt.now() - dt.now()) for _ in range(LOOPS)]
    min_td = min(filter(bool, min_td))
    print("min delta dt.now(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  dt.now(): %s ns\r\n" % (time.time_ns() - starts))
    #
    starts = time.time_ns()
    min_td = [abs(dt_now() - dt_now()) for _ in range(LOOPS)]
    min_td = min(filter(bool, min_td))
    print("min delta dt_now(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  dt_now(): %s ns\r\n" % (time.time_ns() - starts))
    #
    starts = time.time_ns()
    min_td = [
        abs(
            (dt_now if sys.platform == "win32" else dt.now)()
            - (dt_now if sys.platform == "win32" else dt.now)()
        )
        for _ in range(LOOPS)
    ]
    min_td = min(filter(bool, min_td))
    print("min delta dt_now(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  dt_now(): %s ns\r\n" % (time.time_ns() - starts))
    #
    dt_nov = dt_now if sys.platform == "win32" else dt.now
    starts = time.time_ns()
    min_td = [abs(dt_nov() - dt_nov()) for _ in range(LOOPS)]
    min_td = min(filter(bool, min_td))
    print("min delta dt_now(): %s ns" % math.ceil(min_dt * 1e9))
    print("duration  dt_now(): %s ns\r\n" % (time.time_ns() - starts))
