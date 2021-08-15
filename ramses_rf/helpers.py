#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Helper functions."""

import asyncio
import ctypes
import re
import sys
import time
from datetime import datetime as dt
from inspect import iscoroutinefunction
from typing import Optional, Union


class FILETIME(ctypes.Structure):
    """Data structure for GetSystemTimePreciseAsFileTime()."""

    _fields_ = [("dwLowDateTime", ctypes.c_uint), ("dwHighDateTime", ctypes.c_uint)]


def dt_now() -> dt:
    """Return the current datetime as a local/naive datetime object.

    This is slower, but potentially more accurate, than dt.now(), and is used mainly for
    packet timestamps.
    """
    return dt.fromtimestamp(timestamp())


def dt_str() -> str:
    """Return the current datetime as a isoformat string."""
    return dt_now().isoformat(timespec="microseconds")


def timestamp() -> float:
    """Return the number of seconds since the Unix epoch.

    Return an accurate value, even for Windows-based systems.
    """  # see: https://www.python.org/dev/peps/pep-0564/
    if sys.platform != "win32":
        return time.time_ns() / 1e9  # since 1970-01-01T00:00:00Z, time.gmtime(0)
    file_time = FILETIME()
    ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(file_time))
    _time = (file_time.dwLowDateTime + (file_time.dwHighDateTime << 32)) / 1e7
    return _time - 134774 * 24 * 60 * 60  # otherwise, is since 1601-01-01T00:00:00Z


def _precision_v_cost():
    import math

    #
    LOOPS = 10 ** 6
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
    LOOPS = 10 ** 4
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


def _double(val, factor=1) -> Optional[float]:
    """Return a double, used by 31DA."""
    if val == "7FFF":
        return
    result = int(val, 16)
    assert result < 32767
    return result if factor == 1 else result / factor


def _flag8(byte, *args) -> list:
    """Split a byte (as a str) into a list of 8 bits (1/0)."""
    ret = [0] * 8
    byte = bytes.fromhex(byte)[0]
    for i in range(8):
        ret[i] = byte & 1
        byte = byte >> 1
    return ret


def _percent(value: str) -> Optional[float]:  # a percentage 0-100% (0.0 to 1.0)
    """Return a percentage, 0-100% with resolution of 0.5%."""
    assert len(value) == 2, "len is not 2"
    if value in {"EF", "FE", "FF"}:  # TODO: diff b/w FE (seen with 3150) & FF
        return
    assert int(value, 16) <= 200, "max value should be 0xC8, not 0x{value}"
    return int(value, 16) / 200


def bool_from_hex(value: str) -> Optional[bool]:  # either 00 or C8
    """Return a boolean."""
    assert value in {"00", "C8", "FF"}, value
    return {"00": False, "C8": True}.get(value)


def date_from_hex(value: str) -> Optional[str]:  # YY-MM-DD
    """Return a date string in the format YY-MM-DD."""
    assert len(value) == 8, "len is not 8"
    if value == "FFFFFFFF":
        return
    return dt(
        year=int(value[4:8], 16),
        month=int(value[2:4], 16),
        day=int(value[:2], 16) & 0b11111,  # 1st 3 bits: DayOfWeek
    ).strftime("%Y-%m-%d")


def dtm_from_hex(value: str) -> str:  # from parsers
    """Convert a hex string to an (naive, local) isoformat string."""
    #        00141B0A07E3  (...HH:MM:00)    for system_mode, zone_mode (schedules?)
    #      0400041C0A07E3  (...HH:MM:SS)    for sync_datetime

    if value == "FF" * 6:
        return None

    if len(value) == 12:
        value = f"00{value}"
    # assert len(value) == 14
    return dt(
        year=int(value[10:14], 16),
        month=int(value[8:10], 16),
        day=int(value[6:8], 16),
        hour=int(value[4:6], 16) & 0b11111,  # 1st 3 bits: DayOfWeek
        minute=int(value[2:4], 16),
        second=int(value[:2], 16) & 0b1111111,  # 1st bit: used for DST
    ).isoformat()


def dtm_to_hex(dtm: Union[str, dt]) -> str:
    """Convert a datetime (isoformat string, or datetime obj) to a hex string."""

    def _dtm_to_hex(tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, *args):
        return f"{tm_min:02X}{tm_hour:02X}{tm_mday:02X}{tm_mon:02X}{tm_year:04X}"

    if dtm is None:
        return "FF" * 6

    if isinstance(dtm, str):
        try:
            dtm = dt.fromisoformat(dtm)
        except ValueError:
            raise ValueError("Invalid datetime isoformat string")
    elif not isinstance(dtm, dt):
        raise TypeError("Invalid datetime object")

    # if dtm < dt.now() + td(minutes=1):
    #     raise ValueError("Invalid datetime")

    return _dtm_to_hex(*dtm.timetuple())


def dts_from_hex(value: str) -> Optional[str]:
    """YY-MM-DD HH:MM:SS."""
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
    ).strftime("%Y-%m-%dT%H:%M:%S")


def dts_to_hex(dtm: Union[str, dt]) -> str:  # TODO: WIP
    """YY-MM-DD HH:MM:SS."""
    if dtm is None:
        return "00000000007F"
    if isinstance(dtm, str):
        try:
            dtm = dt.fromisoformat(dtm)  # TODO: YY-MM-DD, not YYYY-MM-DD
        except ValueError:
            raise ValueError("Invalid datetime isoformat string")
    elif not isinstance(dtm, dt):
        raise TypeError("Invalid datetime object")
    (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, *args) = dtm.timetuple()
    val = sum(
        (
            tm_year % 100 << 24,
            tm_mon << 36,
            tm_mday << 31,
            tm_hour << 19,
            tm_min << 13,
            tm_sec << 7,
        )
    )
    return f"{val:012X}"


def str_from_hex(value: str) -> Optional[str]:  # printable ASCII characters
    """Return a string of printable ASCII characters."""
    # result = bytearray.fromhex(value).split(b"\x7F")[0]  # TODO: needs checking
    result = bytearray([x for x in bytearray.fromhex(value) if 31 < x < 127])
    return result.decode("ascii").strip() if result else None


def str_to_hex(value: str) -> str:
    """Convert a string to a variable-length ASCII hex string."""
    return "".join(f"{ord(x):02X}" for x in value)
    # return value.encode().hex()


def temp_from_hex(value: str) -> Union[float, bool, None]:
    """Convert a 2's complement 4-byte hex string to an float."""
    assert len(value) == 4, f"{value} should be 4 bytes long"
    if value == "31FF":  # means: N/A (== 127.99, 2s complement), signed?
        return
    if value == "7EFF":  # possibly only for setpoints? unsigned?
        return False
    if value == "7FFF":  # also: FFFF?, means: N/A (== 327.67)
        return
    temp = int(value, 16)
    return (temp if temp < 2 ** 15 else temp - 2 ** 16) / 100


def temp_to_hex(value: float) -> str:
    """Convert a float to a 2's complement 4-byte hex string."""
    assert -(2 ** 7) <= value < 2 ** 7, f"{value} is out of range"
    if value is None:
        return "7FFF"  # or: "31FF"?
    if value is False:
        return "7EFF"
    temp = int(value * 100)
    return f"{temp if temp >= 0 else temp + 2 ** 16:04X}"


def valve_demand(value: str) -> dict:
    # a damper restricts flow, a valve permits flow
    demand = int(value, 16)
    if demand & 0xF0 == 0xF0:
        VALVE_STATE = {
            "F0": "open_circuit",
            "F1": "short_circuit",
            "FD": "valve_stuck",  # damper/valve stuck
            "FE": "actuator_stuck",
        }  # VALVE_STATE.get(value, "malfunction")
        return {
            "heat_demand": None,
            "fault": VALVE_STATE.get(value, "malfunction"),
        }
    assert demand <= 200
    return {"heat_demand": demand / 200}


def periodic(period):
    def scheduler(fcn):
        async def wrapper(*args, **kwargs):
            while True:
                asyncio.create_task(fcn(*args, **kwargs))
                await asyncio.sleep(period)

        return wrapper

    return scheduler


def schedule_task(func, *args, delay=None, period=None, **kwargs) -> asyncio.Task:
    """Start a coro after delay seconds."""

    async def execute_func(func, *args, **kwargs):
        if iscoroutinefunction(func):
            return await func(*args, **kwargs)
        return func(*args, **kwargs)

    async def schedule_func(delay, period, func, *args, **kwargs):
        if delay:
            await asyncio.sleep(delay)
        await execute_func(func, *args, **kwargs)

        while period:
            await execute_func(func, *args, **kwargs)
            await asyncio.sleep(period)

    return asyncio.create_task(schedule_func(delay, period, func, *args, **kwargs))


def slugify_string(key: str) -> str:
    """Convert a string to snake_case."""
    string = re.sub(r"[\-\.\s]", "_", str(key))
    return (string[0]).lower() + re.sub(
        r"[A-Z]", lambda matched: f"_{matched.group(0).lower()}", string[1:]
    )
