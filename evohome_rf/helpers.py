#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - Helper functions."""

import ctypes
import re
import sys
import time
from datetime import datetime as dt
from typing import List, Optional, Tuple, Union

from .const import (
    DEVICE_ID_REGEX,
    DEVICE_LOOKUP,
    DEVICE_TYPES,
    HGI_DEV_ADDR,
    NON_DEV_ADDR,
    NUL_DEV_ADDR,
    Address,
    id_to_address,
)
from .exceptions import CorruptAddrSetError


class FILETIME(ctypes.Structure):
    """Data structure for GetSystemTimePreciseAsFileTime()."""

    _fields_ = [("dwLowDateTime", ctypes.c_uint), ("dwHighDateTime", ctypes.c_uint)]


def dt_now() -> dt:
    """Return the time now as a UTC datetime object."""
    return dt.fromtimestamp(time_time())


def dt_str() -> str:
    """Return the time now as a isoformat string."""
    now = time_time()
    mil = f"{now%1:.6f}".lstrip("0")
    return time.strftime(f"%Y-%m-%dT%H:%M:%S{mil}", time.localtime(now))


def time_time() -> float:
    """Return the number of seconds since the Unix epoch.

    Return an accurate value, even for Windows-based systems.
    """  # see: https://www.python.org/dev/peps/pep-0564/
    if sys.platform != "win32":
        return time.time()  # since 1970-01-01T00:00:00Z, time.gmtime(0)
    file_time = FILETIME()
    ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(file_time))
    _time = (file_time.dwLowDateTime + (file_time.dwHighDateTime << 32)) / 1e7
    return _time - 134774 * 24 * 60 * 60  # otherwise, is since 1601-01-01T00:00:00Z


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

    # if dtm < dt_now() + td(minutes=1):
    #     raise ValueError("Invalid datetime")

    return _dtm_to_hex(*dtm.timetuple())


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
    ).strftime("%Y-%m-%d %H:%M:%S")


def temp_to_hex(value: int) -> str:
    """Convert an int to a 2-byte hex string."""
    if value is None:
        return "7FFF"  # or: "31FF"?
    if value is False:
        return "7EFF"
    temp = int(value * 100)
    if temp < 0:
        temp += 2 ** 16
    return f"{temp:04X}"


def str_to_hex(value: str) -> str:
    """Convert a string to a variable-length ASCII hex string."""
    return "".join([f"{ord(x):02X}" for x in value])


def is_valid_dev_id(value) -> bool:
    if not isinstance(value, str):
        return False

    elif not DEVICE_ID_REGEX.match(value):
        return False

    elif value[:2] not in DEVICE_TYPES:
        return False

    return True


def dev_hex_to_id(device_hex: str, friendly_id=False) -> str:
    """Convert (say) '06368E' to '01:145038' (or 'CTL:145038')."""

    if device_hex == "FFFFFE":  # aka '63:262142'
        return ">null dev<" if friendly_id else NUL_DEV_ADDR.id

    if not device_hex.strip():  # aka '--:------'
        return f"{'':10}" if friendly_id else NON_DEV_ADDR.id

    _tmp = int(device_hex, 16)
    dev_type = f"{(_tmp & 0xFC0000) >> 18:02d}"
    if friendly_id:
        dev_type = DEVICE_TYPES.get(dev_type, f"{dev_type:<3}")

    return f"{dev_type}:{_tmp & 0x03FFFF:06d}"


def dev_id_to_hex(device_id: str) -> str:
    """Convert (say) '01:145038' (or 'CTL:145038') to '06368E'."""

    if len(device_id) == 9:  # e.g. '01:123456'
        dev_type = device_id[:2]

    else:  # len(device_id) == 10, e.g. 'CTL:123456', or ' 63:262142'
        dev_type = DEVICE_LOOKUP.get(device_id[:3], device_id[1:3])

    return f"{(int(dev_type) << 18) + int(device_id[-6:]):0>6X}"  # no preceding 0x


def extract_addrs(pkt_fragment: str) -> Tuple[Address, Address, List[Address]]:
    """Return the address fields from (e.g): '01:078710 --:------ 01:144246 '."""

    addrs = [id_to_address(pkt_fragment[i : i + 9]) for i in range(0, 30, 10)]

    # This check will invalidate these rare pkts (which are never transmitted)
    # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF02FF
    # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF0200
    if not all(
        (
            addrs[0].id not in (NON_DEV_ADDR.id, NUL_DEV_ADDR.id),
            (addrs[1].id, addrs[2].id).count(NON_DEV_ADDR.id) == 1,
        )
    ) and not all(
        (
            addrs[2].id not in (NON_DEV_ADDR.id, NUL_DEV_ADDR.id),
            addrs[0].id == addrs[1].id == NON_DEV_ADDR.id,
        )
    ):
        raise CorruptAddrSetError(f"Invalid addr set: {pkt_fragment}")

    device_addrs = list(filter(lambda x: x.type != "--", addrs))
    if len(device_addrs) > 2:
        raise CorruptAddrSetError(f"Invalid addr set (i.e. 3 addrs): {pkt_fragment}")

    src_addr = device_addrs[0]
    dst_addr = device_addrs[1] if len(device_addrs) > 1 else NON_DEV_ADDR

    if src_addr.id == dst_addr.id:
        src_addr = dst_addr
    elif src_addr.type == "18" and dst_addr.id == HGI_DEV_ADDR.id:
        # 000  I --- 18:013393 18:000730 --:------ 0001 005 00FFFF0200 (valid, ex HGI80)
        raise CorruptAddrSetError(f"Invalid src/dst addr pair: {pkt_fragment}")
        # pass
    elif dst_addr.type == "18" and src_addr.id == HGI_DEV_ADDR.id:
        raise CorruptAddrSetError(f"Invalid src/dst addr pair: {pkt_fragment}")
        # pass
    elif {src_addr.type, dst_addr.type}.issubset({"01", "23"}):
        raise CorruptAddrSetError(f"Invalid src/dst addr pair: {pkt_fragment}")
    elif src_addr.type == dst_addr.type:
        # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5 (invalid)
        raise CorruptAddrSetError(f"Invalid src/dst addr pair: {pkt_fragment}")

    return src_addr, dst_addr, addrs


def slugify_string(key: str) -> str:
    """Convert a string to snake_case."""
    string = re.sub(r"[\-\.\s]", "_", str(key))
    return (string[0]).lower() + re.sub(
        r"[A-Z]", lambda matched: f"_{matched.group(0).lower()}", string[1:]
    )
