#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - Helper functions."""

from datetime import datetime as dt
import re
from typing import List, Tuple, Union

from .const import HGI_DEVICE, NON_DEVICE, NUL_DEVICE, Address, id_to_address


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

    # if dtm < dt_now() + timedelta(minutes=1):
    #     raise ValueError("Invalid datetime")

    return _dtm_to_hex(*dtm.timetuple())


def dtm_from_hex(value: str) -> str:  # from parsers
    """Convert a hex string to an (naive, local) isoformat string."""
    #        00141B0A07E3  (...HH:MM:00)    for system_mode, zone_mode (schedules?)
    #      0400041C0A07E3  (...HH:MM:SS)    for sync_datetime

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


def extract_addrs(pkt: str) -> Tuple[Address, Address, List[Address]]:
    """Return the address fields."""

    addrs = [id_to_address(pkt[i : i + 9]) for i in range(11, 32, 10)]

    # This check will invalidate these rare pkts (which are never transmitted)
    # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF02FF
    # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF0200
    if not all(
        (
            addrs[0].id not in (NON_DEVICE.id, NUL_DEVICE.id),
            (addrs[1].id, addrs[2].id).count(NON_DEVICE.id) == 1,
        )
    ) and not all(
        (
            addrs[2].id not in (NON_DEVICE.id, NUL_DEVICE.id),
            addrs[0].id == addrs[1].id == NON_DEVICE.id,
        )
    ):
        raise TypeError("invalid addr set")

    device_addrs = list(filter(lambda x: x.type != "--", addrs))

    src_addr = device_addrs[0]
    dst_addr = device_addrs[1] if len(device_addrs) > 1 else NON_DEVICE

    if src_addr.id == dst_addr.id:
        src_addr = dst_addr
    elif src_addr.type == "18" and dst_addr.id == HGI_DEVICE.id:
        # 000  I --- 18:013393 18:000730 --:------ 0001 005 00FFFF0200 (valid, ex HGI80)
        pass  # the above has been used for port wakeup
    elif src_addr.type == dst_addr.type:
        # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5 (invalid)
        raise TypeError("invalid src/dst addr pair")

    if len(device_addrs) > 2:
        raise TypeError("too many addrs (i.e. three addrs)")

    return src_addr, dst_addr, addrs


def slugify_string(key: str) -> str:
    """Convert a string to snake_case."""
    string = re.sub(r"[\-\.\s]", "_", str(key))
    return (string[0]).lower() + re.sub(
        r"[A-Z]", lambda matched: f"_{matched.group(0).lower()}", string[1:]
    )
