#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Helper functions."""

from datetime import datetime as dt
import re
from typing import Union


def slugify_string(key: str) -> str:
    """Convert a string to snake_case."""
    string = re.sub(r"[\-\.\s]", "_", str(key))
    return (string[0]).lower() + re.sub(
        r"[A-Z]", lambda matched: f"_{matched.group(0).lower()}", string[1:]
    )


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
