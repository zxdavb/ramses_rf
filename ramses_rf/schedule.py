#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Construct a command (packet that is to be sent).
"""

import logging
import struct
import zlib
from datetime import timedelta as td
from typing import Tuple

import voluptuous as vol

from ramses_rf.protocol.const import SZ_CHANGE_COUNTER

from .const import (
    SZ_FRAG_NUMBER,
    SZ_FRAGMENT,
    SZ_SCHEDULE,
    SZ_TOTAL_FRAGS,
    SZ_ZONE_IDX,
    __dev_mode__,
)
from .protocol.command import Command
from .protocol.message import Message

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
)

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    _0001,
    _0002,
    _0004,
    _0005,
    _0006,
    _0008,
    _0009,
    _000A,
    _000C,
    _000E,
    _0016,
    _0100,
    _0150,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _0B04,
    _1030,
    _1060,
    _1081,
    _1090,
    _1098,
    _10A0,
    _10B0,
    _10E0,
    _10E1,
    _1100,
    _11F0,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _12F0,
    _1300,
    _1F09,
    _1F41,
    _1FC9,
    _1FCA,
    _1FD0,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2389,
    _2400,
    _2401,
    _2410,
    _2420,
    _2D49,
    _2E04,
    _2E10,
    _30C9,
    _3110,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3200,
    _3210,
    _3220,
    _3221,
    _3223,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)


MSG = "msg"

DAY_OF_WEEK = "day_of_week"
HEAT_SETPOINT = "heat_setpoint"
SWITCHPOINTS = "switchpoints"
TIME_OF_DAY = "time_of_day"
ENABLED = "enabled"

FIVE_MINS = td(minutes=5)

REGEX_TIME_OF_DAY = r"^([0-1][0-9]|2[0-3]):[0-5][05]$"


def schema_sched(schema_switchpoint: vol.Schema) -> vol.Schema:
    schema_sched_day = vol.Schema(
        {
            vol.Required(DAY_OF_WEEK): int,
            vol.Required(SWITCHPOINTS): vol.All(
                [schema_switchpoint], vol.Length(min=1)
            ),
        },
        extra=vol.PREVENT_EXTRA,
    )
    return vol.Schema(
        vol.Schema([schema_sched_day], vol.Length(min=7, max=7)),
        extra=vol.PREVENT_EXTRA,
    )


SCHEMA_SWITCHPOINT_DHW = vol.Schema(
    {
        vol.Required(TIME_OF_DAY): vol.Match(REGEX_TIME_OF_DAY),
        vol.Required(ENABLED): bool,
    },
    extra=vol.PREVENT_EXTRA,
)
SCHEMA_SWITCHPOINT_ZON = vol.Schema(
    {
        vol.Required(TIME_OF_DAY): vol.Match(REGEX_TIME_OF_DAY),
        vol.Required(HEAT_SETPOINT): vol.All(
            vol.Coerce(float), vol.Range(min=5, max=35)
        ),
    },
    extra=vol.PREVENT_EXTRA,
)
SCHEMA_SCHEDULE_DHW = vol.Schema(
    {
        vol.Required(SZ_ZONE_IDX): "HW",
        vol.Required(SZ_SCHEDULE): schema_sched(SCHEMA_SWITCHPOINT_DHW),
    },
    extra=vol.PREVENT_EXTRA,
)
SCHEMA_SCHEDULE_ZON = vol.Schema(
    {
        vol.Required(SZ_ZONE_IDX): vol.Match(r"0[0-F]"),
        vol.Required(SZ_SCHEDULE): schema_sched(SCHEMA_SWITCHPOINT_ZON),
    },
    extra=vol.PREVENT_EXTRA,
)
SCHEMA_SCHEDULE = vol.Schema(
    vol.Any(SCHEMA_SCHEDULE_DHW, SCHEMA_SCHEDULE_ZON), extra=vol.PREVENT_EXTRA
)

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Schedule:  # 0404
    """The schedule of a zone."""

    def __init__(self, zone, **kwargs) -> None:

        self._loop = zone._gwy._loop

        self.id = zone.id
        self._zone = zone
        self.idx = zone.idx

        self.ctl = zone.ctl
        self.tcs = zone.tcs
        self._gwy = zone._gwy

        self._schedule = None
        self._schedule_done = None  # TODO: deprecate

        self._rx_frags = _init_set()
        self._tx_frags = _init_set()

        self._global_ver: int = None
        self._sched_ver: int = 0

    def __str__(self) -> str:
        return f"{self._zone} (schedule)"

    def _handle_msg(self, msg: Message) -> None:
        """Process a schedule packet: if possible, create the corresponding schedule."""

        if msg.code == _0006:
            self._global_ver = msg.payload[SZ_CHANGE_COUNTER]
            return

        # RP --- 01:145038 18:013393 --:------ 0404 007 002300080001FF  # 0404|RP|01:145038|FA01
        if msg.payload[SZ_TOTAL_FRAGS] != 255:
            self._rx_frags = self._add_fragment(self._rx_frags, msg.payload)

    def _add_fragment(self, frag_set, fragment) -> list:
        """Return a valid fragment set, after adding a fragment.

        Whenever the fragment table is full, check for a valid schedule.
        If required, start a new fragment set with the fragment.
        """

        if fragment[SZ_TOTAL_FRAGS] != _size_set(frag_set):  # schedule has changed
            return _init_set(fragment)

        frag_set[fragment[SZ_FRAG_NUMBER] - 1] = fragment

        if None in frag_set or self._test_set(frag_set):
            return frag_set

        return _init_set(fragment)

    async def _is_dated(self, *, force_io: bool = False) -> Tuple[bool, bool]:
        """Indicate if it is possible that a more recent schedule is available.

        If required, retrieve the latest global version (change counter) from the
        TCS.

        There may be a false positive if another zone's schedule is changed when
        this zone's schedule has not. There may be a false negative if this zone's
        schedule was changed only very recently and a cached global version was
        used.

        If `force_io`, then a true negative is guaranteed (it forces an RQ).
        """

        # this will not cause an I/O...
        if (
            not force_io
            and not self._sched_ver
            or (self._global_ver and self._global_ver > self._sched_ver)
        ):
            return True, False  # is_dated, did_io

        # this may cause an I/O...
        self._global_ver, did_io = await self.tcs._schedule_version()
        if did_io or self._global_ver > self._sched_ver:
            return self._global_ver > self._sched_ver, did_io  # is_dated, did_io

        if force_io:  # this will cause an I/O...
            self._global_ver, did_io = await self.tcs._schedule_version(
                force_io=force_io
            )

        return self._global_ver > self._sched_ver, did_io  # is_dated, did_io

    async def get_schedule(self, *, force_io: bool = False) -> dict:
        """Get the schedule of a zone.

        Return the cached schedule (which may have been eavesdropped) only if the
        global change counter has not increased.
        Otherwise, RQ the latest schedule from the controller and return that.

        If `force_io`, then the latest schedule is guaranteed (it forces an RQ).
        """

        async def get_fragment(frag_idx: int):  # may: TimeoutError?
            """Retreive a schedule fragment from the controller."""

            frag_set_size = 0 if frag_idx == 0 else _size_set(self._rx_frags)
            cmd = Command.get_schedule_fragment(
                self.ctl.id, self.idx, frag_idx + 1, frag_set_size
            )
            return (await self._gwy.async_send_cmd(cmd)).payload  # may: TimeoutError?

        async def get_tst_fragment(frag_idx):
            self._rx_frags[frag_idx] = await get_fragment(frag_idx)
            if self._test_set(self._rx_frags):
                self._sched_ver = self._global_ver
                self.tcs._release_lock()
                return self._schedule

        is_dated, did_io = await self._is_dated(force_io=force_io)
        if is_dated:
            self._schedule = None  # keep fragments, maybe not this sched that changed
        if self._schedule:
            return self._schedule

        await self.tcs._obtain_lock(self.idx)  # maybe raise TimeOutError

        if not did_io:  # must know the version of the schedule about to be RQ'd
            self._global_ver, _ = await self.tcs._schedule_version(force_io=True)

        # if the 1st fragment is unchanged, then this schedule very likely unchanged
        if schedule := await get_tst_fragment(0):
            return schedule

        self._rx_frags = _init_set(self._rx_frags[0])
        while frag_idx := next(i for i, f in enumerate(self._rx_frags) if f is None):
            if schedule := await get_tst_fragment(frag_idx):
                return schedule

        return self._schedule

    def _test_set(self, frag_set: list) -> bool:
        """Test a fragment set, and cache any valid schedule as the `_schedule` attr."""

        if None in frag_set:
            return False

        try:
            self._schedule = fragments_to_schedule(
                [frag[SZ_FRAGMENT] for frag in frag_set]
            )
        except zlib.error:
            self._schedule = None  # needed?
            return False

        if self.idx == "HW":
            self._schedule[SZ_ZONE_IDX] = "HW"
        return True

    async def set_schedule(self, schedule, force_refresh=False) -> None:
        """Set the schedule of a zone."""

        async def put_fragment(frag_num, frag_cnt, fragment) -> None:
            """Send a schedule fragment to the controller."""

            #
            cmd = Command.set_schedule_fragment(
                self.ctl.id, self.idx, frag_num, frag_cnt, fragment
            )
            await self._gwy.async_send_cmd(cmd)

        if self.idx == "HW":
            schedule = {SZ_ZONE_IDX: "00", SZ_SCHEDULE: schedule}
            schema_schedule = SCHEMA_SCHEDULE_DHW
        else:
            schedule = {SZ_ZONE_IDX: self.idx, SZ_SCHEDULE: schedule}
            schema_schedule = SCHEMA_SCHEDULE_ZON

        try:
            schedule = schema_schedule(schedule)
        except vol.MultipleInvalid as exc:
            raise TypeError(f"failed to set schedule: {exc}")

        self._tx_frags = schedule_to_fragments(schedule)

        await self.tcs._obtain_lock(self.idx)  # maybe raise TimeOutError

        try:
            for num, frag in enumerate(self._tx_frags, 1):
                await put_fragment(num, len(self._tx_frags), frag)
        except TimeoutError as exc:
            raise TimeoutError(f"failed to set schedule: {exc}")
        else:
            if not force_refresh:
                self._global_ver, _ = await self.tcs._schedule_version(force_io=True)
                assert self._global_ver > self._sched_ver
                self._sched_ver = self._global_ver
        finally:
            self.tcs._release_lock()

        if force_refresh:
            self._schedule = await self.get_schedule(force_io=True)
        else:
            self._schedule = schedule[SZ_SCHEDULE]

        return self._schedule

    # @property
    # def schedule(self) -> dict:
    #     return {
    #         SZ_ZONE_IDX: "00" if self.idx == "HW" else self.idx,
    #         SZ_SCHEDULE: self._schedule
    #     }


def _init_set(fragment: dict = None) -> list:
    """Return a new fragment set, initialize it with a fragment if one is provided."""
    if fragment is None:
        return [None]
    frags = [None] * fragment[SZ_TOTAL_FRAGS]
    frags[fragment[SZ_FRAG_NUMBER] - 1] = fragment
    return frags


def _size_set(frag_set: list) -> int:
    """Return the number of fragments in the set or 0 if it is unknown."""
    for frag in (f for f in frag_set if f is not None):  # they will all match
        return frag[SZ_TOTAL_FRAGS]
    return 0  # sentinel value as per RAMSES protocol


def fragments_to_schedule(fragments: list) -> dict:
    """Convert a set of fragments (a blob) into a schedule.

    May raise a `zlib.error` exception.
    """

    raw_schedule = zlib.decompress(bytearray.fromhex("".join(fragments)))

    zone_idx, schedule = None, []
    old_day, switchpoints = 0, []

    for i in range(0, len(raw_schedule), 20):
        zone_idx, day, time, temp, _ = struct.unpack(
            "<xxxxBxxxBxxxHxxHH", raw_schedule[i : i + 20]
        )
        if day > old_day:
            schedule.append({DAY_OF_WEEK: old_day, SWITCHPOINTS: switchpoints})
            old_day, switchpoints = day, []
        switchpoints.append(
            {
                TIME_OF_DAY: "{0:02d}:{1:02d}".format(*divmod(time, 60)),
                **(
                    {ENABLED: bool(temp)}
                    if temp in (0, 1)
                    else {HEAT_SETPOINT: temp / 100}
                ),
            }
        )

    schedule.append({DAY_OF_WEEK: old_day, SWITCHPOINTS: switchpoints})

    return {SZ_ZONE_IDX: f"{zone_idx:02X}", SZ_SCHEDULE: schedule}


def schedule_to_fragments(schedule: dict) -> list:
    """Convert a schedule into a set of fragments (a blob).

    May raise `KeyError`, `zlib.error` exceptions.
    """

    frags = [
        (
            int(schedule[SZ_ZONE_IDX], 16),
            int(week_day[DAY_OF_WEEK]),
            int(setpoint[TIME_OF_DAY][:2]) * 60 + int(setpoint[TIME_OF_DAY][3:]),
            int(
                (setpoint[HEAT_SETPOINT] * 100)
                if setpoint.get(HEAT_SETPOINT)
                else setpoint[ENABLED]
            ),
        )
        for week_day in schedule[SZ_SCHEDULE]
        for setpoint in week_day[SWITCHPOINTS]
    ]
    frags = [struct.pack("<xxxxBxxxBxxxHxxHxx", *s) for s in frags]

    cobj = zlib.compressobj(level=9, wbits=14)
    blob = b"".join(cobj.compress(s) for s in frags) + cobj.flush()
    blob = blob.hex().upper()

    return [blob[i : i + 82] for i in range(0, len(blob), 82)]

    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0100
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0104 688...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0204
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0204 4AE...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0304
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0304 6BE...
