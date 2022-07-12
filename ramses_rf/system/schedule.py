#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Construct a command (packet that is to be sent).
"""
from __future__ import annotations

import asyncio
import logging
import struct
import zlib
from datetime import timedelta as td
from typing import Any, Iterable, Tuple

import voluptuous as vol  # type: ignore[import]

from ramses_rf.protocol.const import SZ_CHANGE_COUNTER

from ..const import (
    SZ_FRAG_NUMBER,
    SZ_FRAGMENT,
    SZ_SCHEDULE,
    SZ_TOTAL_FRAGS,
    SZ_ZONE_IDX,
    __dev_mode__,
)
from ..protocol.command import Command
from ..protocol.message import Message

# skipcq: PY-W2000
from ..const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
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


SCH_SWITCHPOINT_DHW = vol.Schema(
    {
        vol.Required(TIME_OF_DAY): vol.Match(REGEX_TIME_OF_DAY),
        vol.Required(ENABLED): bool,
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_SWITCHPOINT_ZON = vol.Schema(
    {
        vol.Required(TIME_OF_DAY): vol.Match(REGEX_TIME_OF_DAY),
        vol.Required(HEAT_SETPOINT): vol.All(
            vol.Coerce(float), vol.Range(min=5, max=35)
        ),
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_SCHEDULE_DHW = vol.Schema(
    {
        vol.Required(SZ_ZONE_IDX): "HW",
        vol.Required(SZ_SCHEDULE): schema_sched(SCH_SWITCHPOINT_DHW),
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_SCHEDULE_ZON = vol.Schema(
    {
        vol.Required(SZ_ZONE_IDX): vol.Match(r"0[0-F]"),
        vol.Required(SZ_SCHEDULE): schema_sched(SCH_SWITCHPOINT_ZON),
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_SCHEDULE = vol.Schema(
    vol.Any(SCH_SCHEDULE_DHW, SCH_SCHEDULE_ZON), extra=vol.PREVENT_EXTRA
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

        self._schedule: None | dict[str, Any] = {}
        self._schedule_done = None  # TODO: deprecate

        self._rx_frags: list = self._init_set()
        self._tx_frags: list = self._init_set()

        self._global_ver: int = None  # type: ignore[assignment]
        self._sched_ver: int = 0

    def __str__(self) -> str:
        return f"{self._zone} (schedule)"

    def _handle_msg(self, msg: Message) -> None:
        """Process a schedule packet: if possible, create the corresponding schedule."""

        if msg.code == Code._0006:
            self._global_ver = msg.payload[SZ_CHANGE_COUNTER]
            return

        # next line also in self._get_schedule(), so protected here with a lock
        if msg.payload[SZ_TOTAL_FRAGS] != 255 and self.tcs.zone_lock_idx != self.idx:
            self._rx_frags = self._incr_set(self._rx_frags, msg.payload)

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

    async def get_schedule(self, *, force_io: bool = False) -> None | dict:
        """Retrieve/return the brief schedule of a zone.

        Return the cached schedule (which may have been eavesdropped) only if the
        global change counter has not increased.
        Otherwise, RQ the latest schedule from the controller and return that.

        If `force_io`, then the latest schedule is guaranteed (it forces an RQ).
        """

        try:
            await asyncio.wait_for(self._get_schedule(force_io=force_io), timeout=15)
        except asyncio.TimeoutError:
            raise
        return self.schedule

    async def _get_schedule(self, *, force_io: bool = False) -> None | dict:
        """Retrieve/return the brief schedule of a zone."""

        async def get_fragment(frag_num: int):  # may: TimeoutError?
            """Retreive a schedule fragment from the controller."""

            frag_set_size = 0 if frag_num == 1 else self._size_set(self._rx_frags)
            cmd = Command.get_schedule_fragment(
                self.ctl.id, self.idx, frag_num, frag_set_size
            )
            return (await self._gwy.async_send_cmd(cmd)).payload  # may: TimeoutError?

        async def get_tst_fragment(frag_idx: int):
            if self._incr_set(self._rx_frags, await get_fragment(frag_idx)):
                self._sched_ver = self._global_ver
                return self._schedule

        is_dated, did_io = await self._is_dated(force_io=force_io)
        if is_dated:
            self._schedule = {}  # keep fragments, maybe only other sched(s) changed
        if self._schedule:
            return self.schedule

        await self.tcs._obtain_lock(self.idx)  # maybe raise TimeOutError

        if not did_io:  # must know the version of the schedule about to be RQ'd
            self._global_ver, _ = await self.tcs._schedule_version(force_io=True)

        self._rx_frags[0] = None  # if 1st frag valid: schedule very likely unchanged
        while frag_num := next(i for i, f in enumerate(self._rx_frags, 1) if f is None):
            fragment = await get_fragment(frag_num)
            # next line also in self._handle_msg(), so protected there with a lock
            self._rx_frags = self._incr_set(self._rx_frags, fragment)
            if self._schedule:  # TODO: potential for infinite loop?
                self._sched_ver = self._global_ver
                break

        self.tcs._release_lock()
        return self.schedule

    def _proc_set(self, frag_set: list) -> None | dict:  # return full_schedule
        """Process a frag set and return the full schedule (sets `self._schedule`).

        If the schedule is for DHW, set the `zone_idx` key to 'HW' (to avoid confusing
        with zone '00').
        """
        if frag_set == self._init_set(None):
            self._schedule = {SZ_ZONE_IDX: self.idx, SZ_SCHEDULE: None}
            return self._schedule
        try:
            schedule = fragments_to_schedule((frag[SZ_FRAGMENT] for frag in frag_set))
        except zlib.error:
            return None
        if self.idx == "HW":
            schedule[SZ_ZONE_IDX] = "HW"
        self._schedule = schedule
        return self._schedule  # NOTE: not self.schedule

    @staticmethod
    def _init_set(fragment: dict = None) -> list:  # return frag_set
        """Return a new frag set, after initializing it with an optional fragment."""
        if fragment is None or fragment[SZ_TOTAL_FRAGS] is None:
            return [None]
        frag_set = [None] * fragment[SZ_TOTAL_FRAGS]
        frag_set[fragment[SZ_FRAG_NUMBER] - 1] = fragment
        return frag_set

    @staticmethod
    def _size_set(frag_set: list) -> int:  # return len(frag_set)
        """Return the total number of fragments in the complete frag set.

        Return 0 if the expected set size is unknown (sentinel value as per RAMSES II).

        Uses frag_set[i][SZ_TOTAL_FRAGS] instead of `len(frag_set)` (is necessary?).
        """
        for frag in (f for f in frag_set if f is not None):  # they will all match
            assert len(frag_set) == frag[SZ_TOTAL_FRAGS]  # TODO: remove
            return frag[SZ_TOTAL_FRAGS]
        assert len(frag_set) == 1 and frag_set == [None]  # TODO: remove
        return 0  # sentinel value as per RAMSES protocol

    def _incr_set(self, frag_set: list, fragment: dict) -> list:  # return frag_set
        """Add a fragment to a frag set and process/return the new set.

        If the frag set is complete, check for a schedule (sets `self._schedule`).

        If required, start a new frag set with the fragment.
        """
        if fragment[SZ_TOTAL_FRAGS] is None:  # zone has no schedule
            frag_set = self._init_set(None)
            self._proc_set(frag_set)
            return frag_set
        if fragment[SZ_TOTAL_FRAGS] != self._size_set(frag_set):  # schedule has changed
            return self._init_set(fragment)
        frag_set[fragment[SZ_FRAG_NUMBER] - 1] = fragment
        if None in frag_set or self._proc_set(frag_set):  # sets self._schedule
            return frag_set
        return self._init_set(fragment)

    async def set_schedule(self, schedule, force_refresh=False) -> None | dict:
        """Set the schedule of a zone."""

        async def put_fragment(frag_num, frag_cnt, fragment) -> None:
            """Send a schedule fragment to the controller."""

            #
            cmd = Command.set_schedule_fragment(
                self.ctl.id, self.idx, frag_num, frag_cnt, fragment
            )
            await self._gwy.async_send_cmd(cmd)

        def normalise_validate(schedule) -> dict:
            if self.idx == "HW":
                schedule = {SZ_ZONE_IDX: "HW", SZ_SCHEDULE: schedule}
                schema_schedule = SCH_SCHEDULE_DHW
            else:
                schedule = {SZ_ZONE_IDX: self.idx, SZ_SCHEDULE: schedule}
                schema_schedule = SCH_SCHEDULE_ZON

            try:
                schedule = schema_schedule(schedule)
            except vol.MultipleInvalid as exc:
                raise TypeError(f"failed to set schedule: {exc}")

            if self.idx == "HW":
                schedule[SZ_ZONE_IDX] = "00"

            return schedule

        schedule = normalise_validate(schedule)
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
                # assert self._global_ver > self._sched_ver
                self._sched_ver = self._global_ver
        finally:
            self.tcs._release_lock()

        if force_refresh:
            self._schedule = await self.get_schedule(force_io=True)
        else:
            self._schedule = schedule

        return self.schedule

    @property
    def schedule(self) -> None | dict:
        if not self._schedule:
            return None
        return self._schedule[SZ_SCHEDULE]


def fragments_to_schedule(fragments: Iterable) -> dict:
    """Convert a set of fragments (a blob) into a schedule.

    May raise a `zlib.error` exception.
    """

    raw_schedule = zlib.decompress(bytearray.fromhex("".join(fragments)))

    old_day = 0
    schedule = []
    switchpoints: list[dict] = []
    zone_idx = None

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
    frags_: list[bytes] = [struct.pack("<xxxxBxxxBxxxHxxHxx", *s) for s in frags]

    cobj = zlib.compressobj(level=9, wbits=14)
    blob = (b"".join(cobj.compress(s) for s in frags_) + cobj.flush()).hex().upper()

    return [blob[i : i + 82] for i in range(0, len(blob), 82)]

    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0100
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0104 688...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0204
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0204 4AE...
    # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0304
    # RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0304 6BE...
