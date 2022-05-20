#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Construct a command (packet that is to be sent).
"""

import asyncio
import json
import logging
import struct
import zlib
from datetime import datetime as dt
from datetime import timedelta as td
from typing import Optional

from .const import (
    SZ_FRAG_INDEX,
    SZ_FRAG_TOTAL,
    SZ_FRAGMENT,
    SZ_SCHEDULE,
    SZ_ZONE_IDX,
    __dev_mode__,
)
from .protocol.command import (
    FUNC,
    TIMEOUT,
    TIMER_LONG_TIMEOUT,
    TIMER_SHORT_SLEEP,
    Command,
)
from .protocol.exceptions import ExpiredCallbackError

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

FIVE_MINS = td(minutes=5)


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
        self._schedule_done = None

        self._num_frags = None
        self._rx_frags = None
        self._tx_frags = None

        self._msg_0006 = None

        # new
        self._fragments: dict = {}
        self._outdated: bool = True

        self._clear_fragments()

    def __repr__(self) -> str:
        return json.dumps(self.schedule) if self._schedule_done else None

    def __str__(self) -> str:
        return f"{self._zone} (schedule)"

    def _handle_msg(self, msg) -> None:
        """Process a schedule packet: if possible, create the corresponding schedule."""
        if msg.payload[SZ_FRAG_TOTAL] == 255:
            return

        if msg.payload[SZ_FRAG_TOTAL] != self._frag_total:
            self._clear_fragments()  # assume schedule has changed

        self._add_fragment(msg=msg)

    def _add_fragment(self, *, msg) -> None:
        """Add a valid fragment to the fragments table.

        If possible, check for a vaild schedule.
        """

        self._fragments[msg.payload[SZ_FRAG_INDEX]] = msg

        if len(self._fragments) == self._frag_total:
            try:
                self._schedule = self._frags_to_sched(
                    [v.payload[SZ_FRAGMENT] for k, v in sorted(self._fragments.items())]
                )
            except zlib.error:
                self._clear_fragments()  # schedule has changed
                if msg.payload[SZ_FRAG_TOTAL] != 1:  # msg likely part of new schedule
                    self._fragments[msg.payload[SZ_FRAG_INDEX]] = msg

    def _clear_fragments(self):
        """Clear the fragment DB, and optionally start with a new fragment."""
        self._fragments = {}
        self._schedule = None

    @property
    def _frag_total(self) -> Optional[int]:
        """Return the expected number of fragments."""
        for frag in self._fragments.values():  # they will all match
            return frag.payload[SZ_FRAG_TOTAL]

    @property
    def schedule(self) -> Optional[dict]:
        """Return the cached schedule without checking if it is the latest version."""
        if self._schedule is not None:  # and not self._outdated:
            return self._schedule
        return

        # TODO: WIP from here...

        if not self._schedule_done or None in self._rx_frags:
            return
        if self._schedule:
            return self._schedule

        if self._rx_frags[0][MSG].payload[SZ_FRAG_TOTAL] == 255:
            return {}

        try:
            self._schedule = self._frags_to_sched(
                [v for d in self._rx_frags for k, v in d.items() if k == SZ_FRAGMENT]
            )
        except zlib.error:
            self._clear_fragments()
            _LOGGER.exception("Invalid schedule fragments: %s", self._rx_frags)
            return

        # if len(self._fragments) == self._frag_total:
        #     try:
        #         self._schedule = self._frags_to_sched(
        #             [v.payload[SZ_FRAGMENT] for k, v in sorted(self._fragments.items())]
        #         )
        #     except zlib.error:
        #         self._clear_fragments(msg=msg)  # delete all fragments except this one

        return self._schedule

    async def is_dated(self, *, force_update: bool = False) -> bool:
        """Return True if the schedule is out of date (a newer version is available).

        If required, retreive the latest global change counter (version number) from
        the TCS (which may necessitate an RQ).

        There may be a false positive if another zone's schedule is changed when
        this zone's schedule has not. There may be a false negative if this zone's
        schedule was changed only very recently.
        """

        if not force_update:

            if self._outdated is True:
                return self._outdated

            if self._version is None or self._schedule is None:
                self._outdated = True
                return self._outdated

        old_ver = self._version
        self._version = await self.tcs.get_schedule_version(force_update=force_update)

        self._outdated = self._version > old_ver
        return self._outdated

    async def get_schedule(self, *, force_update: bool = False) -> dict:
        """Get the up-to-date schedule of a zone.

        Return the cached schedule (which may have been eavesdropped) only if the
        global change counter has not increased.
        Otherwise, RQ the latest schedule from the controller and return that.
        """

        if self._schedule and not await self.is_dated(force_update=force_update):
            return self._schedule

        self._clear_fragments()

        if not await self._obtain_lock(self.idx):  # TODO: should raise a TimeOut
            return

        self._rq_fragment(frag_cnt=0)  # calls loop.create_task()

        self._schedule_done = None
        time_start = dt.now()

        while not self._schedule_done:
            await asyncio.sleep(TIMER_SHORT_SLEEP)
            if dt.now() > time_start + TIMER_LONG_TIMEOUT:
                self._release_lock()
                raise ExpiredCallbackError(f"{self}: failed to get schedule")

        self._release_lock()

        return self.schedule

    def _rq_fragment(self, *, frag_cnt=0) -> None:
        """Request the next missing fragment (index starts at 1, not 0)."""
        _LOGGER.debug("Schedule(%s)._rq_fragment(%s)", self.id, frag_cnt)

        # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0100
        # RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0104 688...
        # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0204
        # RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0204 4AE...
        # RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0304
        # RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0304 6BE...

        def rq_callback(msg) -> None:
            if not msg:  # _LOGGER.debug()... TODO: needs fleshing out
                # TODO: remove any callbacks from self._gwy.msg_transport._callbacks
                _LOGGER.warning(f"Schedule({self.id}): Callback timed out")
                self._schedule_done = True
                return

            _LOGGER.debug(
                f"Schedule({self.id})._proc_fragment(msg), frag_idx=%s, frag_cnt=%s",
                msg.payload.get(SZ_FRAG_INDEX),
                msg.payload.get(SZ_FRAG_TOTAL),
            )

            if msg.payload[SZ_FRAG_TOTAL] == 255:  # no schedule (i.e. no zone)
                _LOGGER.warning(f"Schedule({self.id}): No schedule")

            elif msg.payload[SZ_FRAG_TOTAL] != len(self._rx_frags):  # e.g. 1st frag
                self._rx_frags = [None] * msg.payload[SZ_FRAG_TOTAL]

            self._rx_frags[msg.payload[SZ_FRAG_INDEX] - 1] = msg

            if None in self._rx_frags:  # there are still frags to get
                self._rq_fragment(frag_cnt=msg.payload[SZ_FRAG_TOTAL])
            else:
                self._schedule_done = True

        if frag_cnt == 0:
            self._rx_frags = [None]  # and: frag_idx = 0
        frag_idx = next(i for i, f in enumerate(self._rx_frags) if f is None)

        rq_callback = {FUNC: rq_callback, TIMEOUT: 1}
        cmd = Command.get_schedule_fragment(
            self.ctl.id, self.idx, frag_idx, frag_cnt, callback=rq_callback
        )
        self._gwy.send_cmd(cmd)

    async def set_schedule(self, schedule) -> None:
        """Set the schedule of a zone."""

        if not await self._obtain_lock(self.idx):  # TODO: should raise a TimeOut
            return

        self._schedule_done = None

        self._tx_frags = self._sched_to_frags(schedule)
        self._tx_fragment(frag_idx=0)

        time_start = dt.now()
        while not self._schedule_done:
            await asyncio.sleep(TIMER_SHORT_SLEEP)
            if dt.now() > time_start + TIMER_LONG_TIMEOUT:
                self._release_lock()
                raise ExpiredCallbackError(f"{self}: failed to set schedule")

        self._release_lock()

    def _tx_fragment(self, frag_idx=0) -> None:
        """Send the next fragment (index starts at 0)."""
        _LOGGER.debug(
            "Schedule(%s)._tx_fragment(%s/%s)",
            self.id,
            frag_idx + 1,
            len(self._tx_frags),
        )

        def tx_callback(msg) -> None:
            _LOGGER.debug(
                f"Schedule({self.id})._proc_fragment(msg), frag_idx=%s, frag_cnt=%s",
                msg.payload.get(SZ_FRAG_INDEX),
                msg.payload.get(SZ_FRAG_TOTAL),
            )

            if msg.payload[SZ_FRAG_INDEX] < msg.payload[SZ_FRAG_TOTAL]:
                self._tx_fragment(frag_idx=msg.payload.get(SZ_FRAG_INDEX))
            else:
                self._schedule_done = True

        tx_callback = {FUNC: tx_callback, TIMEOUT: 3}  # 1 sec too low
        cmd = Command.put_schedule_fragment(
            self.ctl.id,
            self.idx,
            frag_idx,
            len(self._tx_frags),
            self._tx_frags[frag_idx],
            callback=tx_callback,
        )
        self._gwy.send_cmd(cmd)

    @staticmethod
    def _frags_to_sched(frags: list) -> dict:
        """Convert a set of fragments (a blob) into a schedule.

        May raise a `zlib.error` exception.
        """
        # _LOGGER.debug(f"Sched({self})._frags_to_sched: array is: %s", frags)
        raw_schedule = zlib.decompress(bytearray.fromhex("".join(frags)))

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
                    HEAT_SETPOINT: temp / 100,
                }
            )

        schedule.append({DAY_OF_WEEK: old_day, SWITCHPOINTS: switchpoints})

        return {SZ_ZONE_IDX: f"{zone_idx:02X}", SZ_SCHEDULE: schedule}

    @staticmethod
    def _sched_to_frags(schedule: dict) -> list:
        # _LOGGER.debug(f"Sched({self})._sched_to_frags: array is: %s", schedule)
        frags = [
            (
                int(schedule[SZ_ZONE_IDX], 16),
                int(week_day[DAY_OF_WEEK]),
                int(setpoint[TIME_OF_DAY][:2]) * 60 + int(setpoint[TIME_OF_DAY][3:]),
                int(setpoint[HEAT_SETPOINT] * 100),
            )
            for week_day in schedule[SZ_SCHEDULE]
            for setpoint in week_day[SWITCHPOINTS]
        ]
        frags = [struct.pack("<xxxxBxxxBxxxHxxHxx", *s) for s in frags]

        cobj = zlib.compressobj(level=9, wbits=14)
        blob = b"".join(cobj.compress(s) for s in frags) + cobj.flush()
        blob = blob.hex().upper()

        return [blob[i : i + 82] for i in range(0, len(blob), 82)]

    @classmethod  # constructor using RP/0404 tuple
    def create_from_pkts(cls, zone, packets, **kwargs):
        """Constructor to initiate with a tuple of schedule fragments."""
        self = cls(zone, **kwargs)

        self._rx_frags = [None] * len(packets)
        for msg in packets:
            self._rx_frags[msg.payload[SZ_FRAG_INDEX] - 1] = {
                SZ_FRAGMENT: msg.payload[SZ_FRAGMENT],
                MSG: msg,
            }

        self._schedule_done = True

        return self if self.schedule else cls(zone, **kwargs)
