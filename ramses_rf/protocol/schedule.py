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

from .command import FUNC, TIMEOUT, TIMER_LONG_TIMEOUT, TIMER_SHORT_SLEEP, Command
from .exceptions import ExpiredCallbackError

from .const import I_, RP, RQ, W_, __dev_mode__  # noqa: F401, isort: skip
from .const import (  # noqa: F401, isort: skip
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
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _0B04,
    _1030,
    _1060,
    _1090,
    _10A0,
    _10E0,
    _1100,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _1F09,
    _1F41,
    _1FC9,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2D49,
    _2E04,
    _30C9,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3220,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)


ZONE_IDX = "zone_idx"
MSG = "msg"

DAY_OF_WEEK = "day_of_week"
HEAT_SETPOINT = "heat_setpoint"
SWITCHPOINTS = "switchpoints"
TIME_OF_DAY = "time_of_day"

SCHEDULE = "schedule"

FIVE_MINS = td(minutes=5)

FRAGMENT = "fragment"
FRAG_INDEX = "frag_index"
FRAG_TOTAL = "frag_total"


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Schedule:  # 0404
    """The schedule of a zone."""

    def __init__(self, zone, **kwargs) -> None:
        _LOGGER.debug("Schedule(zone=%s).__init__()", zone.id)  # TODO: str(zone) breaks

        self._loop = zone._gwy._loop

        self.id = zone.id
        self._zone = zone
        self.idx = zone.idx

        self._ctl = zone._ctl
        self._evo = zone._evo
        self._gwy = zone._gwy

        self._schedule = None
        self._schedule_done = None

        # initialse the fragment array()
        self._num_frags = None
        self._rx_frags = None
        self._tx_frags = None

    def __repr_(self) -> str:
        return json.dumps(self.schedule) if self._schedule_done else None

    def __str_(self) -> str:
        return f"{self._zone} (schedule)"

    @property
    def schedule(self) -> Optional[dict]:
        """Return the schedule of a zone."""
        if not self._schedule_done or None in self._rx_frags:
            return
        if self._schedule:
            return self._schedule

        if self._rx_frags[0][MSG].payload[FRAG_TOTAL] == 255:
            return {}

        frags = [v for d in self._rx_frags for k, v in d.items() if k == FRAGMENT]

        try:
            self._schedule = self._frags_to_sched(frags)
        except zlib.error:
            self._schedule = None
            _LOGGER.exception("Invalid schedule fragments: %s", frags)
            return

        return self._schedule

    async def get_schedule(self, force_refresh=None) -> Optional[dict]:
        """Get the schedule of a zone."""
        _LOGGER.debug(f"Schedule({self.id}).get_schedule()")

        if not await self._obtain_lock():  # TODO: should raise a TimeOut
            return

        if force_refresh:
            self._schedule_done = None

        if not self._schedule_done:
            self._rq_fragment(frag_cnt=0)  # calls loop.create_task()

            time_start = dt.now()
            while not self._schedule_done:
                await asyncio.sleep(TIMER_SHORT_SLEEP)
                if dt.now() > time_start + TIMER_LONG_TIMEOUT:
                    self._release_lock()
                    raise ExpiredCallbackError(f"{self}: failed to get schedule")

        self._release_lock()

        return self.schedule

    def _rq_fragment(self, frag_cnt=0) -> None:
        """Request the next missing fragment (index starts at 1, not 0)."""
        _LOGGER.debug("Schedule(%s)._rq_fragment(%s)", self.id, frag_cnt)

        def oth_callback(msg) -> None:
            _LOGGER.warning(f"Schedule({self.id}): Received {msg._pkt}")
            self._0006 = msg

        def rq_callback(msg) -> None:
            if not msg:  # _LOGGER.debug()... TODO: needs fleshing out
                # TODO: remove any callbacks from msg._gwy.msg_transport._callbacks
                _LOGGER.warning(f"Schedule({self.id}): Callback timed out")
                self._schedule_done = True
                return

            _LOGGER.debug(
                f"Schedule({self.id})._proc_fragment(msg), frag_idx=%s, frag_cnt=%s",
                msg.payload.get(FRAG_INDEX),
                msg.payload.get(FRAG_TOTAL),
            )

            if msg.payload[FRAG_TOTAL] == 255:  # no schedule (i.e. no zone)
                _LOGGER.warning(f"Schedule({self.id}): No schedule")
                # TODO: remove any callbacks from msg._gwy.msg_transport._callbacks
                # self._rx_frags = [None]

            elif msg.payload[FRAG_TOTAL] != len(self._rx_frags):  # e.g. 1st frag
                self._rx_frags = [None] * msg.payload[FRAG_TOTAL]

            self._rx_frags[msg.payload[FRAG_INDEX] - 1] = {
                FRAGMENT: msg.payload[FRAGMENT],
                MSG: msg,
            }

            # discard any fragments significantly older that this most recent fragment
            for frag in [f for f in self._rx_frags if f is not None]:
                frag = None if frag[MSG].dtm < msg.dtm - FIVE_MINS else frag

            if None in self._rx_frags:  # there are still frags to get
                self._rq_fragment(frag_cnt=msg.payload[FRAG_TOTAL])
            else:
                self._schedule_done = True

        if frag_cnt == 0:
            self._rx_frags = [None]  # and: frag_idx = 0

        frag_idx = next((i for i, f in enumerate(self._rx_frags) if f is None), -1)

        # 053 RQ --- 30:185469 01:037519 --:------ 0006 001 00
        # 045 RP --- 01:037519 30:185469 --:------ 0006 004 000500E6

        # 059 RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0100
        # 045 RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0104 688...
        # 059 RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0204
        # 045 RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0204 4AE...
        # 059 RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0304
        # 046 RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0304 6BE...

        rq_callback = {FUNC: rq_callback, TIMEOUT: 1}
        cmd = Command.get_schedule_fragment(
            self._ctl.id, self.idx, frag_idx, frag_cnt, callback=rq_callback
        )
        self._gwy.send_cmd(cmd)
        # NOTE: have a signature of the schedule to check against future 0006 pkts
        cmd = Command(RQ, _0006, "00", self._ctl.id, callback=oth_callback)
        self._gwy.send_cmd(cmd)

    @staticmethod
    def _frags_to_sched(frags: list) -> dict:
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

        return {ZONE_IDX: f"{zone_idx:02X}", SCHEDULE: schedule}

    @staticmethod
    def _sched_to_frags(schedule: dict) -> list:
        # _LOGGER.debug(f"Sched({self})._sched_to_frags: array is: %s", schedule)
        frags = [
            (
                int(schedule[ZONE_IDX], 16),
                int(week_day[DAY_OF_WEEK]),
                int(setpoint[TIME_OF_DAY][:2]) * 60 + int(setpoint[TIME_OF_DAY][3:]),
                int(setpoint[HEAT_SETPOINT] * 100),
            )
            for week_day in schedule[SCHEDULE]
            for setpoint in week_day[SWITCHPOINTS]
        ]
        frags = [struct.pack("<xxxxBxxxBxxxHxxHxx", *s) for s in frags]

        cobj = zlib.compressobj(level=9, wbits=14)
        blob = b"".join(cobj.compress(s) for s in frags) + cobj.flush()
        blob = blob.hex().upper()

        return [blob[i : i + 82] for i in range(0, len(blob), 82)]

    async def set_schedule(self, schedule) -> None:
        """Set the schedule of a zone."""
        _LOGGER.debug(f"Schedule({self.id}).set_schedule(schedule)")

        if not await self._obtain_lock():  # TODO: should raise a TimeOut
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
                msg.payload.get(FRAG_INDEX),
                msg.payload.get(FRAG_TOTAL),
            )

            if msg.payload[FRAG_INDEX] < msg.payload[FRAG_TOTAL]:
                self._tx_fragment(frag_idx=msg.payload.get(FRAG_INDEX))
            else:
                self._schedule_done = True

        tx_callback = {FUNC: tx_callback, TIMEOUT: 3}  # 1 sec too low
        cmd = Command.put_schedule_fragment(
            self._ctl.id,
            self.idx,
            frag_idx,
            len(self._tx_frags),
            self._tx_frags[frag_idx],
            callback=tx_callback,
        )
        self._gwy.send_cmd(cmd)

    async def _obtain_lock(self) -> bool:  # Lock to prevent Rx/Tx at same time
        while True:

            self._evo.zone_lock.acquire()
            if self._evo.zone_lock_idx is None:
                self._evo.zone_lock_idx = self.idx
            self._evo.zone_lock.release()

            if self._evo.zone_lock_idx == self.idx:
                break

            await asyncio.sleep(0.1)  # gives the other zone enough time

        return True

    def _release_lock(self) -> None:
        self._evo.zone_lock.acquire()
        self._evo.zone_lock_idx = None
        self._evo.zone_lock.release()

    @classmethod  # constructor using RP/0404 tuple
    def create_from_pkts(cls, zone, packets, **kwargs):
        """Constructor to initiate with a tuple of schedule fragments."""
        self = cls(zone, **kwargs)

        self._rx_frags = [None] * len(packets)
        for msg in packets:
            self._rx_frags[msg.payload[FRAG_INDEX] - 1] = {
                FRAGMENT: msg.payload[FRAGMENT],
                MSG: msg,
            }

        self._schedule_done = True

        return self if self.schedule else cls(zone, **kwargs)
