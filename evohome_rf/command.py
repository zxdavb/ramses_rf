#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser.

Construct a command (packet that is to be sent).
"""

import asyncio
from datetime import datetime as dt, timedelta as td
from functools import total_ordering
import json
import logging
import struct
from types import SimpleNamespace
from typing import Optional
import zlib

from .const import (
    _dev_mode_,
    CODES_SANS_DOMAIN_ID,
    CODE_SCHEMA,
    COMMAND_FORMAT,
    COMMAND_REGEX,
    HGI_DEVICE,
)
from .exceptions import ExpiredCallbackError
from .helpers import dt_now, extract_addrs

DAY_OF_WEEK = "day_of_week"
HEAT_SETPOINT = "heat_setpoint"
SWITCHPOINTS = "switchpoints"
TIME_OF_DAY = "time_of_day"

SCHEDULE = "schedule"
ZONE_IDX = "zone_idx"

TIMER_SHORT_SLEEP = 0.05
TIMER_LONG_TIMEOUT = td(seconds=60)

FIVE_MINS = td(minutes=5)


Priority = SimpleNamespace(LOW=6, DEFAULT=4, HIGH=2, ASAP=0)

DEV_MODE = _dev_mode_

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def _pkt_header(pkt: str, rx_header=None) -> Optional[str]:
    """Return the QoS header of a packet."""

    verb = pkt[4:6]
    if rx_header:
        verb = "RP" if verb == "RQ" else " I"  # RQ/RP, or W/I
    code = pkt[41:45]
    src, dst, _ = extract_addrs(pkt)
    addr = dst.id if src.type == "18" else src.id
    payload = pkt[50:]

    header = "|".join((verb, addr, code))

    if code in ("0001", "7FFF") and rx_header:
        return

    if code in ("0005", "000C"):  # zone_idx, device_class
        return "|".join((header, payload[:4]))

    if code == "0404":  # zone_schedule: zone_idx, frag_idx
        return "|".join((header, payload[:2] + payload[10:12]))

    if code == "0418":  # fault_log: log_idx
        if payload == CODE_SCHEMA["0418"]["null_rp"]:
            return header
        return "|".join((header, payload[4:6]))

    if code in CODES_SANS_DOMAIN_ID:  # have no domain_id
        return header

    return "|".join((header, payload[:2]))  # assume has a domain_id


@total_ordering
class Command:
    """The command class."""

    def __init__(self, verb, dest_addr, code, payload, **kwargs) -> None:
        """Initialise the class."""

        self.verb = verb
        self.from_addr = kwargs.get("from_addr", HGI_DEVICE.id)
        self.dest_addr = dest_addr if dest_addr is not None else self.from_addr
        self.code = code
        self.payload = payload

        self._is_valid = None
        if not self.is_valid:
            raise ValueError(f"Invalid parameter values for command: {self}")

        self.callback = kwargs.get("callback", {})  # TODO: use voluptuous
        if self.callback:
            self.callback["args"] = self.callback.get("args", [])
            self.callback["kwargs"] = self.callback.get("kwargs", {})

        self.qos = self._qos
        self.qos.update(kwargs.get("qos", {}))
        self._priority = self.qos["priority"]
        self._priority_dtm = dt_now()  # used for __lt__, etc.

        self._rx_header = None
        self._tx_header = None

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""

        return COMMAND_FORMAT.format(
            self.verb,
            self.from_addr,
            self.dest_addr,
            self.code,
            int(len(self.payload) / 2),
            self.payload,
        )

    @property
    def _qos(self) -> dict:
        """Return the QoS params of this (request) packet."""

        # the defaults for these are in packet.py
        # qos = {"priority": Priority.DEFAULT, "retries": 3, "timeout": td(seconds=0.5)}
        qos = {"priority": Priority.DEFAULT, "retries": 3}

        if self.code in ("0016", "1F09") and self.verb == "RQ":
            qos.update({"priority": Priority.HIGH, "retries": 5})

        elif self.code == "0404" and self.verb in ("RQ", " W"):
            qos.update({"priority": Priority.HIGH, "timeout": td(seconds=0.30)})

        elif self.code == "0418" and self.verb == "RQ":
            qos.update({"priority": Priority.LOW, "retries": 3})

        return qos

    @property
    def tx_header(self) -> str:
        """Return the QoS header of this (request) packet."""
        if self._tx_header is None:
            self._tx_header = _pkt_header(f"... {self}")
        return self._tx_header

    @property
    def rx_header(self) -> Optional[str]:
        """Return the QoS header of a response packet (if any)."""
        if self.tx_header and self._rx_header is None:
            self._rx_header = _pkt_header(f"... {self}", rx_header=True)
        return self._rx_header

    @property
    def is_valid(self) -> Optional[bool]:
        """Return True if a valid command, otherwise return False/None."""

        if self._is_valid is not None:
            return self._is_valid

        if not COMMAND_REGEX.match(str(self)):
            self._is_valid = False
        elif 0 > len(self.payload) > 96:
            self._is_valid = False
        else:
            self._is_valid = True

        if not self._is_valid:
            _LOGGER.debug("Command has an invalid structure: %s", self)

        return self._is_valid

    @staticmethod
    def _is_valid_operand(other) -> bool:
        return hasattr(other, "_priority") and hasattr(other, "_priority_dtm")

    def __eq__(self, other) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self._priority, self._priority_dtm) == (
            other._priority,
            other._priority_dtm,
        )

    def __lt__(self, other) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self._priority, self._priority_dtm) < (
            other._priority,
            other._priority_dtm,
        )


class FaultLog:  # 0418
    """The fault log of a system."""

    def __init__(self, ctl, msg=None, **kwargs) -> None:
        _LOGGER.debug("FaultLog(ctl=%s).__init__()", ctl)

        self.id = ctl.id
        self._ctl = ctl
        # self._evo = ctl._evo
        self._gwy = ctl._gwy

        self._fault_log = None
        self._fault_log_done = None

        self._limit = 11  # TODO: make configurable

    def __repr_(self) -> str:
        return json.dumps(self._fault_log) if self._fault_log_done else None

    def __str_(self) -> str:
        return f"{self._ctl} (fault log)"

    @property
    def fault_log(self) -> Optional[dict]:
        """Return the fault log of a system."""
        if not self._fault_log_done:
            return

        result = {
            x: {k: v for k, v in y.items() if k[:1] != "_"}
            for x, y in self._fault_log.items()
        }

        return {k: [x for x in v.values()] for k, v in result.items()}

    async def get_fault_log(self, force_refresh=None) -> Optional[dict]:
        """Get the fault log of a system."""
        _LOGGER.debug("FaultLog(%s).get_fault_log()", self)

        self._fault_log = {}
        self._fault_log_done = None

        self._rq_log_entry(log_idx=0)  # calls asyncio.create_task()

        time_start = dt.now()
        while not self._fault_log_done:
            await asyncio.sleep(TIMER_SHORT_SLEEP)
            if dt.now() > time_start + TIMER_LONG_TIMEOUT * 2:
                raise ExpiredCallbackError("failed to obtain log entry (long)")

        return self.fault_log

    def _rq_log_entry(self, log_idx=0):
        """Request the next log entry."""
        _LOGGER.debug("FaultLog(%s)._rq_log_entry(%s)", self, log_idx)

        async def rq_callback(msg) -> None:
            _LOGGER.debug("FaultLog(%s)._proc_log_entry(%s)", self.id, msg)

            if not msg:
                self._fault_log_done = True
                # raise ExpiredCallbackError("failed to obtain log entry (short)")
                return

            if not msg.payload:
                # TODO: delete other callbacks rather than waiting for them to expire
                self._fault_log_done = True
                return

            log = dict(msg.payload)
            log_idx = int(log.pop("log_idx"), 16)
            self._fault_log[log_idx] = log

            if log_idx < self._limit:
                self._rq_log_entry(log_idx + 1)
            else:
                self._fault_log_done = True

        # TODO: (make method) register callback for null response (no log_idx left)
        header = "|".join(("RP", self.id, "0418"))
        if header not in self._gwy.msg_transport._callbacks:
            self._gwy.msg_transport._callbacks[header] = {
                "func": rq_callback,
                "daemon": True,
                "args": [],
                "kwargs": {},
            }

        callback = {"func": rq_callback, "timeout": td(seconds=10)}
        cmd = Command("RQ", self._ctl.id, "0418", f"{log_idx:06X}", callback=callback)
        asyncio.create_task(self._gwy.msg_protocol.send_data(cmd))


class Schedule:  # 0404
    """The schedule of a zone."""

    def __init__(self, zone, **kwargs) -> None:
        _LOGGER.debug("Schedule(zone=%s).__init__()", zone)

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

        if self._rx_frags[0]["msg"].payload["frag_total"] == 255:
            return {}

        frags = [v for d in self._rx_frags for k, v in d.items() if k == "fragment"]

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
            self._rq_fragment(frag_cnt=0)  # calls asyncio.create_task()

            time_start = dt.now()
            while not self._schedule_done:
                await asyncio.sleep(TIMER_SHORT_SLEEP)
                if dt.now() > time_start + TIMER_LONG_TIMEOUT:
                    self._release_lock()
                    raise ExpiredCallbackError("failed to get schedule")

        self._release_lock()

        return self.schedule

    def _rq_fragment(self, frag_cnt=0) -> None:
        """Request the next missing fragment (index starts at 1, not 0)."""
        _LOGGER.debug("Schedule(%s)._rq_fragment(%s)", self.id, frag_cnt)

        async def rq_callback(msg) -> None:
            if not msg:  # _LOGGER.debug()... TODO: needs fleshing out
                # TODO: remove any callbacks from msg._gwy.msg_transport._callbacks
                _LOGGER.warning(f"Schedule({self.id}): Callback timed out")
                self._schedule_done = True
                return

            _LOGGER.debug(
                f"Schedule({self.id})._proc_fragment(msg), frag_idx=%s, frag_cnt=%s",
                msg.payload.get("frag_index"),
                msg.payload.get("frag_total"),
            )

            if msg.payload["frag_total"] == 255:  # no schedule (i.e. no zone)
                _LOGGER.warning(f"Schedule({self.id}): No schedule")
                # TODO: remove any callbacks from msg._gwy.msg_transport._callbacks
                pass  # self._rx_frags = [None]

            elif msg.payload["frag_total"] != len(self._rx_frags):  # e.g. 1st frag
                self._rx_frags = [None] * msg.payload["frag_total"]

            self._rx_frags[msg.payload["frag_index"] - 1] = {
                "fragment": msg.payload["fragment"],
                "msg": msg,
            }

            # discard any fragments significantly older that this most recent fragment
            for frag in [f for f in self._rx_frags if f is not None]:
                frag = None if frag["msg"].dtm < msg.dtm - FIVE_MINS else frag

            if None in self._rx_frags:  # there are still frags to get
                self._rq_fragment(frag_cnt=msg.payload["frag_total"])
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

        payload = f"{self.idx}20000800{frag_idx + 1:02d}{frag_cnt:02d}"  # DHW: 23000800
        callback = {"func": rq_callback, "timeout": td(seconds=1)}
        cmd = Command("RQ", self._ctl.id, "0404", payload, callback=callback)
        asyncio.create_task(self._gwy.msg_protocol.send_data(cmd))

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
        blob = b"".join([cobj.compress(s) for s in frags]) + cobj.flush()
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
                raise ExpiredCallbackError("failed to set schedule")

        self._release_lock()

    def _tx_fragment(self, frag_idx=0) -> None:
        """Send the next fragment (index starts at 0)."""
        _LOGGER.debug(
            "Schedule(%s)._tx_fragment(%s/%s)", self.id, frag_idx, len(self._tx_frags)
        )

        async def tx_callback(msg) -> None:
            _LOGGER.debug(
                f"Schedule({self.id})._proc_fragment(msg), frag_idx=%s, frag_cnt=%s",
                msg.payload.get("frag_index"),
                msg.payload.get("frag_total"),
            )

            if msg.payload["frag_index"] < msg.payload["frag_total"]:
                self._tx_fragment(frag_idx=msg.payload.get("frag_index"))
            else:
                self._schedule_done = True

        payload = "{0}200008{1:02X}{2:02d}{3:02d}{4:s}".format(
            self.idx,
            int(len(self._tx_frags[frag_idx]) / 2),
            frag_idx + 1,
            len(self._tx_frags),
            self._tx_frags[frag_idx],
        )
        callback = {"func": tx_callback, "timeout": td(seconds=3)}  # 1 sec too low
        cmd = Command(" W", self._ctl.id, "0404", payload, callback=callback)
        asyncio.create_task(self._gwy.msg_protocol.send_data(cmd))

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
