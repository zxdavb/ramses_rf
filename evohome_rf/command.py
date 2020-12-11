#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome serial."""

import asyncio
from datetime import timedelta
from functools import total_ordering
import json
import logging
import struct
from types import SimpleNamespace
from typing import Optional
import zlib

from .const import (
    __dev_mode__,
    CODES_SANS_DOMAIN_ID,
    CODE_SCHEMA,
    COMMAND_FORMAT,
    HGI_DEVICE,
)
from .logger import dt_now

# SERIAL_PORT = "serial_port"
# CMD_CODE = "cmd_code"
# CMD_VERB = "cmd_verb"
# PAYLOAD = "payload"

# DEVICE_1 = "device_1"
# DEVICE_2 = "device_2"
# DEVICE_3 = "device_3"

DAY_OF_WEEK = "day_of_week"
HEAT_SETPOINT = "heat_setpoint"
SWITCHPOINTS = "switchpoints"
TIME_OF_DAY = "time_of_day"

SCHEDULE = "schedule"
ZONE_IDX = "zone_idx"

FIVE_MINS = timedelta(minutes=5)


Priority = SimpleNamespace(LOW=6, DEFAULT=4, HIGH=2, ASAP=0)
Qos = SimpleNamespace(
    AT_MOST_ONCE=0,  # PUB (no handshake)
    AT_LEAST_ONCE=1,  # PUB, ACK (2-way handshake)
    EXACTLY_ONCE=2,  # PUB, REC, REL (FIN) (3/4-way handshake)
)

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


def _pkt_header(packet, response_header=None) -> Optional[str]:
    """Return the QoS header of a packet."""

    packet = str(packet)

    verb = packet[4:6]
    if response_header:
        verb = "RP" if verb == "RQ" else " I"  # RQ/RP, or W/I
    code = packet[41:45]
    addr = packet[21:30] if packet[11:13] == "18" else packet[11:20]
    payload = packet[50:]

    header = "|".join((verb, addr, code))

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

        self.qos = kwargs.get("qos", {})

        self.callback = kwargs.get("callback", {})  # TODO: use voluptuos
        if self.callback:
            self.callback["args"] = self.callback.get("args", [])
            self.callback["kwargs"] = self.callback.get("kwargs", {})

        priority = Priority.HIGH if verb in ("0016", "1FC9") else Priority.DEFAULT
        self._priority = self.qos["priority"] = self.qos.get("priority", priority)
        self._priority_dtm = dt_now()  # used for __lt__, etc.

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
    def _rq_header(self) -> Optional[str]:
        """Return the QoS header of this (request) packet."""
        return _pkt_header(f"... {self}")

    @property
    def _rp_header(self) -> Optional[str]:
        """Return the QoS header of a response packet (if any)."""
        if self._rq_header:  # will be None if RQ header is None
            return _pkt_header(f"... {self}", response_header=True)

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
        """Initialise the class."""
        _LOGGER.debug("FaultLog(%s).__init__()", ctl)

        self.id = ctl.id

        self._ctl = ctl
        # self._evo = ctl._evo
        self._gwy = ctl._gwy

        self._fault_log = None
        self._fault_log_done = None

        # TODO: (make method) register a callback for a null response (have no log_idx)
        self._gwy.msg_transport._callbacks["|".join(("RP", self.id, "0418"))] = {
            "func": self._proc_log_entry,
            "daemon": True,
            "args": [],
            "kwargs": {},
        }

    def __repr_(self) -> str:
        return json.dumps(self._fault_log) if self._fault_log_done else None

    def __str_(self) -> str:
        return f"{self._ctl} (fault log)"

    @property
    def fault_log(self) -> Optional[dict]:
        """Return the fault log of a system."""
        if self._fault_log_done:
            return {
                x: {k: v for k, v in y.items() if k[:1] != "_"}
                for x, y in self._fault_log.items()
            }

    @property
    def complete(self) -> Optional[bool]:
        """Return True if the fault log has been retreived in full."""
        return self._fault_log_done

    def start(self) -> None:
        _LOGGER.debug("FaultLog(%s).start()", self)

        self.reset()
        self._req_log_entry(0)

    def reset(self) -> None:
        _LOGGER.debug("FaultLog(%s).reset()", self)

        self._fault_log = {}
        self._fault_log_done = None

    def _req_log_entry(self, log_idx=0):
        """Request the next log entry."""
        _LOGGER.debug("FaultLog(%s)._req_log_entry(%s)", self, log_idx)

        def send_cmd(payload) -> None:
            qos = {
                "priority": Priority.LOW,
                "retries": 2,
                # "timeout": timedelta(seconds=1.0),
            }
            callback = {"func": self._proc_log_entry, "timeout": timedelta(seconds=1)}

            cmd = Command(
                "RQ", self._ctl.id, "0418", payload, qos=qos, callback=callback
            )
            asyncio.create_task(self._gwy.msg_protocol.send_data(cmd))

        send_cmd(f"{log_idx:06X}")

    def _proc_log_entry(self, msg) -> None:
        _LOGGER.debug("FaultLog(%s)._proc_log_entry(%s)", self.id, msg)

        if not msg:
            # raise ExpiredCallbackError
            return

        if msg.code != "0418" or msg.verb != "RP":
            raise ValueError(f"incorrect message verb/code: {msg.verb}/{msg.code}")

        if not msg.payload:
            # TODO: delete other call backs rather than waiting for them to expire
            self._fault_log_done = True
            return

        log = dict(msg.payload)
        log_idx = int(log.pop("log_idx"), 16)
        self._fault_log[log_idx] = log

        self._req_log_entry(log_idx + 1)


class Schedule:  # 0404
    """The schedule of a zone."""

    def __init__(self, zone, **kwargs) -> None:
        """Initialise the class."""
        _LOGGER.debug("Schedule(%s).__init__()", zone.id)

        self.id = zone.id
        self._zone = zone
        self.idx = zone.idx

        self._ctl = zone._ctl
        self._evo = zone._evo
        self._gwy = zone._gwy

        self._qos = {
            "priority": Priority.HIGH,
            "retries": 3,
            "timeout": timedelta(seconds=0.5),
        }

        self._schedule = None
        self._schedule_done = None

        # initialse the fragment array()
        self.total_frags = None
        self._rx_frags = None
        self._rx_frags = None

    def __repr_(self) -> str:
        return json.dumps(self.schedule) if self._schedule_done else None

    def __str_(self) -> str:
        return f"{self._zone} (schedule)"

    @property
    def schedule(self) -> Optional[dict]:
        """Return the schedule of a zone."""
        if not self._schedule_done:
            return self._schedule  # or None?

        frags = [v for d in self._rx_frags for k, v in d.items() if k == "fragment"]
        # _LOGGER.debug(f"Sched({self.id}).schedule: array is: %s", frags,)

        try:
            self._schedule = self._frags_to_sched(frags)
        except zlib.error:
            self.reset()
            _LOGGER.exception("Invalid schedule fragments: %s", frags)
            return

        # _LOGGER.debug(f"Sched({self.id}).schedule: %s", self._schedule)
        self._schedule_done = True

        return self._schedule["schedule"]

    @staticmethod
    def _frags_to_sched(frags: list) -> dict:
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

    async def get_schedule(self) -> None:
        """Get the schedule of a zone."""
        _LOGGER.debug("Schedule(%s).get_schedule()", self.id)
        if not await self._obtain_lock():
            return  # should raise a TimeOut

        self._schedule = None
        self._schedule_done = None

        self._rx_frags, self.total_frags = [None], 0
        self._rx_fragment(frag_idx=1)

    def _rx_fragment(self, frag_idx=1) -> None:
        """Request the next fragment (index starts at 1, not 0)."""
        _LOGGER.debug(
            "Schedule(%s)._rx_fragment(%s/%s)", self.id, frag_idx, self.total_frags
        )

        def proc_msg(msg) -> None:
            if not msg:  # TODO: needs fleshing out
                _LOGGER.debug("Schedule(%s)._proc_fragment(): no message", self.id)
                return

            _LOGGER.debug(
                "Schedule(%s)._proc_fragment(%s/%s)",
                self.id,
                msg.payload.get("frag_index"),
                msg.payload.get("frag_total"),
            )

            if msg.code != "0404" or msg.verb != "RP":
                raise ValueError(f"incorrect message verb/code: {msg.verb}/{msg.code}")
            if msg.payload["zone_idx"] != self.idx:
                raise ValueError("mismatched zone_idx")
            if self._evo.zone_lock_idx != self.idx:
                raise ValueError("unsolicited packet")

            if self.total_frags == 0:  # this should be the 1st fragment
                self.total_frags = msg.payload["frag_total"]
                self._rx_frags = [None] * msg.payload["frag_total"]

            elif self.total_frags != msg.payload["frag_total"]:
                _LOGGER.warning("total fragments has changed: will re-initialise array")
                self.total_frags = msg.payload["frag_total"]
                self._rx_frags = [None] * msg.payload["frag_total"]
                self._schedule = None

            self._rx_frags[msg.payload["frag_index"] - 1] = {
                "_msg_dtm": msg.dtm,
                "frag_index": msg.payload["frag_index"],
                "fragment": msg.payload["fragment"],
            }

            # discard any fragments significantly older that this most recent fragment
            for frag in [f for f in self._rx_frags if f is not None]:
                frag = None if frag["_msg_dtm"] < msg.dtm - FIVE_MINS else frag

            if msg.payload["frag_index"] < msg.payload["frag_total"]:
                self._rx_fragment(frag_idx=msg.payload["frag_index"] + 1)

            else:
                self._evo.zone_lock.acquire()
                self._evo.zone_lock_idx = None
                self._evo.zone_lock.release()

                self._schedule_done = True

        callback = {"func": proc_msg, "timeout": timedelta(seconds=1)}
        payload = f"{self.idx}20000800{frag_idx:02d}{self.total_frags:02d}"

        cmd = Command(
            "RQ", self._ctl.id, "0404", payload, qos=self._qos, callback=callback
        )
        asyncio.create_task(self._gwy.msg_protocol.send_data(cmd))

    async def set_schedule(self, schedule) -> None:
        """Set the schedule of a zone."""
        _LOGGER.debug("Schedule(%s).set_schedule()", self.id)
        if not await self._obtain_lock():
            return  # should raise a TimeOut

        self._schedule = None
        self._schedule_done = None

        self._tx_frags = self._sched_to_frags(
            {"zone_idx": self.idx, "schedule": schedule}
        )
        self._tx_fragment(frag_idx=0)

    def _tx_fragment(self, frag_idx=0) -> None:
        """Send the next fragment (index starts at 0)."""
        _LOGGER.debug(
            "Schedule(%s)._tx_fragment(%s/%s)", self.id, frag_idx, len(self._tx_frags)
        )

        def proc_msg(msg) -> None:
            pass

        callback = {"func": proc_msg, "timeout": timedelta(seconds=3)}  # 1 sec too low
        payload = "{0}200008{1:02X}{2:02d}{3:02d}{4:s}".format(
            self.idx,
            int(len(self._tx_frags[frag_idx]) / 2),
            frag_idx + 1,
            len(self._tx_frags),
            self._tx_frags[frag_idx],
        )
        cmd = Command(
            " W", self._ctl.id, "0404", payload, qos=self._qos, callback=callback
        )
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
