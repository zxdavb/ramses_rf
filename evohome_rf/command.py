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


Priority = SimpleNamespace(LOW=6, DEFAULT=4, HIGH=2, ASAP=0)
Qos = SimpleNamespace(
    AT_MOST_ONCE=0,  # PUB (no handshake)
    AT_LEAST_ONCE=1,  # PUB, ACK (2-way handshake)
    EXACTLY_ONCE=2,  # PUB, REC, REL (FIN) (3/4-way handshake)
)

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


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
            return self._fault_log

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
            callback = {
                "func": self._proc_log_entry,
                "timeout": timedelta(seconds=1),
            }

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
        log_idx = int(log.pop("log_idx"))
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

        self._schedule = None
        self._schedule_done = None

        # initialse the fragment array
        self.total_frags = None
        self._frag_array = None

        # self._init_frag_array(total_frags=0)  # could use msg.payload["frag_total"]

    def __repr_(self) -> str:
        return json.dumps(self.schedule) if self._schedule_done else None

    def __str_(self) -> str:
        return f"{self._zone} (schedule)"

    @property
    def schedule(self) -> Optional[dict]:
        """Return the schedule of a zone."""
        if not self._schedule_done:
            return self._schedule

        _LOGGER.debug(
            "Sched(%s).schedule: array is: %s",
            self.id,
            [{d["frag_index"]: d["fragment"]} for d in self._frag_array],
        )

        if self._frag_array == [] or not all(self._frag_array):
            return

        frags = [v for d in self._frag_array for k, v in d.items() if k == "fragment"]
        try:
            raw_schedule = zlib.decompress(bytearray.fromhex("".join(frags)))
        except zlib.error:
            _LOGGER.exception("Invalid schedule fragments: %s", self._frag_array)
            self.reset()
            return

        self._schedule = []
        old_day, switchpoints = 0, []

        for i in range(0, len(raw_schedule), 20):
            zone, day, time, temp, _ = struct.unpack(
                "<xxxxBxxxBxxxHxxHH", raw_schedule[i : i + 20]
            )
            if day > old_day:
                self._schedule.append(
                    {"day_of_week": old_day, "switchpoints": switchpoints}
                )
                old_day, switchpoints = day, []
            switchpoints.append(
                {
                    "time_of_day": "{0:02d}:{1:02d}".format(*divmod(time, 60)),
                    "heat_setpoint": temp / 100,
                }
            )

        self._schedule.append({"day_of_week": old_day, "switchpoints": switchpoints})
        self._schedule_done = True

        _LOGGER.debug("Schedule(%s): len(schedule): %s", self.id, len(self._schedule))
        # _LOGGER.debug("Sched(%s).schedule: %s", self.id, self._schedule)
        return self._schedule

    async def start(self) -> None:
        _LOGGER.debug("Schedule(%s).start()", self.id)

        while True:

            self._evo.zone_lock.acquire()
            if self._evo.zone_lock_idx is None:
                self._evo.zone_lock_idx = self.idx
            self._evo.zone_lock.release()

            if self._evo.zone_lock_idx == self.idx:
                break

            await asyncio.sleep(0.1)  # gives the other zone enough time

        # TODO: use a lock to ensure only 1 schedule being requested at a time
        self.reset()
        if self._evo.zone_lock_idx == self.idx:
            self._req_fragment(frag_idx=1)  # start at 1, not 0

    def reset(self) -> None:
        _LOGGER.debug("Schedule(%s).reset()", self.id)

        self._schedule = None
        self._schedule_done = None

        self._init_frag_array(total_frags=0)

    def _init_frag_array(self, total_frags=0) -> None:
        """Reset the fragment array."""
        self.total_frags = total_frags
        self._frag_array = [None] * total_frags
        self._schedule = None

    def _req_fragment(self, frag_idx=1) -> None:
        """Request the next fragment (starting a 1, not 0)."""
        _LOGGER.debug(
            "Schedule(%s)._req_fragment(%s/%s)", self.id, frag_idx, self.total_frags
        )

        def send_cmd(payload) -> None:
            qos = {
                "priority": Priority.HIGH,
                "retries": 3,
                "timeout": timedelta(seconds=0.5),
            }
            callback = {
                "func": self._proc_fragment,
                "timeout": timedelta(seconds=1),
            }

            cmd = Command(
                "RQ", self._ctl.id, "0404", payload, qos=qos, callback=callback
            )
            asyncio.create_task(self._gwy.msg_protocol.send_data(cmd))

        send_cmd(f"{self.idx}20000800{frag_idx:02d}{self.total_frags:02d}")

    def _proc_fragment(self, msg) -> None:
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
            self._init_frag_array(msg.payload["frag_total"])

        elif self.total_frags != msg.payload["frag_total"]:
            _LOGGER.warning("total fragments has changed: will re-initialise array")
            self._init_frag_array(msg.payload["frag_total"])

        self._frag_array[msg.payload["frag_index"] - 1] = {
            "_msg_dtm": msg.dtm,
            "frag_index": msg.payload["frag_index"],
            "fragment": msg.payload["fragment"],
        }

        # discard any fragments significantly older that this most recent fragment
        for frag in [f for f in self._frag_array if f is not None]:
            # TODO: use a CONST for 5 minutes
            frag = None if frag["_msg_dtm"] < msg.dtm - timedelta(minutes=5) else frag

        if msg.payload["frag_index"] < msg.payload["frag_total"]:
            self._req_fragment(frag_idx=msg.payload["frag_index"] + 1)

        else:
            self._evo.zone_lock.acquire()
            self._evo.zone_lock_idx = None
            self._evo.zone_lock.release()

            self._schedule_done = True
