#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome serial."""

from datetime import timedelta
from functools import total_ordering
import json
import logging
import struct
from types import SimpleNamespace
from typing import Optional
import zlib

from .const import __dev_mode__, CODES_SANS_DOMAIN_ID, COMMAND_FORMAT, HGI_DEVICE
from .logger import dt_now

# SERIAL_PORT = "serial_port"
# CMD_CODE = "cmd_code"
# CMD_VERB = "cmd_verb"
# PAYLOAD = "payload"

# DEVICE_1 = "device_1"
# DEVICE_2 = "device_2"
# DEVICE_3 = "device_3"

RQ_RETRY_LIMIT = 7
RQ_TIMEOUT = 0.03


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

    verb = packet[4:6]
    if response_header:
        verb = "RP" if verb == "RQ" else " I"  # RQ/RP, or W/I
    code = packet[41:45]
    addr = packet[21:30] if packet[11:13] == "18" else packet[11:20]
    payload = packet[50:]

    header = "|".join((verb, addr, code))

    if code in ("0005", "000C"):  # zone_idx, type
        return "|".join((header, payload[:4]))

    if code == "0404":  # zone_idx, frag_idx
        return "|".join((header, payload[:2] + payload[10:12]))

    if code == "0418":  # log_idx
        return "|".join((header, payload[4:6]))

    if code in CODES_SANS_DOMAIN_ID:  # have no domain_id
        return header

    return "|".join((header, payload[:2]))  # has a domain_id


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

        self.qos = kwargs

        priority = Priority.HIGH if verb in ("0016", "1FC9") else Priority.DEFAULT
        self._priority = kwargs.get("priority", priority)
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


class FaultLog:
    """The fault log (of a system) class."""

    def __init__(self, controller, msg=None, **kwargs) -> None:
        """Initialise the class."""
        self._ctl = controller

        self._gwy = controller._gwy
        self._que = controller._que

        self.id = controller.id

        self._fault_log = []

    def add_fault(self, msg) -> None:
        _LOGGER.error("Sched(%s).add_fragment: xxx", self.id)

    def req_schedule(self) -> int:
        _LOGGER.error("Sched(%s).req_schedule: xxx", self.id)

    def req_fragment(self, restart=False) -> int:
        _LOGGER.error("Sched(%s).req_fragment: xxx", self.id)

        if self._gwy.self.config["disable_sending"]:
            return

    def __repr_(self) -> str:
        return json.dumps(self._fault_log)

    def __str_(self) -> str:
        return json.dumps(self._fault_log, indent=2)

    @property
    def fault_log(self) -> list:
        if self._fault_log is not None:
            return self._fault_log

        return self._fault_log


class Schedule:
    """The schedule (of a zone) class."""

    # TODO: stop responding to fragments sent by others
    # TODO: use a lock to only request one schedule at a time

    def __init__(self, zone, msg=None, **kwargs) -> None:
        """Initialise the class."""
        self._zone = zone

        self._ctl = zone._ctl
        self._gwy = zone._gwy
        self._que = zone._que

        self.idx = zone.idx

        # initialse the fragment array: DRY
        self._init_frag_array(total_frags=0)  # could use msg.payload["frag_total"]

        if msg is not None:
            if msg.payload["frag_index"] != 1:
                raise ValueError("not the first fragment of the message")
            self.add_fragment(msg)

    def _init_frag_array(self, total_frags=0) -> None:
        """Reset the fragment array."""
        self.total_frags = total_frags
        self._frag_array = [None] * total_frags
        self._schedule = None

    def add_fragment(self, msg) -> None:
        _LOGGER.error("Sched(%s).add_fragment: xxx", self.idx)

        if msg.code != "0404" or msg.verb != "RP":
            raise ValueError("incorrect message verb/code")
        if msg.payload["zone_idx"] != self.idx:
            raise ValueError("mismatched zone_idx")

        if self.total_frags == 0:
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

        # if not [x for x in self._frag_array if x is None]:  # TODO: can leave out?
        #     _ = self.schedule if self._gwy.self.config["disable_sending"] else None

    def req_schedule(self) -> int:
        _LOGGER.error("Sched(%s).req_schedule: xxx", self.idx)

        # TODO: use a lock to ensure only 1 schedule being requested at a time
        # self.req_fragment(restart=True)

    def req_fragment(self, restart=False) -> int:
        """Request the next fragment, and return that fragment's index number.

        Return 0 when there are no more fragments to get.
        """
        _LOGGER.error("Sched(%s).req_fragment: xxx", self.idx)

        if self._gwy.self.config["disable_sending"]:
            return

        if restart is True:  # or self.total_frags == 0
            self._init_frag_array(0)

        if self._frag_array == []:  # aka self.total_frags == 0:
            missing_frags = [0]  # all(frags missing), but how many is unknown
            # kwargs = {"pause": Pause.LONG}  # , "priority": Priority.DEFAULT}

        else:  # aka not all(self._frag_array)
            missing_frags = [i for i, val in enumerate(self._frag_array) if val is None]
            if missing_frags == []:
                print(self.schedule)
                return 0  # not any(frags missing), nothing to add

        header = f"{self.idx}20000800{missing_frags[0] + 1:02d}{self.total_frags:02d}"
        self._que.put_nowait(
            Command("RQ", self._ctl.id, "0404", header, priority=Priority.HIGH)
        )

        return missing_frags[0] + 1

    def __repr_(self) -> str:
        return json.dumps(self._schedule)

    def __str_(self) -> str:
        return json.dumps(self._schedule, indent=2)

    @property
    def schedule(self) -> list:
        if self._schedule is not None:
            return self._schedule

        _LOGGER.warning(
            "Sched(%s).schedule: array is: %s",
            self.idx,
            [{d["frag_index"]: d["fragment"]} for d in self._frag_array],
        )

        if self._frag_array == [] or not all(self._frag_array):
            return

        frags = [v for d in self._frag_array for k, v in d.items() if k == "fragment"]
        try:
            raw_schedule = zlib.decompress(bytearray.fromhex("".join(frags)))
        except zlib.error:
            _LOGGER.exception("Invalid schedule fragments: %s", self._frag_array)
            self._init_frag_array(total_frags=0)
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

        _LOGGER.debug("Sched(%s): len(schedule): %s", self.idx, len(self._schedule))
        # _LOGGER.debug("Sched(%s).schedule: %s", self.idx, self._schedule)
        return self._schedule
