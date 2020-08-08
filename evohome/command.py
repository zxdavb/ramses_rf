"""Evohome serial."""

from datetime import timedelta
from functools import total_ordering
import json
import logging
import struct
from types import SimpleNamespace
from typing import Optional
import zlib

from .const import __dev_mode__, COMMAND_FORMAT, HGI_DEVICE
from .logger import dt_now

SERIAL_PORT = "serial_port"
CMD_CODE = "cmd_code"
CMD_TYPE = "cmd_type"
PAYLOAD = "payload"

DEVICE_1 = "device_1"
DEVICE_2 = "device_2"
DEVICE_3 = "device_3"

RQ_RETRY_LIMIT = 7
RQ_TIMEOUT = 0.03


# PAUSE: Default of 0.03 too short, but 0.05 OK; Long pause required after 1st RQ/0404
Pause = SimpleNamespace(NONE=0, MINIMUM=0.01, SHORT=0.01, DEFAULT=0.05, LONG=0.15)
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

        self.id = zone.id

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
        _LOGGER.error("Sched(%s).add_fragment: xxx", self.id)

        if msg.code != "0404" or msg.verb != "RP":
            raise ValueError("incorrect message verb/code")
        if msg.payload["zone_idx"] != self.id:
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

        if not [x for x in self._frag_array if x is None]:  # TODO: can leave out?
            _ = self.schedule if self._gwy.config["listen_only"] else None

    def req_schedule(self) -> int:
        _LOGGER.error("Sched(%s).req_schedule: xxx", self.id)

        self.req_fragment(restart=True)

    def req_fragment(self, restart=False) -> int:
        """Request the next fragment, and return the fragment number.

        Return 0 if there ar eno more fragments to get.
        """
        _LOGGER.error("Sched(%s).req_fragment: xxx", self.id)

        if self._gwy.config["listen_only"]:
            return

        if restart is True:  # or self.total_frags == 0
            self._init_frag_array(0)

        if self._frag_array == []:  # aka self.total_frags == 0:
            missing_frags = [0]  # all(frags missing), but how many is unknown
            kwargs = {"pause": Pause.LONG}  # , "priority": Priority.DEFAULT}

        else:  # aka not all(self._frag_array)
            missing_frags = [i for i, val in enumerate(self._frag_array) if val is None]
            if missing_frags == []:
                print(self.schedule)
                return 0  # not any(frags missing), nothing to add
            kwargs = {"pause": Pause.DEFAULT, "priority": Priority.HIGH}

        header = f"{self.id}20000800{missing_frags[0] + 1:02d}{self.total_frags:02d}"
        self._que.put_nowait(Command("RQ", self._ctl.id, "0404", header, **kwargs))

        return missing_frags[0] + 1

    def __repr_(self) -> str:
        return json.dumps(self._schedule)

    def __str_(self) -> str:
        return json.dumps(self._schedule, indent=2)

    @property
    def schedule(self) -> list:
        _LOGGER.warning("Sched(%s).schedule: array is: %s", self.id, self._frag_array)

        # enumerate()

        if self._schedule is not None:
            return self._schedule

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

        _LOGGER.debug("zone(%s): len(schedule): %s", self.id, len(self._schedule))
        # _LOGGER.debug("zone(%s) schedule is: %s", self.id, self._schedule)
        return self._schedule


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

        self.pause = kwargs.get("pause", Pause.DEFAULT)

        priority = Priority.HIGH if verb in ("0016", "1FC9") else Priority.DEFAULT
        self._priority = kwargs.get("priority", priority)
        self._priority_dtm = dt_now()  # used for __lt__, etc.

        qos = Qos.AT_LEAST_ONCE if self.verb in ("RQ", " W") else Qos.AT_MOST_ONCE
        self.qos = kwargs.get("qos", qos)

        self.dtm_expires = None  # TODO: these 3 shouldn't be instance attributes?
        self.dtm_timeout = None
        self.transmit_count = 0

    def __repr__(self) -> str:
        result = {"packet": str(self)}
        result.update(
            {
                k: v
                for k, v in self.__dict__.items()
                if k not in ("verb", "from_addr", "dest_addr", "code", "payload")
            }
        )
        return json.dumps(result)

    def __str__(self) -> str:
        return COMMAND_FORMAT.format(
            self.verb,
            self.from_addr,
            self.dest_addr,
            self.code,
            int(len(self.payload) / 2),
            self.payload,
        )

    @property
    def _header(self) -> Optional[str]:
        """Return the QoS header of a response packet, if one is expected."""

        if self.verb in ("RQ", " W"):
            return "|".join(
                ("RP" if self.verb == "RQ" else " I", self.dest_addr, self.code)
            )

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
