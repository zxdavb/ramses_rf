"""Evohome serial."""

from datetime import datetime as dt
from functools import total_ordering
import logging
import struct
import zlib

from .const import (
    COMMAND_FORMAT,
    DEFAULT_PRIORITY,
    HIGH_PRIORITY,
    HGI_DEV_ID,
    __dev_mode__,
)

# from .logger import _LOGGER

SERIAL_PORT = "serial_port"
CMD_CODE = "cmd_code"
CMD_TYPE = "cmd_type"
PAYLOAD = "payload"

DEVICE_1 = "device_1"
DEVICE_2 = "device_2"
DEVICE_3 = "device_3"

MIN_GAP_BETWEEN_CMDS = 0.7
MAX_CMDS_PER_MINUTE = 30

_LOGGER = logging.getLogger(__name__)
if True or __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


class Schedule:
    """The schedule (of a zone) class."""

    def __init__(self, gwy, msg, **kwargs) -> None:
        """Initialise the class."""
        self._msg = msg
        self._evo = gwy.evo
        self._gwy = gwy
        self._que = gwy.cmd_que

        if msg.payload["frag_index"] != 1:
            raise ValueError("not the first fragment of the message")
        self.frag_total = msg.payload["frag_total"]

        self.zone_idx = msg.payload["zone_idx"]
        self._schedule = None
        self._fragments = [None] * self.frag_total

        # self.update(msg)

    def update(self, msg) -> str:
        if msg.payload["frag_total"] != self.frag_total:
            raise ValueError("mismatched number of fragment")
        frag_index = msg.payload["frag_index"]

        self._fragments[frag_index - 1] = msg.payload["fragment"]

        # TODO: if required, queue requests for remaining fragments (needs improving)
        if self._gwy.config["listen_only"]:
            return

        if len([x for x in self._fragments if x is not None]) == 1:
            for idx in range(frag_index + 1, self.frag_total + 1):
                header = f"{self.zone_idx}20000800{idx:02d}{self.frag_total:02d}"
                self._que.put_nowait(
                    Command(
                        "RQ", self._evo.ctl_id, "0404", header, priority=HIGH_PRIORITY
                    )
                )

    def __repr_(self) -> str:
        return self._schedule

    def __str_(self) -> str:
        return self._schedule

    @property
    def schedule(self, msg) -> list:
        _LOGGER.debug("schedule array is: %s", self._fragments)

        if self._schedule is None or not all(self._fragments):
            return []

        try:
            raw_schedule = zlib.decompress(bytearray.fromhex("".join(self._fragments)))
        except zlib.error:
            _LOGGER.exception("*** FAILED to ZLIB ***, %s", self._fragments)
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

        return self._schedule


@total_ordering
class Command:
    """The command class."""

    def __init__(self, verb, dest_addr, code, payload, **kwargs) -> None:
        """Initialise the class."""
        self.verb = verb
        self.from_addr = kwargs.get("from_addr", HGI_DEV_ID)
        self.dest_addr = dest_addr
        self.code = code
        self.payload = payload

        priority = kwargs.get("priority", DEFAULT_PRIORITY)
        self.priority = DEFAULT_PRIORITY if priority is None else priority
        self._dtm = dt.now()

    def __str__(self) -> str:
        _cmd = COMMAND_FORMAT.format(
            self.verb,
            self.from_addr,
            self.dest_addr,
            self.code,
            int(len(self.payload) / 2),
            self.payload,
        )

        # if not COMMAND_REGEX.match(_cmd):
        #     raise ValueError(f"Message is not valid, >>{_cmd}<<")

        return _cmd

    def _is_valid_operand(self, other) -> bool:
        return hasattr(other, "priority") and hasattr(other, "_dtm")

    def __eq__(self, other) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self.priority, self._dtm) == (other.priority, other._dtm)

    def __lt__(self, other) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self.priority, self._dtm) < (other.priority, other._dtm)
