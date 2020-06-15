"""Evohome serial."""

from datetime import datetime as dt, timedelta
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
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


class Schedule:
    """The schedule (of a zone) class."""

    def __init__(self, gwy, zone_idx, msg=None, **kwargs) -> None:
        """Initialise the class."""
        self._evo = gwy.evo
        self._gwy = gwy
        self._que = gwy.cmd_que

        self.zone_idx = zone_idx  # msg.payload["zone_idx"]
        self._msg = msg

        self.total_frags = self._fragments = self._schedule = None

        if msg is not None:
            if msg.payload["frag_index"] != 1:
                raise ValueError("not the first fragment of the message")

            # self.add_fragment(msg)

    def add_fragment(self, msg) -> None:
        if msg.code != "0404" or msg.verb != "RP":
            raise ValueError("incorrect message verb/code")

        if msg.payload["zone_idx"] != self.zone_idx:
            raise ValueError("mismatched zone_idx")

        if self.total_frags is None:
            self.total_frags = msg.payload["frag_total"]
            self._fragments = [None] * self.total_frags

        elif self.total_frags != msg.payload["frag_total"]:
            raise ValueError("mismatched number of fragment")

        self._fragments[msg.payload["frag_index"] - 1] = {
            "fragment": msg.payload["fragment"],
            "dtm": msg.dtm,
        }

        for frag in self._fragments:
            if frag is not None and frag["dtm"] > dt.now() + timedelta(minutes=5):
                frag = None

        if not [x for x in self._fragments if x is None]:  # TODO: can leave out
            _ = self.schedule

    def request_fragment(self, restart=False) -> None:
        # TODO: if required, queue requests for remaining fragments (needs improving)
        if self._gwy.config["listen_only"]:
            return

        if self.total_frags is None or restart is True:
            self._fragments = None
            self.total_frags = frag_idx = 0

        else:
            frag_idx = [idx for idx, val in enumerate(self._fragments) if val is None][
                0
            ]

        header = f"{self.zone_idx}20000800{frag_idx + 1:02d}{self.total_frags:02d}"
        self._que.put_nowait(
            Command("RQ", self._evo.ctl_id, "0404", header, priority=HIGH_PRIORITY)
        )

    def __repr_(self) -> str:
        return self._schedule

    def __str_(self) -> str:
        return str(self._schedule)

    @property
    def schedule(self) -> list:
        _LOGGER.debug("schedule array is: %s", self._fragments)

        if self._schedule is not None:
            return self._schedule

        if not all(self._fragments):
            return

        raw_fragments = [
            v for d in self._fragments for k, v in d.items() if k == "fragment"
        ]
        try:
            raw_schedule = zlib.decompress(bytearray.fromhex("".join(raw_fragments)))
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

        _LOGGER.debug("schedule is: %s", self._schedule)
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
