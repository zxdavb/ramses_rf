"""Evohome serial."""

from datetime import datetime as dt, timedelta
from functools import total_ordering
import logging
import struct
import zlib

from .const import COMMAND_FORMAT, HGI_DEV_ID, __dev_mode__

SERIAL_PORT = "serial_port"
CMD_CODE = "cmd_code"
CMD_TYPE = "cmd_type"
PAYLOAD = "payload"

DEVICE_1 = "device_1"
DEVICE_2 = "device_2"
DEVICE_3 = "device_3"

# MIN_GAP_BETWEEN_CMDS = 0.7
# MAX_CMDS_PER_MINUTE = 30

PRIORITY_LOW = 6
PRIORITY_DEFAULT = 4
PRIORITY_HIGH = 2

PAUSE_LONG = 0.15  # seconds
PAUSE_DEFAULT = 0.05
PAUSE_SHORT = 0.01

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


class Schedule:
    """The schedule (of a zone) class."""

    def __init__(self, gwy, zone_idx, msg=None, **kwargs) -> None:
        """Initialise the class."""
        self._evo = gwy.evo
        self._gwy = gwy
        self._que = gwy.cmd_que

        self.zone_idx = zone_idx  # aka msg.payload["zone_idx"]

        # initialse the fragment array: DRY
        self._init_frag_array(total_frags=0)  # could use msg.payload["frag_total"]

        if msg is not None:
            if msg.payload["frag_index"] != 1:
                raise ValueError("not the first fragment of the message")
            # self.add_fragment(msg)

    def _init_frag_array(self, total_frags=0) -> None:
        """Reset the fragment array."""
        self.total_frags = total_frags
        self._frag_array = [None] * total_frags
        self._schedule = None

    def add_fragment(self, msg) -> None:
        if msg.code != "0404" or msg.verb != "RP":
            raise ValueError("incorrect message verb/code")
        if msg.payload["zone_idx"] != self.zone_idx:
            raise ValueError("mismatched zone_idx")

        if self.total_frags == 0:
            self._init_frag_array(msg.payload["frag_total"])

        elif self.total_frags != msg.payload["frag_total"]:
            _LOGGER.warning("total fragments has changed: will re-initialise array")
            self._init_frag_array(msg.payload["frag_total"])

        self._frag_array[msg.payload["frag_index"] - 1] = {
            "fragment": msg.payload["fragment"],
            "dtm": msg.dtm,
        }

        # discard any fragments significantly older that this most recent fragment
        for frag in [f for f in self._frag_array if f is not None]:
            frag = None if frag["dtm"] < msg.dtm - timedelta(minutes=5) else frag

        if not [x for x in self._frag_array if x is None]:  # TODO: can leave out?
            _ = self.schedule if self._gwy.config["listen_only"] else None

    def req_fragment(self, restart=False) -> None:
        """Request a remaining fragment, if any."""
        # first pkt: PRIORITY_LOW, PAUSE_LONG
        # otherwise: PRIORITY_HIGH, PAUSE_DEFAULT

        if self._gwy.config["listen_only"]:
            return

        if self.total_frags == 0 or restart is True:
            self._init_frag_array(0)

        missing_frags = [i for i, val in enumerate(self._frag_array) if val is None]
        frag_idx = 1 if len(missing_frags) == 0 else missing_frags[0] + 1

        header = f"{self.zone_idx}20000800{frag_idx:02d}{self.total_frags:02d}"
        self._que.put_nowait(
            Command("RQ", self._evo.ctl_id, "0404", header, priority=PRIORITY_HIGH)
        )  # pkts (other than 1st pkt) should be high priority

    def __repr_(self) -> str:
        return self._schedule

    def __str_(self) -> str:
        return str(self._schedule)

    @property
    def schedule(self) -> list:
        # _LOGGER.debug("schedule array is: %s", self._frag_array)

        if self._schedule is not None:
            return self._schedule

        if self._frag_array == [] or not all(self._frag_array):
            return

        raw_frags = [
            v for d in self._frag_array for k, v in d.items() if k == "fragment"
        ]
        try:
            raw_schedule = zlib.decompress(bytearray.fromhex("".join(raw_frags)))
        except zlib.error:
            _LOGGER.exception("Failed to decompress (resetting): %s", self._frag_array)
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

        _LOGGER.debug("zone %s len(schedule): %s", self.zone_idx, len(self._schedule))
        # _LOGGER.debug("zone %s schedule is: %s", self.zone_idx, self._schedule)
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

        pause = kwargs.get("pause", PAUSE_DEFAULT)
        self.pause = PAUSE_DEFAULT if pause is None else pause

        priority = kwargs.get("priority", PRIORITY_DEFAULT)
        self.priority = PRIORITY_DEFAULT if priority is None else priority

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
