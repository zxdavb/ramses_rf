"""Evohome serial."""

from datetime import datetime as dt
from functools import total_ordering
import logging

from .const import COMMAND_FORMAT, DEFAULT_PRIORITY, HGI_DEV_ID, __dev_mode__

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


@total_ordering
class Command:
    """The command class."""

    def __init__(self, verb, dest_addr, code, payload, **kwargs) -> None:
        """Initialise the  class."""
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
