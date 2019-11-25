"""Honeywell RAMSES II / Residential Network Protocol entities."""
import time
from datetime import datetime as dt
from datetime import timedelta

from .const import COMMAND_LOOKUP, DEVICE_LOOKUP, DEVICE_MAP
from .logger import _LOGGER

SYNC_CYCLE_DURATION = timedelta(seconds=185.5)


class Controller:
    """The Controller class."""

    def __init__(self, entity_id, gateway) -> None:
        self._id = entity_id
        self._command_queue = gateway.command_queue

        self._data = {}
        self._sync_cycle_timeout = None

    def initialise(self):
        """Create the main loop."""
        # cat pkts.log | grep 'I ... CTL' | grep -E '1F09|2309|30C9' -C2
        # 2019-11-12T17:54:21.821896 073  I --- CTL:145038  --:------ CTL:145038 1F09 003 FF073F
        # 2019-11-12T17:54:21.834551 073  I --- CTL:145038  --:------ CTL:145038 2309 021 0007D00107D002079E03073A04073A05073A06073A
        # 2019-11-12T17:54:21.854341 072  I --- CTL:145038  --:------ CTL:145038 30C9 021 0008270107E50207EE0307BB040732057FFF060792
        # these three packets are sent every cycle

        while True:
            cmd = (COMMAND_LOOKUP["sync_cycle"], SYNC_CYCLE_TIMER)
            self._command_queue.put(cmd)

            self._sync_cycle_timeout = dt.utcnow() + SYNC_CYCLE_DURATION
            time.sleep(SYNC_CYCLE_DURATION)

    def sync_cycle(self, device_id):
        """Respond to a sync_cycle request (RQ) from a bound device."""

        # if not bound_device(device_id):
        #     return  # ignore devices not bound to us

        remaining_seconds = (self._sync_cycle_timeout - dt.utcnow()).total_seconds()
        if remaining_seconds < 0:
            remaining_seconds = 0

        cmd = (COMMAND_LOOKUP["sync_cycle"], device_id, remaining_seconds)
        self._command_queue.put(cmd)

        while True:
            self._command_queue.put((COMMAND_LOOKUP["sync_cycle"], SYNC_CYCLE_TIMER))
            time.sleep(SYNC_CYCLE_TIMER)
