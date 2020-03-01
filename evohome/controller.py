"""Honeywell RAMSES II / Residential Network Protocol entities."""
import time
from datetime import datetime as dt
from datetime import timedelta

from .const import COMMAND_LOOKUP

SYNC_CYCLE_TIMER = 185.5
SYNC_CYCLE_DURATION = timedelta(seconds=SYNC_CYCLE_TIMER)


class Controller:
    """The Controller class."""

    def __init__(self, entity_id, gateway) -> None:
        """Initialse the class."""
        self._id = entity_id
        self._command_queue = gateway.command_queue

        self._data = {}
        self._sync_cycle_timeout = None

    def initialise(self):
        """Create the main loop."""
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
