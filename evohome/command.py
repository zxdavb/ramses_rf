"""Evohome serial."""

import time

from .const import COMMAND_FORMAT, COMMAND_REGEX, CTL_DEV_ID, HGI_DEV_ID

# from .logger import _LOGGER

SERIAL_PORT = "serial_port"
CMD_CODE = "cmd_code"
CMD_TYPE = "cmd_type"
PAYLOAD = "payload"

DEVICE_1 = "device_1"
DEVICE_2 = "device_2"
DEVICE_3 = "device_3"


class Command:
    """The command class."""

    #
    def __init__(self, entity, command_code, destination, payload="00") -> None:
        self.entity = entity
        self.command_code = command_code
        self.destination = destination
        self.payload = payload

    def __str__(self) -> str:
        _cmd = COMMAND_FORMAT.format(
            HGI_DEV_ID,
            self.destination,
            self.command_code,
            len(self.payload) / 2,
            self.payload,
        )

        # if not COMMAND_REGEX.match(_cmd):
        #     raise ValueError(f"Message is not valid, >>{_cmd}<<")

        return _cmd

    def execute(self) -> int:
        """Send a command to the RF bus."""
        self.entity._gateway.command_queue.put(self)
