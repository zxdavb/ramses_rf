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
    def __init__(self, command_code, gateway, destination, payload) -> None:
        self._gateway = gateway

        self._command_code = command_code
        self._payload = payload
        self._destination = destination

    def __str__(self) -> str:
        _cmd = COMMAND_FORMAT.format(
            HGI_DEV_ID,
            self._destination,
            self._command_code,
            len(self._payload) / 2,
            self._payload,
        )

        # if not COMMAND_REGEX.match(_cmd):
        #     raise ValueError(f"Message is not valid, >>{_cmd}<<")

        return _cmd

    def execute(self) -> int:
        """Send a command to the RF bus."""
        self._gateway.command_queue.put(str(self), timeout=5)
