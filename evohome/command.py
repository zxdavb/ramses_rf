"""Evohome serial."""

from .const import COMMAND_FORMAT, CTL_DEV_ID, HGI_DEV_ID

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
    def __init__(
        self, gateway, code, verb="RQ", dest_id=CTL_DEV_ID, payload="00"
    ) -> None:
        self._gateway = gateway
        self.code = code
        self.verb = verb
        self.device_id = (
            dest_id if dest_id else CTL_DEV_ID
        )  # TODO: self._gateway.controller_id
        self.payload = payload

    def __str__(self) -> str:
        _cmd = COMMAND_FORMAT.format(
            self.verb,
            HGI_DEV_ID,
            self.device_id,
            self.code,
            len(self.payload) / 2,
            self.payload,
        )

        # if not COMMAND_REGEX.match(_cmd):
        #     raise ValueError(f"Message is not valid, >>{_cmd}<<")

        return _cmd
