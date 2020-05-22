"""Evohome serial."""

from .const import COMMAND_FORMAT, HGI_DEV_ID

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


# def get_schedule(zone_idx, controller, gateway):
#     packet_total = 0
#     packet_num = 0
#     # packet_list = []
#     payload = f"{zone_idx:02X}20000800{packet_num:02d}{packet_total:02d}"
#     gwy.command_queue.put_nowait(Command("RQ", controller, "0404", payload))
#     packet_total = 5  # TBA
#     for i in range(2, packet_total + 1):
#         gwy.command_queue.put_nowait(Command("RQ", controller, "0404", payload))


class Command:
    """The command class."""

    def __init__(self, verb, dest_addr, code, payload, **kwargs) -> None:
        """Initialise the  class."""
        self.verb = verb
        self.from_addr = kwargs.get("from_addr", HGI_DEV_ID)
        self.dest_addr = dest_addr
        self.code = code
        self.payload = payload

        self.priority = kwargs.get("priority", 1)

    def __str__(self) -> str:
        """Represent as a string."""
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

    def __lt__(self, other) -> bool:
        """Represent as a string."""
        return self.priority < other.priority
