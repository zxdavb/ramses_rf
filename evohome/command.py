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


# cmd = Command(self, "2349", verb="RQ", dest_id="04:056059", payload="0100")
# self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
# await asyncio.sleep(0.05)  # 0.8, 1.0 OK, 0.5 too short

# cmd = Command(self, "2309", verb="RQ", dest_id="04:056059", payload="00")
# self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
# await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short

# cmd = Command(self, "3150", verb="RQ", dest_id="04:056059", payload="0100")
# self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
# await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short


# def get_schedule(zone_idx, controller, gateway):

#     packet_total = 0
#     packet_num = 0

#     # packet_list = []

#     payload = f"{zone_idx:02X}20000800{packet_num:02d}{packet_total:02d}"

#     gateway.command_queue.put_nowait(
#         Command(gateway, "0404", "RQ", controller, payload)
#     )

#     packet_total = 5  # TBA
#     for i in range(2, packet_total + 1):
#         gateway.command_queue.put_nowait(
#             Command(gateway, "0404", "RQ", controller, payload)
#         )


class Command:
    """The command class."""

    def __init__(self, gateway, verb="RQ", from_addr=HGI_DEV_ID, **kwargs) -> None:
        """Initialise the  class."""
        self._gwy = gateway
        self._evo = gateway.evo

        self.verb = verb
        self.from_addr = from_addr
        self.dest_addr = kwargs.get("dest_addr", gateway.evo.ctl_id)
        self.code = kwargs.get("code", "1F09")
        self.payload = kwargs.get("payload", "FF")
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


# 0100, payload = "00"
# 1F09, payload = "FF"
# 000A, payload = zz00
# 000C, payload = zz00


# def scan_tight(dest_id):
#     for code in COMMAND_SCHEMA:
#         cmd = Command(self, code, verb="RQ", dest_id=dest_id, payload="0100")
#         yield cmd

#     # for code in COMMAND_SCHEMA:
#     #     while self.reader._transport.serial.in_waiting > 0:
#     #         await self._recv_message(source=self.reader)

#     #     cmd = Command(self, code, verb="RQ", dest_id=CTL_DEV_ID, payload="FF")
#     #     self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
#     #     await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short

#     #     while not self.command_queue.empty():
#     #         self.command_queue.get()
#     #         self.command_queue.task_done()

# async def scan_loose():
#     # # BEGIN crazy test block
#     dest_id = "01:145038"  # "07:045960"  # "13:106039"  # "13:237335"  #

#     i = 0x0
#     while i < 0x4010:
#         await self._recv_message(source=self.reader)
#         if self.reader._transport.serial.in_waiting != 0:
#             continue

#         code = f"{i:04X}"

#         cmd = Command(self, code, verb="RQ", dest_id=dest_id, payload="F9")
#         self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
#         await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short

#         cmd = Command(self, code, verb="RQ", dest_id=dest_id, payload="FA")
#         self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
#         await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short

#         cmd = Command(self, code, verb="RQ", dest_id=dest_id, payload="FC")
#         self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
#         await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short

#         if i % 20 == 19:
#             await asyncio.sleep(20)  # 20 OK with 0.8, 30 OK with 1.0

#         if not self.command_queue.empty():
#             self.command_queue.get()
#             self.command_queue.task_done()

#         i += 1
#     # # ENDS crazy test block
