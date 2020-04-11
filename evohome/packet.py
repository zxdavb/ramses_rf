"""Packet processor."""

import logging

import serial  # TODO: dont import unless required
import serial_asyncio  # TODO: dont import unless required
from string import printable

from .const import MESSAGE_REGEX
from .logger import time_stamp

_LOGGER = logging.getLogger(__name__)  # evohome.packet
_LOGGER.setLevel(logging.INFO)  # INFO or DEBUG

BAUDRATE = 115200  # 38400  #  57600  # 76800  # 38400  # 115200
READ_TIMEOUT = 0.5


def split_pkt_line(packet_line: str) -> (str, str, str):
    def _split(text: str, char: str) -> (str, str):
        _list = text.split(char, maxsplit=1)
        return _list[0].strip(), _list[1].strip() if len(_list) == 2 else ""

    packet_tmp, comment = _split(packet_line, "#")
    packet, error = _split(packet_tmp, "*")
    return packet, f"* {error} " if error else "", f"# {comment} " if comment else ""


class Packet:
    """The packet class."""

    def __init__(self, timestamp_packet) -> None:
        """Initialse the class."""
        packet_line = self._packet_line = timestamp_packet[27:]  # .strip()
        self.timestamp = timestamp_packet[:26]

        if not packet_line:  # TODO: validate timestamp
            raise ValueError(f"there is no packet, nor packet metadata: {packet_line}")

        self.date, self.time = self.timestamp[:10], self.timestamp[11:26]
        self.packet, self.error_text, self.comment = split_pkt_line(packet_line)

    def __str__(self) -> str:
        """Represent the entity as a string."""
        return f"{self.timestamp} {self.packet}{self.error_text}{self.comment}"

    @property
    def is_valid(self) -> bool:
        """Return True if a packet is valid in structure, log any baddies."""
        if not self.packet:
            _LOGGER.warning("B< Invalid packet: null packet", extra=self.__dict__)
            return False

        if self.error_text:
            _LOGGER.warning(
                "A%s < Invalid packet: error", self.packet, extra=self.__dict__
            )
            return False

        if not MESSAGE_REGEX.match(self.packet):
            err_msg = "packet structure bad"
        elif int(self.packet[46:49]) > 48:
            err_msg = "payload length excessive"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = f"payload length mismatch"
        else:
            return True

        _LOGGER.warning(
            "C%s < Invalid packet: %s", self.packet, err_msg, extra=self.__dict__
        )
        return False


class SerialPortManager:
    """Fake class docstring."""

    def __init__(self, serial_port, loop, timeout=READ_TIMEOUT) -> None:
        """Fake method docstring."""
        self.serial_port = serial_port
        self.baudrate = BAUDRATE
        self.timeout = timeout
        self.xonxoff = True
        self.loop = loop

        self.reader = self.write = None

    async def __aenter__(self):
        """Fake method docstring."""
        self.reader, self.writer = await serial_asyncio.open_serial_connection(
            loop=self.loop,
            url=self.serial_port,
            baudrate=self.baudrate,
            timeout=self.timeout,
            xonxoff=True,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        """Fake method docstring."""
        pass

    async def get_next_packet(self) -> str:
        """Get the next valid packet from a serial port."""
        try:
            raw_packet = await self.reader.readline()
        except serial.SerialException:
            return ""

        print(f"{raw_packet}")  # TODO: deleteme, only for debugging

        timestamp = time_stamp()
        packet_line = "".join(c for c in raw_packet.decode().strip() if c in printable)

        # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

        return f"{timestamp} {packet_line}" if packet_line else ""
