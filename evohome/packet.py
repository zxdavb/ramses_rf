"""Packet processor."""

import logging

import serial  # TODO: dont import unless required
import serial_asyncio  # TODO: dont import unless required
from string import printable
from typing import Any, Optional, Tuple

from .const import MESSAGE_REGEX
from .logger import time_stamp

_LOGGER = logging.getLogger(__name__)  # evohome.packet

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

    def __init__(self, timestamp, packet_line, raw_packet_line=None) -> None:
        """Create a packet."""
        self.timestamp = timestamp
        self._packet_line = packet_line
        self._raw_packet_line = raw_packet_line

        assert timestamp
        if not bool(packet_line):
            raise ValueError("packet line is null: ", repr(self))

        self.date, self.time = self.timestamp[:10], self.timestamp[11:26]
        self.packet, self.error_text, self.comment = split_pkt_line(packet_line)
        self._packet = self.packet + " " if self.packet else ""  # TODO: a hack 4 log

        self._is_valid = None
        self._is_valid = self.is_valid

    def __str__(self) -> str:
        """Represent the packet as a string."""
        return self.packet if self.packet else ""

    def __repr__(self):
        """Represent the packet in an umabiguous manner."""
        return str(
            self._raw_packet_line if self._raw_packet_line else self._packet_line
        )

    @property
    def is_valid(self) -> bool:
        """Return True if the packet is valid in structure.

        All exceptions are to be trapped, and logged appropriately.
        """
        if self._is_valid is not None:
            return self._is_valid

        if self.error_text:
            if self.packet:
                _LOGGER.warning("%s < Bad packet: ", self, extra=self.__dict__)
            else:
                _LOGGER.warning("< Bad packet: ", extra=self.__dict__)
            return False

        if not self.packet:
            _LOGGER.warning("", extra=self.__dict__)
            return False

        if not MESSAGE_REGEX.match(self.packet):
            err_msg = "packet structure invalid"
        elif int(self.packet[46:49]) > 48:
            err_msg = "payload length excessive"
        elif int(self.packet[46:49]) * 2 != len(self.packet[50:]):
            err_msg = "payload length mismatch"
        else:
            # don't log good packets here: we may want to silently discard some
            # _LOGGER.info("%s", self, extra=self.__dict__)
            return True

        _LOGGER.warning("%s < Bad packet: %s ", self, err_msg, extra=self.__dict__)
        return False


class PortPktProvider:
    """Base class for packets from a serial port."""

    def __init__(self, serial_port, loop, timeout=READ_TIMEOUT) -> None:
        self.serial_port = serial_port
        self.baudrate = BAUDRATE
        self.timeout = timeout
        self.xonxoff = True
        self.loop = loop

        self.reader = self.write = None

    async def __aenter__(self):
        self.reader, self.writer = await serial_asyncio.open_serial_connection(
            loop=self.loop,
            url=self.serial_port,
            baudrate=self.baudrate,
            timeout=self.timeout,
            xonxoff=True,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        pass

    async def get_next_packet(self, prev_pkt=None) -> Tuple[str, Any]:
        """Get the next packet line from a serial port."""

        if prev_pkt and self.reader._transport.serial.in_waiting == 0:  # TODO: mem leak
            raw_packet = prev_pkt
        else:

            try:
                raw_packet = await self.reader.readline()
            except serial.SerialException:
                return

        # print(f"{raw_packet}")  # TODO: deleteme, only for debugging

        timestamp = time_stamp()
        packet = "".join(c for c in raw_packet.decode().strip() if c in printable)

        # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

        return f"{timestamp} {packet}" if packet else f"{timestamp}", raw_packet


class FilePktProvider:
    """Base class for packets from a serial port."""

    def __init__(self, file_name) -> None:
        self.file_name = file_name

    async def __aenter__(self):
        self.reader, self.writer = await serial_asyncio.open_serial_connection(
            loop=self.loop,
            url=self.serial_port,
            baudrate=self.baudrate,
            timeout=self.timeout,
            xonxoff=True,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        pass

    async def get_next_packet(self) -> Optional[str]:
        """Get the next packet line from a serial port."""
        try:
            raw_packet = await self.reader.readline()
        except serial.SerialException:
            return

        # print(f"{raw_packet}")  # TODO: deleteme, only for debugging

        timestamp = time_stamp()
        packet_line = "".join(c for c in raw_packet.decode().strip() if c in printable)

        # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

        return f"{timestamp} {packet_line}" if packet_line else f"{timestamp}"
