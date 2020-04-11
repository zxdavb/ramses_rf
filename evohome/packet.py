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
        self._timestamp = timestamp_packet[:26]

        if not packet_line:  # TODO: validate timestamp
            raise ValueError(f"there is no packet, nor packet metadata: {packet_line}")

        self.date, self.time = self._timestamp[:10], self._timestamp[11:26]
        self.packet, self.error, self.comment = split_pkt_line(packet_line)

    def __str__(self) -> str:
        """Represent the entity as a string."""
        return f"{self._timestamp} {self.packet}{self.error}{self.comment}"


def is_wanted_packet(pkt, blacklist=None) -> bool:
    """Return False if any blacklisted text is in packet."""
    packet = pkt.get("packet")

    if not any(x in packet for x in ([] if blacklist is None else blacklist)):
        _LOGGER.info("%s", packet, extra=pkt)
        return True

    _LOGGER.debug("%s < Ignored packet: blacklisted by text", packet, extra=pkt)
    return False


def is_valid_packet(pkt: dict, logging=True) -> bool:
    """Return True if a packet is valid."""
    packet = pkt.get("packet")

    if pkt["error_text"]:
        _LOGGER.warning("%s", packet, extra=pkt)
        return False

    if not packet:
        if pkt["comment"]:
            _LOGGER.warning("%s", packet, extra=pkt)
        return False

    # try:  # TODO: this entire block shouldn't be needed
    #     _ = MESSAGE_REGEX.match(packet)
    # except TypeError:
    #     _LOGGER.warning(
    #         "%s < Invalid packet: TypeError (%s)", packet, type(packet), extra=pkt
    #     )
    #     return False

    # else:
    if not MESSAGE_REGEX.match(packet):
        err_msg = "packet structure bad"
    elif int(packet[46:49]) > 48:
        err_msg = "payload too long"
    elif len(packet[50:]) != 2 * int(packet[46:49]):
        err_msg = "payload length mismatch"
    else:
        return True

    # if logging is False:  # TODO: is needed?
    #     return False

    _LOGGER.warning("%s < Invalid packet: %s", packet, err_msg, extra=pkt)
    return False


def is_wanted_device(pkt, whitelist=None, blacklist=None) -> bool:
    """Return True if a packet doesn't contain blacklisted devices."""
    packet = pkt["packet"]
    # if " 18:" in packet:  # TODO: should we respect backlisting for this device?
    #     return True
    if whitelist:
        return any(device in packet for device in whitelist)
    return not any(device in packet for device in blacklist)


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
