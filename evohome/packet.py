"""Packet processor."""

import logging

import serial
import serial_asyncio
from string import printable

from .const import MESSAGE_REGEX
from .logger import time_stamp

_LOGGER = logging.getLogger(__name__)  # evohome.packet
_LOGGER.setLevel(logging.INFO)  # INFO or DEBUG

BAUDRATE = 115200  # 38400  #  57600  # 76800  # 38400  # 115200
READ_TIMEOUT = 0.5


def is_wanted_packet(pkt, blacklist=None) -> bool:
    """Return False if any blacklisted text is in packet."""
    packet = pkt["packet"]

    if not any(x in packet for x in ([] if blacklist is None else blacklist)):
        _LOGGER.info("%s", packet, extra=pkt)
        return True

    _LOGGER.debug("*** Ignored packet: >>>%s<<< (in text blacklist)", packet, extra=pkt)
    return False


def is_valid_packet(pkt, logging=True) -> bool:
    """Return True if a packet is valid."""
    packet = pkt["packet"]

    if packet is None:
        return False

    try:  # TODO: this entire block shouldn't be needed
        _ = MESSAGE_REGEX.match(packet)
    except TypeError:
        _LOGGER.warning(
            "*** Invalid packet: >>>%s<<< (%s)",
            packet,
            f"TypeError ({type(packet)})",
            extra=pkt,
        )
        return False

    else:
        if not MESSAGE_REGEX.match(packet):
            err_msg = "packet structure bad"
        elif int(packet[46:49]) > 48:
            err_msg = "payload too long"
        elif len(packet[50:]) != 2 * int(packet[46:49]):
            err_msg = "payload length mismatch"
        else:
            return True

        if logging is False:
            return False

        _LOGGER.warning("*** Invalid packet: >>>%s<<< (%s)", packet, err_msg, extra=pkt)
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

    async def get_next_packet(self) -> dict:
        """Get the next valid packet from a serial port."""
        try:
            raw_packet = await self.reader.readline()
        except serial.SerialException:
            return {}

        timestamp = time_stamp()  # at end of packet
        packet = "".join(c for c in raw_packet.decode().strip() if c in printable)

        # any firmware-level packet hacks, i.e. non-HGI80 devices, should be here

        return {
            "packet": packet,
            "packet_raw": raw_packet,
            "date": timestamp[:10],
            "time": timestamp[11:],
        }
