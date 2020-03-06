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


def is_wanted_packet(raw_packet, dtm, black_list=None) -> bool:
    """Return False if any blacklisted text is in packet."""
    if not any(x in raw_packet for x in ([] if black_list is None else black_list)):
        _LOGGER.info(
            "%s", raw_packet, extra={"date": dtm[:10], "time": dtm[11:]},
        )
        return True

    _LOGGER.debug(
        "*** Ignored packet: >>>%s<<< (is in text blacklist)",
        raw_packet,
        extra={"date": dtm[:10], "time": dtm[11:]},
    )
    return False


def is_valid_packet(raw_packet, dtm, logging=True) -> bool:
    """Return True if a packet is valid."""
    if raw_packet is None:
        return False

    try:  # TODO: this entire block shouldn't be needed
        _ = MESSAGE_REGEX.match(raw_packet)
    except TypeError:
        _LOGGER.warning(
            "*** Invalid packet: >>>%s<<< (%s)",
            raw_packet,
            f"raw packet bad ({type(raw_packet)})",
            extra={"date": dtm[:10], "time": dtm[11:]},
        )
        return False

    else:
        if not MESSAGE_REGEX.match(raw_packet):
            err_msg = "packet structure bad"
        elif int(raw_packet[46:49]) > 48:
            err_msg = "payload too long"
        elif len(raw_packet[50:]) != 2 * int(raw_packet[46:49]):
            err_msg = "payload length mismatch"
        else:
            return True

        if logging is False:
            return False

        _LOGGER.warning(
            "*** Invalid packet: >>>%s<<< (%s)",
            raw_packet,
            err_msg,
            extra={"date": dtm[:10], "time": dtm[11:]},
        )
        return False


def is_wanted_device(raw_packet, white_list=None, black_list=None) -> bool:
    """Return True if a packet doesn't contain black-listed devices."""
    if " 18:" in raw_packet:
        return True
    if white_list:
        return any(device in raw_packet for device in white_list)
    return not any(device in raw_packet for device in black_list)


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

    async def get_next_packet(self):
        """Get the next valid packet from a serial port."""
        try:
            raw_packet = await self.reader.readline()
        except serial.SerialException:
            return (None, None)

        timestamp = time_stamp()  # at end of packet
        raw_packet = "".join(c for c in raw_packet.decode().strip() if c in printable)

        if not raw_packet:
            return (timestamp, None)

        # firmware-level packet hacks, i.e. non-HGI80 devices, should be here
        return (timestamp, raw_packet)
