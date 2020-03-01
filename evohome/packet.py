"""Packet processor."""

import asyncio
import ctypes
import logging
import os
import time
from string import printable
from typing import Optional

import serial

from .const import INSERT_SQL, MESSAGE_REGEX
from .message import Message

_LOGGER = logging.getLogger(__name__)  # evohome.packet
_LOGGER.setLevel(logging.INFO)  # INFO or DEBUG


class FILETIME(ctypes.Structure):
    """Data structure for GetSystemTimePreciseAsFileTime()."""

    _fields_ = [("dwLowDateTime", ctypes.c_uint), ("dwHighDateTime", ctypes.c_uint)]


def time_stamp():
    """Return an accurate time, even for Windows-based systems."""
    # see: https://www.python.org/dev/peps/pep-0564/
    if os.name == "nt":
        file_time = FILETIME()
        ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(file_time))
        _time = (file_time.dwLowDateTime + (file_time.dwHighDateTime << 32)) / 1e7
        return _time - 134774 * 24 * 60 * 60  # since 1601-01-01T00:00:00Z
    # if os.name == "posix":
    return time.time()  # since 1970-01-01T00:00:00Z


async def get_next_packet(gateway, source, dont_parse=False) -> Optional[str]:
    """Get the next valid/wanted packet, stamped with an isoformat datetime."""
    # pylint: disable=protected-access

    def is_wanted_device(raw_packet, dtm=None) -> bool:
        """Return True if a packet doesn't contain black-listed packets."""
        if " 18:" in raw_packet:
            return True
        if gateway.device_white_list:
            return any(device in raw_packet for device in gateway.device_white_list)
        return not any(device in raw_packet for device in gateway.device_black_list)

    def is_parsing_packet(raw_packet, dtm) -> bool:
        """Return True if a packet is to be parsed."""
        # in whitelist (if there is one) and not in blacklist

        # whitelist = gateway.config["white_list"]
        # if whitelist and not any(x in raw_packet for x in whitelist):
        #     err_msg = "is not in whitelist"
        # elif any(x in raw_packet for x in gateway.config["black_list"]):
        #     err_msg = "is in blacklist"
        # else:
        #     return True

        # _LOGGER.debug(
        #     "*** Ignored packet: >>>%s<<< (%s)",
        #     raw_packet,
        #     err_msg,
        #     extra={"date": dtm[:10], "time": dtm[11:]},
        # )
        # return False
        return True

    def is_valid_packet(raw_packet, dtm) -> bool:
        """Return True if a packet is valid."""
        if not MESSAGE_REGEX.match(raw_packet):
            err_msg = "packet structure bad"
        elif int(raw_packet[46:49]) > 48:
            err_msg = "payload too long"
        elif len(raw_packet[50:]) != 2 * int(raw_packet[46:49]):
            err_msg = "payload length mismatch"
        else:
            return True

        _LOGGER.warning(
            "*** Invalid packet: >>>%s<<< (%s)",
            raw_packet,
            err_msg,
            extra={"date": dtm[:10], "time": dtm[11:]},
        )
        return False

    def get_packet_from_file(source) -> Optional[str]:  # ?async
        """Get the next valid packet from a log file."""
        timestamped_packet = source.readline()
        return timestamped_packet[:26], timestamped_packet[27:]

    async def get_packet_from_port(source) -> Optional[str]:
        """Get the next valid packet from a serial port."""

        def _timestamp() -> str:
            now = time_stamp()  # 1580666877.7795346
            mil = f"{now%1:.6f}".lstrip("0")  # .779535
            return time.strftime(f"%Y-%m-%dT%H:%M:%S{mil}", time.localtime(now))

        try:
            raw_packet = await source.readline()
        except serial.SerialException:
            return None, None

        timestamp = _timestamp()  # at end of packet
        raw_packet = "".join(c for c in raw_packet.decode().strip() if c in printable)

        if raw_packet:
            # firmware-level packet hacks, i.e. non-HGI80 devices, should be here
            return timestamp, raw_packet

    # get the next packet
    if isinstance(source, asyncio.streams.StreamReader):
        timestamp, packet = await get_packet_from_port(source)
    else:
        timestamp, packet = get_packet_from_file(source)
        if not packet:
            source = None  # EOF

    if not packet:
        return  # read timeout'd (serial port), or EOF (input file)

    # dont keep/process any invalid packets
    if not is_valid_packet(packet, timestamp):
        return

    # drop packets containing black-listed devices
    if not is_wanted_device(packet):
        return

    # if archiving is enabled, store all valid packets, even those not to be parsed
    if gateway._output_db:
        tsp = f"{timestamp} {packet}"
        w = [0, 27, 31, 34, 38, 48, 58, 68, 73, 77, 165]  # 165? 199 works
        data = tuple([tsp[w[i - 1] : w[i] - 1] for i in range(1, len(w))])  # noqa: E203

        _ = gateway._db_cursor.execute(INSERT_SQL, data)
        gateway._output_db.commit()

    _LOGGER.info("%s", packet, extra={"date": timestamp[:10], "time": timestamp[11:]})

    if dont_parse or not is_parsing_packet(packet, timestamp):
        return

    try:
        msg = Message(gateway, packet, timestamp)
    except (ValueError, AssertionError):
        _LOGGER.exception(
            "%s", packet, extra={"date": timestamp[:10], "time": timestamp[11:]}
        )
        return

    if not msg.is_valid_payload:
        return

    # UPDATE: only certain packets should become part of the canon
    try:
        if "18" in msg.device_id:  # leave in anyway?
            return
        elif msg.device_id[0][:2] == "--":
            gateway.device_by_id[msg.device_id[2]].update(msg)
        else:
            gateway.device_by_id[msg.device_id[0]].update(msg)
    except KeyError:
        pass
