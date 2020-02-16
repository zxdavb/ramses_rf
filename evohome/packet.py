"""Packet processor."""

import asyncio
import ctypes
import logging
import os
from string import printable
import time
from typing import Optional

import serial

from .const import INSERT_SQL, MESSAGE_REGEX


_LOGGER = logging.getLogger(__name__)  # evohome.packet
_LOGGER.setLevel(logging.INFO)  # INFO or DEBUG


class FILETIME(ctypes.Structure):
    """Data structure for GetSystemTimePreciseAsFileTime()."""
    _fields_ = [("dwLowDateTime", ctypes.c_uint), ("dwHighDateTime", ctypes.c_uint)]


def time_stamp():
    """Return an accurate time, even for Windows-based systems."""
    if os.name == "nt":
        file_time = FILETIME()
        ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(file_time))
        _time = (file_time.dwLowDateTime + (file_time.dwHighDateTime << 32)) / 1e7
        return _time - 134774 * 24 * 60 * 60  # since 1601-01-01T00:00:00Z
    # if os.name == "posix":
    return time.time()  # since 1970-01-01T00:00:00Z


async def get_next_packet(gateway, source) -> Optional[str]:
    """Get the next valid/wanted packet, stamped with an isoformat datetime."""
    # pylint: disable=protected-access

    def is_wanted_packet(raw_packet, timestamp) -> bool:
        """Return True if a packet is wanted."""
        if gateway.config.get("white_list"):
            if not any(dev in raw_packet for dev in gateway.config["white_list"]):
                _LOGGER.debug(
                    "*** Unwanted packet: Not in whitelist: >>>%s<<<", raw_packet,
                    extra={"date": timestamp[:10], "time": timestamp[11:]}
                )
                return False
        if gateway.config.get("black_list"):
            if any(dev in raw_packet for dev in gateway.config["black_list"]):
                _LOGGER.debug(
                    "*** Unwanted packet: Blacklisted: >>>%s<<<", raw_packet,
                    extra={"date": timestamp[:10], "time": timestamp[11:]}
                )
                return False
        return True

    def is_valid_packet(raw_packet, timestamp) -> bool:
        """Return True if a packet is valid."""
        if not MESSAGE_REGEX.match(raw_packet):
            _LOGGER.warning(
                "*** Invalid packet: Packet structure bad: >>>%s<<<", raw_packet,
                extra={"date": timestamp[:10], "time": timestamp[11:]}
            )
            return False
        if int(raw_packet[46:49]) > 48:
            _LOGGER.warning(
                "*** Invalid packet: Payload too long: >>>%s<<<", raw_packet,
                extra={"date": timestamp[:10], "time": timestamp[11:]}
            )
            return False
        if len(raw_packet[50:]) != 2 * int(raw_packet[46:49]):
            _LOGGER.warning(
                "*** Invalid packet: Payload length mismatch: >>>%s<<<", raw_packet,
                extra={"date": timestamp[:10], "time": timestamp[11:]}
            )
            return False
        return True

    def get_packet_from_file(source) -> Optional[str]:  # ?async
        """Get the next valid packet from a log file."""
        raw_packet = source.readline()
        return raw_packet.strip()  # includes a timestamp

    async def get_packet_from_port(source) -> Optional[str]:
        """Get the next valid packet from a serial port."""
        try:
            raw_packet = await source.readline()
        except serial.SerialException:
            return

        # dt.now().isoformat() doesn't work well on Windows
        now = time.time()  # 1580666877.7795346
        if os.name == "nt":
            now = time_stamp()  # 1580666877.7795346
        mil = f"{now%1:.6f}".lstrip("0")  # .779535
        timestamp = time.strftime(f"%Y-%m-%dT%H:%M:%S{mil}", time.localtime(now))

        try:
            raw_packet = raw_packet.decode("ascii").strip()
        except UnicodeDecodeError:
            return

        raw_packet = "".join(c for c in raw_packet if c in printable)
        if not raw_packet:
            return

        # firmware-level packet hacks, i.e. non-HGI80 devices, should be here
        if raw_packet[:3] == "???":  # HACK: don't send nanoCUL packets to DB
            raw_packet = f"000 {raw_packet[4:]}"

            if gateway.config.get("database"):
                _LOGGER.warning(
                    "*** Using non-HGI firmware: Disabling database logging",
                    extra={"date": timestamp[:10], "time": timestamp[11:]}
                )
                gateway.config["database"] = gateway._output_db = None

            # if not gateway.config.get("listen_only"):  # TODO: make this once-only
            #     _LOGGER.warning(
            #         "*** Using non-HGI firmware: Packet sending may not work",
            #         extra={"date": timestamp[:10], "time": timestamp[11:]}
            #     )

        return f"{timestamp} {raw_packet}"  # timestamped_packet

    # get the next packet
    if isinstance(source, asyncio.streams.StreamReader):
        timestamped_packet = await get_packet_from_port(source)
    else:
        timestamped_packet = get_packet_from_file(source)
        if not timestamped_packet:
            source = None  # EOF

    if not timestamped_packet:
        return  # read timeout'd (serial port), or EOF (input file)

    packet = timestamped_packet[27:]
    timestamp = timestamped_packet[:26]

    # dont keep/process any invalid packets
    if not is_valid_packet(packet, timestamp):
        return

    # if enabled, log all valid packets (even if not wanted) to DB/file
    if gateway._output_db:
        w = [0, 27, 31, 34, 38, 48, 58, 68, 73, 77, 199]  # 165?
        data = tuple(
            [timestamped_packet[w[i - 1] : w[i] - 1] for i in range(1, len(w))]
        )

        _ = gateway._db_cursor.execute(INSERT_SQL, data)
        gateway._output_db.commit()

    if gateway._output_fp:
        gateway._output_fp.write(f"{timestamped_packet}\n")  # TODO: make async

    _LOGGER.info(packet, extra={"date": timestamp[:10], "time": timestamp[11:]})

    # only return *wanted* valid packets for further processing
    if is_wanted_packet(packet, timestamp):  # in whitelist (if there is one) and not in blacklist
        return timestamped_packet
