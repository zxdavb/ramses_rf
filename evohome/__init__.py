"""Evohome serial."""
import queue
import signal
import sys
import threading
import time
from curses.ascii import isprint
from datetime import datetime as dt
from typing import Tuple

import asyncio
import serial_asyncio

import serial

from .command import Command
from .const import (
    COMMAND_EXPOSES_ZONE,
    COMMAND_FORMAT,
    COMMAND_LOOKUP,
    COMMAND_MAP,
    COMMAND_SCHEMA,
    CTL_DEV_ID,
    DEVICE_LOOKUP,
    DEVICE_MAP,
    HGI_DEV_ID,
    MESSAGE_REGEX,
    PACKETS_FILE,
)
from .entity import System
from .logger import _CONSOLE, _LOGGER
from .message import Message

# from typing import Optional


PORT_NAME = "/dev/ttyUSB0"
PORT_BAUDRATE = 115200
PORT_BTYTESIZE = serial.EIGHTBITS
PORT_PARITY = serial.PARITY_NONE
PORT_STOPBITS = serial.STOPBITS_ONE
PORT_TIMEOUT = 0.1


def close_serial_port(serial_port=None):
    def close_port(port):
        if port.is_open:
            # port.reset_input_buffer()
            # port.reset_output_buffer()
            port.close()

        if port.is_open:
            return port
        return None

    print("Closing serial port...")
    for _ in range(3):
        not_closed = close_port(serial_port)
        if not_closed:
            time.sleep(3)

    if not_closed:
        print("port *not* closed")
    else:
        print("port closed (clean exit)")


def open_serial_port(serial_port_name):
    def open_port(port_name):
        try:
            port = serial.Serial(
                port=port_name,
                baudrate=PORT_BAUDRATE,
                # bytesize=serial.EIGHTBITS,
                # parity=serial.PARITY_NONE,
                # stopbits=serial.STOPBITS_ONE,
                timeout=0.1,
                # write_timeout=0
            )

        except serial.serialutil.SerialException as exc:
            _LOGGER.exception("Exception: %s", exc)
            return None

        if port.is_open:
            # _LOGGER.debug("Port opened: %s", port)
            return port

        _LOGGER.error("No port: %s", port)

    # _LOGGER.debug("Opening port: %s", port)
    for _ in range(2):
        serial_port = open_port(serial_port_name)
        if serial_port:
            break
    assert serial_port is not None
    return serial_port


class Gateway:
    """The gateway class."""

    def __init__(self, serial_port, console_log=False, fake_port=False, logfile=PACKETS_FILE):
        self.serial_port = serial_port if serial_port else PORT_NAME
        self.fake_port = fake_port
        self.logfile = logfile

        if console_log is True:
            _LOGGER.addHandler(_CONSOLE)

        self.device_by_id = {}
        self.domain_by_id = {}
        self.zone_by_id = {}
        self.devices = []
        self.domains = []
        self.zones = []
        self.system = None

        self.command_queue = queue.Queue(maxsize=200)
        self.message_queue = queue.Queue(maxsize=400)

        self.reader = self.writer = None

    async def start(self):
        """Enumerate the Controller, all Zones, and the DHW relay (if any)."""
        # self.fake_port = open(PACKETS_FILE, "r")  # TODO: set a flag

        self.reader, self.writer = await serial_asyncio.open_serial_connection(
            url=PORT_NAME, baudrate=PORT_BAUDRATE
        )

        self._packet_log = open(self.logfile, "a+")

        signal.signal(signal.SIGINT, self.signal_handler)

        await self.main_loop()

    async def main_loop(self) -> None:
        """The main loop."""
        while True:
            await self._recv_message()
            await self._send_command()

    def signal_handler(self, signum, frame):
        def print_database(self):
            print("zones = %s", {k: v.name for k, v in self.domain_by_id.items()})
            print("devices = %s", {k: v.type for k, v in self.device_by_id.items()})

        print_database()  # TODO: deleteme

        close_serial_port()
        self._packet_log.close()

        sys.exit()

    async def _recv_message(self) -> None:
        """Receive a message."""
        await asyncio.sleep(0.01)

        packet_dt, raw_packet = await self._get_packet()

        msg = Message(raw_packet, self, pkt_dt=packet_dt)

        if COMMAND_SCHEMA.get(msg.command_code):
            if COMMAND_SCHEMA[msg.command_code].get("non_evohome"):
                return  # continue  # ignore non-evohome commands

        if {msg.device_type[0], msg.device_type[1]} & {"GWY", "VNT"}:
            return  # continue  # ignore non-evohome device types

        if self.fake_port:
            if "HGI" in [msg.device_type[0], msg.device_type[1]]:
                return  # continue  # ignore the HGI

        if not msg.payload:  # not a (currently) decodable payload
            _LOGGER.info("%s  RAW: %s %s", msg._pkt_dt, msg, msg.raw_payload)
            return  # continue
        else:
            _LOGGER.info("%s  MSG: %s %s", msg._pkt_dt, msg, msg.payload)

    async def _send_command(self) -> None:
        """Send a command."""
        if not self.command_queue.empty():
            cmd = self.command_queue.get()

            if not cmd.entity._data.get(cmd.command_code):
                self.writer.write(bytearray(f"{cmd}\r\n".encode("ascii")))

            self.command_queue.task_done()

        await asyncio.sleep(0.1)

    async def _get_packet(self) -> Tuple[str, str]:
        """Get the next packet, along with an isoformat datetime string."""

        # if self.fake_port:
        #     raw_packet = self.fake_port.readline().strip()

        #     if raw_packet:
        #         packet_dt = raw_packet[:26]
        #         raw_packet = raw_packet[27:]
        #     else:
        #         return "EOF", None

        # else:
        while True:
            try:
                raw_packet = await self.reader.readline()
                raw_packet = raw_packet.decode("ascii").strip()
            except (serial.SerialException, UnicodeDecodeError):
                continue

            raw_packet = "".join(char for char in raw_packet if isprint(char))

            if not raw_packet:
                continue

            packet_dt = dt.now().isoformat()

            if self._packet_log:  # TODO: make this async
                self._packet_log.write(f"{packet_dt} {raw_packet}\r\n")

            if not MESSAGE_REGEX.match(raw_packet):
                _LOGGER.warning("Packet structure is not valid, >> %s <<", raw_packet)
                continue

            if len(raw_packet[50:]) != 2 * int(raw_packet[46:49]):
                _LOGGER.warning("Packet payload length not valid, >> %s <<", raw_packet)
                continue

            if int(raw_packet[46:49]) > 48:  # TODO: a ?corrupt pkt of 55 seen
                _LOGGER.warning("Packet payload length excessive, >> %s <<", raw_packet)
                continue

            return packet_dt, raw_packet
