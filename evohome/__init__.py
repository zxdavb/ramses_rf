"""Evohome serial."""
from queue import Queue
import signal
import sys
from threading import Thread
import time
from curses.ascii import isprint
from datetime import datetime as dt
from typing import Tuple

import asyncio
import serial_asyncio

import serial

from .command import Command
from .const import (
    ALL_DEV_ID,
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
    NO_DEV_ID,
    PACKETS_FILE,
)
from .entity import System
from .logger import _CONSOLE, _LOGGER
from .message import Message

# from typing import Optional


PORT_NAME = "/dev/ttyUSB0"
BAUDRATE = 115200
READ_TIMEOUT = 0


class MessageWorker(Thread):
    """Fake docstring."""

    def __init__(self, gateway, queue):
        Thread.__init__(self)
        self.gateway = queue
        self.queue = queue


class RecvPacketWorker(MessageWorker):
    """Fake docstring."""

    def run(self):
        while True:
            try:
                pass
            finally:
                pass


class ProcMessageWorker(MessageWorker):
    """Fake docstring."""

    def run(self):
        while True:
            message = self.queue.get()
            try:
                pass
            finally:
                self.queue.task_done()


class SendCommandWorker(MessageWorker):
    """Fake docstring."""

    def run(self):
        while True:
            command = self.queue.get()
            try:
                pass
            finally:
                self.queue.task_done()


class Gateway:
    """The gateway class."""

    def __init__(
        self,
        serial_port=None,
        input_file=None,
        console_log=False,
        output_file=PACKETS_FILE,
        message_file=None,
        loop=None,
    ):
        if serial_port and input_file:  # must be mutually exclusive
            _LOGGER.warning(
                "Ignoring packet file (%s) as a port (%s) has been specified",
                input_file,
                serial_port
            )
            input_file = None

        elif not (serial_port or input_file):
            _LOGGER.warning("Using default port (%s)", PORT_NAME)
            serial_port = PORT_NAME

        self.serial_port = serial_port
        self.input_file = input_file
        self.output_file = output_file if output_file else PACKETS_FILE
        self._loop = loop if loop else asyncio.get_event_loop()

        self._input_fp = self._output_fp = None

        if console_log is True:
            _LOGGER.addHandler(_CONSOLE)

        self.command_queue = Queue(maxsize=200)
        self.message_queue = Queue(maxsize=400)

        self.reader = self.writer = None

        self.device_by_id = {}
        self.domain_by_id = {}
        self.zone_by_id = {}
        self.devices = []
        self.domains = []
        self.zones = []
        self.system = None

    async def start(self):
        """Enumerate the Controller, all Zones, and the DHW relay (if any)."""
        signal.signal(signal.SIGINT, self.signal_handler)

        if self.output_file:
            self._output_fp = open(self.output_file, "a+")

        if self.input_file:
            self._input_fp = open(self.input_file, "r")
            while True:
                await self._recv_message()

        else:
            self.reader, self.writer = await serial_asyncio.open_serial_connection(
                loop=self._loop,
                url=self.serial_port,
                baudrate=BAUDRATE,
                timeout=READ_TIMEOUT
            )

            while True:
                await self._recv_message()
                await self._send_command()

    def signal_handler(self, signum, frame):
        def print_database():
            print("zones = %s", {k: v.zone_type for k, v in self.domain_by_id.items()})
            print(
                "devices = %s", {k: v.device_type for k, v in self.device_by_id.items()}
            )

        print_database()  # TODO: deleteme

        self._output_fp.close()

        sys.exit()

    async def _recv_message(self) -> None:
        """Receive a message."""
        if self.input_file:
            raw_packet = await self._get_packet_from_file()

            if not raw_packet:
                return

        else:
            await asyncio.sleep(0.01)  # 0.05 was working well
            raw_packet = await self._get_packet_from_port()

            if raw_packet is None:
                return

        try:
            msg = Message(raw_packet[27:], self, pkt_dt=raw_packet[:26])
        except (ValueError, AssertionError):
            return

        if COMMAND_SCHEMA.get(msg.command_code):
            if COMMAND_SCHEMA[msg.command_code].get("non_evohome"):
                return  # ignore non-evohome commands

        if {msg.device_type[0], msg.device_type[1]} & {"GWY", "VNT"}:
            return  # ignore non-evohome device types

        if msg.device_id[0] == NO_DEV_ID and msg.device_type[2] == " 12":
            return  # ignore non-evohome device types

        if self.input_file:
            if "HGI" in [msg.device_type[0], msg.device_type[1]]:
                return  # ignore the HGI

        if not msg.payload:
            _LOGGER.info("%s  RAW: %s %s", msg._pkt_dt, msg, msg.raw_payload)
            return  # not a (currently) decodable payload
        else:
            _LOGGER.info("%s  MSG: %s %s", msg._pkt_dt, msg, msg.payload)

    async def _send_command(self) -> None:
        """Send a command."""
        if not self.command_queue.empty():
            cmd = self.command_queue.get()

            if not cmd.entity._data.get(cmd.command_code):
                self.writer.write(bytearray(f"{cmd}\r\n".encode("ascii")))

            self.command_queue.task_done()

        await asyncio.sleep(0.05)  # 0.1 was working well

    async def _get_packet_from_file(self) -> Tuple[str, str]:
        """Get the next valid packet, along with an isoformat datetime string."""

        raw_packet = self._input_fp.readline()

        return raw_packet.strip()

    async def _get_packet_from_port(self) -> Tuple[str, str]:
        """Get the next valid packet, along with an isoformat datetime string."""

        try:
            raw_packet = await self.reader.readline()
            raw_packet = raw_packet.decode("ascii").strip()
        except (serial.SerialException, UnicodeDecodeError):
            return

        raw_packet = "".join(char for char in raw_packet if isprint(char))

        if not raw_packet:
            return

        packet_dt = dt.now().isoformat()

        if self._output_fp:  # TODO: make this async
            self._output_fp.write(f"{packet_dt} {raw_packet}\r\n")

        if not MESSAGE_REGEX.match(raw_packet):
            _LOGGER.warning("Packet structure is not valid, >> %s <<", raw_packet)
            return

        if len(raw_packet[50:]) != 2 * int(raw_packet[46:49]):
            _LOGGER.warning("Packet payload length not valid, >> %s <<", raw_packet)
            return

        if int(raw_packet[46:49]) > 48:  # TODO: a ?corrupt pkt of 55 seen
            _LOGGER.warning("Packet payload length excessive, >> %s <<", raw_packet)
            return

        return f"{packet_dt} {raw_packet}"
