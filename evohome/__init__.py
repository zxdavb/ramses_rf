"""Evohome serial."""
import os
import psutil
process = psutil.Process(os.getpid())
import resource
# 32567296, 31804 vs 34639872, 33828
# 32919552, 32148

from queue import Queue
import signal
import sys
from threading import Thread
import time
from curses.ascii import isprint
from datetime import datetime as dt
from typing import Optional, Tuple

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


DEFAULT_PORT_NAME = "/dev/ttyUSB0"
BAUDRATE = 115200  # 38400  #  57600  # 76800  # 38400  # 115200
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
        **kwargs
    ):
        self.serial_port = serial_port
        self._config = kwargs

        if kwargs.get("console_log") is True:
            _LOGGER.addHandler(_CONSOLE)

        self.read_only = kwargs.get("listen_only", False)
        self._loop = kwargs.get("loop", asyncio.get_event_loop())

        self.input_file = kwargs.get("input_file")
        self.output_file = kwargs.get("output_file", PACKETS_FILE)
        self._error_fp = self._input_fp = self._output_fp = None

        if self.serial_port and self.input_file:  # must be mutually exclusive
            _LOGGER.warning(
                "Ignoring packet file (%s) as a port (%s) has been specified",
                self.input_file,
                self.serial_port
            )
            self.input_file = None

        elif not (self.serial_port or self.input_file):
            _LOGGER.warning("Using default port (%s)", DEFAULT_PORT_NAME)
            self.serial_port = DEFAULT_PORT_NAME

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

        async def _recv_message() -> None:
            """Receive a message."""
            raw_packet = await self.get_packet()

            if raw_packet is None:
                return

            if self._config.get("raw_packets"):
                _LOGGER.info("%s PKT: %s", raw_packet[:26], raw_packet[27:])
                return

            try:
                msg = Message(raw_packet[27:], self, pkt_dt=raw_packet[:26])
            except (ValueError, AssertionError):
                return

            if not msg.payload:
                _LOGGER.info("%s RAW: %s %s", msg._pkt_dt, msg, msg.raw_payload)
                return  # not a (currently) decodable payload
            # elif msg.non_evohome:  # TODO: make a switch
            #     return
            else:
                _LOGGER.info("%s MSG: %s %s", msg._pkt_dt, msg, msg.payload)

        async def _send_command() -> None:
            """Send a command."""
            if not self.command_queue.empty():
                cmd = self.command_queue.get()

                if not self.read_only:
                    if not cmd.entity._data.get(cmd.command_code):
                        self.writer.write(bytearray(f"{cmd}\r\n".encode("ascii")))

                self.command_queue.task_done()

            await asyncio.sleep(0.05)  # 0.1 was working well

        signal.signal(signal.SIGINT, self._signal_handler)

        if self.output_file:
            self._output_fp = open(self.output_file, "a+")
            self._error_fp = open(f"{self.output_file}", "a+")

        if self.input_file:
            self._input_fp = open(self.input_file, "r")
            while True:
                await _recv_message()

        else:
            self.reader, self.writer = await serial_asyncio.open_serial_connection(
                loop=self._loop,
                url=self.serial_port,
                baudrate=BAUDRATE,
                timeout=READ_TIMEOUT
            )

            i = 20
            while True:
                await _recv_message()
                await _send_command()

                if i == 100:  # TODO remove me - only to chase memory leak
                    i = 0
                    print(
                        f"{process.memory_info().rss}, "
                        f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}"
                    )

                i += 1

    def _signal_handler(self, signum, frame):
        def print_database():
            print("zones = %s", {k: v.zone_type for k, v in self.domain_by_id.items()})
            print(
                "devices = %s", {k: v.device_type for k, v in self.device_by_id.items()}
            )

        print_database()  # TODO: deleteme

        self._error_fp.close()
        self._output_fp.close()

        sys.exit()

    async def get_packet(self) -> Optional[str]:
        """Get the next valid packet, prepended with an isoformat datetime."""

        def unwanted_packet(raw_packet) -> bool:
            """Return True only if a packet is not wanted."""
            if any(x in raw_packet for x in ["12:227486", "13:171587"]):
                return True  # neighbour

            if any(x in raw_packet for x in ["30:082155", "32:206250", "32:168090"]):
                return True  # nuaire

            return False

        def valid_packet(raw_packet) -> bool:
            """Return True only if a packet is valid."""
            if not MESSAGE_REGEX.match(raw_packet):
                _LOGGER.debug(
                    "Invalid packet: "
                    "Structure is not valid, >> %s <<", raw_packet
                )
                return False

            if len(raw_packet[50:]) != 2 * int(raw_packet[46:49]):
                _LOGGER.warning(
                    "Invalid packet: "
                    "Payload length is incorrect, >> %s <<", raw_packet
                )
                return False

            if int(raw_packet[46:49]) > 48:
                _LOGGER.warning(
                    "Invalid packet: "
                    "Payload length is excessive, >> %s <<", raw_packet
                )
                return False

            return True

        async def get_packet_from_db() -> Optional[str]:
            """Get the next valid packet from a database."""
            return None  # TODO: needs doing

        async def get_packet_from_file() -> Optional[str]:
            """Get the next valid packet from a log file."""
            raw_packet = self._input_fp.readline()

            return raw_packet.strip()

        async def get_packet_from_port() -> Optional[str]:
            """Get the next valid packet from a serial port."""
            try:
                raw_packet = await self.reader.readline()
                raw_packet = raw_packet.decode("ascii").strip()
            except (serial.SerialException, UnicodeDecodeError):
                return

            raw_packet = "".join(char for char in raw_packet if isprint(char))

            if not raw_packet:
                return

            packet_dt = dt.now().isoformat()

            # firmware packet hacks, e.g. non-HGI80 firmware, should be done here
            # raw_packet = re.sub(r"", "", raw_packet)

            return f"{packet_dt} {raw_packet}"

        # get the next packet
        if self.input_file:
            timestamped_packet = await get_packet_from_file()
        elif False:  # TODO: needs doing
            timestamped_packet = await get_packet_from_db()
        else:
            # await asyncio.sleep(0.01)  # 0.05 was working well
            timestamped_packet = await get_packet_from_port()

        if not timestamped_packet:
            return None

        if not valid_packet(timestamped_packet[27:]):
            if self._error_fp:
                self._error_fp.write(f"{timestamped_packet}\r\n")  # TODO: make async
                self._error_fp.flush()
            return None

        # if self._config.get("raw_packets"):
        #     return timestamped_packet

        # most packet hacks should be done after this point
        if unwanted_packet(timestamped_packet[27:]):
            return None

        # log it to file, or DB if required
        if self._output_fp:
            self._output_fp.write(f"{timestamped_packet}\r\n")  # TODO: make async

        return timestamped_packet
