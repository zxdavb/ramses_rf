"""Evohome serial."""
import queue
import signal
import sys
import threading
import time
from curses.ascii import isprint
from datetime import datetime as dt
from typing import Tuple

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
from .logger import _LOGGER
from .message import Message

# https://gist.github.com/Dobiasd/37705392b4aaa3a3539ba1a61efec6b6
# https://codereview.stackexchange.com/questions/202393/a-thread-safe-priority-queue-keeping-its-elements-unique

# from typing import Optional


PORT_NAME = "/dev/ttyUSB0"
PORT_BAUDRATE = 115200
PORT_BTYTESIZE = serial.EIGHTBITS
PORT_PARITY = serial.PARITY_NONE
PORT_STOPBITS = serial.STOPBITS_ONE
PORT_TIMEOUT = 0.1


def close_serial_port(serial_port):
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

    def __init__(self, serial_port=PORT_NAME):
        self.device_by_id = {}
        self.domain_by_id = {}
        self.system = None

        self.command_queue = queue.Queue(maxsize=200)
        self.message_queue = queue.Queue(maxsize=400)

        self._packet_log = open(PACKETS_FILE, "a+")
        self.ser = open_serial_port(serial_port)  # TODO: move out of __init__
        self.fake_port = None

        signal.signal(signal.SIGINT, self.signal_handler)

    def print_database(self):
        print("zones = %s", {k: v.name for k, v in self.domain_by_id.items()})
        print("devices = %s", {k: v.type for k, v in self.device_by_id.items()})

    def signal_handler(self, signum, frame):
        self.print_database()  # TODO: deleteme

        close_serial_port(self.ser)
        self._packet_log.close()

        sys.exit()

    def _get_packet(self, timeout=0.1) -> Tuple[str, str]:
        """Get the next packet, along with an isoformat dt string."""

        if self.fake_port:
            raw_packet = self.fake_port.readline().strip()

            if raw_packet:
                packet_dt = raw_packet[:26]
                raw_packet = raw_packet[27:]
            else:
                return "EOF", None

        else:
            self.ser.timeout = timeout

            try:
                raw_packet = self.ser.readline().decode("ascii").strip()
            except UnicodeDecodeError:
                return None, None

            raw_packet = "".join(char for char in raw_packet if isprint(char))

            if not raw_packet:
                return None, None

            if not isinstance(raw_packet, str):
                _LOGGER.warning("Packet datatype is not a string, >> %s <<", raw_packet)
                return None, None

            packet_dt = dt.now().isoformat()

            if self._packet_log:
                self._packet_log.write(f"{packet_dt} {raw_packet}\r\n")

        if not MESSAGE_REGEX.match(raw_packet):
            _LOGGER.warning("Packet structure is not valid, >> %s <<", raw_packet)
            return None, None

        if len(raw_packet[50:]) != 2 * int(raw_packet[46:49]):
            _LOGGER.warning("Packet payload length is not valid, >> %s <<", raw_packet)
            return None, None

        if int(raw_packet[46:49]) > 48:
            _LOGGER.warning("Packet payload length is excessive, >> %s <<", raw_packet)
            return None, None

        return raw_packet, packet_dt

    def start(self):
        """Enumerate the Controller, all Zones, and the DHW relay (if any)."""
        x = threading.Thread(target=self.main_loop, daemon=True)
        x.start()

        # y = threading.Thread(target=self.process_packets, daemon=True)
        # y.start()

        x.join()

    def main_loop(self):
        """The main loop."""
        # self.fake_port = open(PACKETS_FILE, "r")  # TODO: set a flag

        while True:
            if self.ser.in_waiting != 0:  # or self.fake_port:
                raw_packet, pkt_datetime = self._get_packet()

                if raw_packet:
                    # print(pkt_datetime, raw_packet)
                    # self.message_queue.put((raw_packet, pkt_datetime))
                    self.process_packets(raw_packet, pkt_datetime)

                continue

            if not self.command_queue.empty():
                _cmd = self.command_queue.get()
                self.ser.write(bytearray(f"{_cmd}\r\n".encode("ascii")))

                # time.sleep(0.1)  # 0.1 works reliably
                self.command_queue.task_done()
                time.sleep(0.1)  # 0.1 works reliably

    def process_packets(self, raw_packet, pkt_datetime):
        """The main loop."""

        # while True:
        # if not self.message_queue.empty():
        # raw_packet, pkt_datetime = self.message_queue.get()
        # self.message_queue.task_done()

        msg = Message(raw_packet, self, pkt_dt=pkt_datetime)

        if COMMAND_SCHEMA.get(msg.command_code):
            if COMMAND_SCHEMA[msg.command_code].get("non_evohome"):
                return  # continue  # ignore non-evohome commands

        if {msg.device_type[0], msg.device_type[1]} & {"GWY", "VNT"}:
            return  # continue  # ignore non-evohome device types

        # if "HGI" in [msg.device_type[0], msg.device_type[1]]:
        #     continue  # ignore the HGI

        if not msg.payload:  # not a (currently) decodable payload
            # _LOGGER.info("RAW: %s | %-8s ||", str(msg)[:80], msg.raw_payload)
            _LOGGER.info("%s  RAW: %s %s", msg._pkt_dt, msg, msg.raw_payload)
            return  # continue
        else:
            _LOGGER.info("%s  MSG: %s %s", msg._pkt_dt, msg, msg.payload)
