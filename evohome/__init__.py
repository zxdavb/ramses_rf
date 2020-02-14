"""Evohome serial."""
import ctypes
import os
from queue import Queue
import signal
import sys
from threading import Thread
import time

from string import printable
from datetime import datetime as dt
from typing import Optional

import asyncio
import serial_asyncio
import sqlite3

import serial

from .command import Command
from .const import (
    NUL_DEV_ID,
    COMMAND_EXPOSES_ZONE,
    COMMAND_FORMAT,
    COMMAND_LOOKUP,
    COMMAND_MAP,
    COMMAND_REGEX,
    COMMAND_SCHEMA,
    CTL_DEV_ID,
    DEVICE_LOOKUP,
    DEVICE_MAP,
    HGI_DEV_ID,
    MESSAGE_REGEX,
    NON_DEV_ID,
    PACKETS_FILE,
)
from .entity import System
from .logger import _CONSOLE, _LOGGER
from .message import Message

# from typing import Optional


DEFAULT_DATABASE = "evohome_rf.db"
BAUDRATE = 115200  # 38400  #  57600  # 76800  # 38400  # 115200
READ_TIMEOUT = 0

TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS packets (
        dt      TEXT PRIMARY KEY,
        rssi    TEXT NOT NULL,
        verb    TEXT NOT NULL,
        seq     TEXT NOT NULL,
        dev_1   TEXT NOT NULL,
        dev_2   TEXT NOT NULL,
        dev_3   TEXT NOT NULL,
        code    TEXT NOT NULL,
        len     TEXT NOT NULL,
        payload TEXT NOT NULL
    ) WITHOUT ROWID;
"""
INDEX_SQL = "CREATE INDEX IF NOT EXISTS code_idx ON packets(code);"
INSERT_SQL = """
    INSERT INTO packets(dt, rssi, verb, seq, dev_1, dev_2, dev_3, code, len, payload)
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""


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

    def __init__(self, serial_port, loop=None, **kwargs):
        self.serial_port = serial_port
        self.loop = kwargs.get("loop", asyncio.get_event_loop())
        self.config = kwargs

        self._input_fp = self._output_fp = None
        self._output_db = self._db_cursor = None

        if self.serial_port and kwargs.get("input_file"):
            _LOGGER.warning("Ignoring input file (%s)", kwargs["input_file"])
            kwargs["input_file"] = None

        if kwargs.get("input_file") and not self.config.get("listen_only"):
            _LOGGER.warning("Forcing listen_only mode on")
            self.config["listen_only"] = True

        self.reader = self.writer = None

        self.command_queue = Queue(maxsize=200)
        self.message_queue = Queue(maxsize=400)

        self.system = System(self)

        self.zones = []
        self.zone_by_id = {}

        self.domains = []
        self.domain_by_id = {}

        self.devices = []
        self.device_by_id = {}

        self.data = {f"{i:02X}": {} for i in range(12)}

    def _signal_handler(self, signum, frame):
        print(f"\r\n{self.database}")  # TODO: deleteme

        if self._output_fp:
            self._output_fp.close()
        sys.exit()

    @property
    def database(self) -> Optional[dict]:
        controllers = [d for d in self.devices if d.device_type == "CTL"]
        if len(controllers) != 1:
            print("fail test 0: more/less than 1 controller")
            return

        database = {
            "controller": controllers[0].device_id,
            "boiler": {
                "dhw_sensor": controllers[0].dhw_sensor,
                "tpi_relay": controllers[0].tpi_relay,
            },
            "zones": {},
            #  "devices": {},
        }

        orphans = database["orphans"] = [
            d.device_id for d in self.devices if d.parent_zone is None
        ]

        database["heat_demand"] = {
            d.device_id: d.heat_demand
            for d in self.devices
            if hasattr(d, "heat_demand")
        }

        thermometers = database["thermometers"] = {
            d.device_id: d.temperature
            for d in self.devices
            if hasattr(d, "temperature")
        }
        thermometers.pop(database["boiler"]["dhw_sensor"], None)

        for z in self.zone_by_id:  # [z.zone_idx for z in self.zones]:
            actuators = [k for d in self.data[z].get("actuators", []) for k in d.keys()]
            children = [d.device_id for d in self.devices if d.parent_zone == z]

            zone = database["zones"][z] = {
                "name": self.data[z].get("name"),  # TODO: do it this way
                "temperature": self.zone_by_id[z].temperature,  # TODO: or this way
                "heat_demand": self.zone_by_id[z].heat_demand,
                "sensor": None,
                "actuators": actuators,
                "children": children,  # TODO: could this include non-actuators?
                "devices": list(set(actuators) | set(children)),
            }
            orphans = list(set(orphans) - set(zone["devices"]))

        # check each zones has a unique (and non-null) temperature
        zone_map = {
            str(v["temperature"]): k
            for k, v in database["zones"].items()
            if v["temperature"] is not None
        }

        # for z in self.zone_by_id:  # [z.zone_idx for z in self.zones]:
        #     if

        # TODO: needed? or just process only those with a unique temp?
        if len(zone_map) != len(database["zones"]):  # duplicate/null temps
            print("fail test 1: non-unique (null) zone temps")
            return database

        # check all possible sensors have a unique temp - how?
        temp_map = [t for t in thermometers.values() if t is not None]
        if len(temp_map) != len(thermometers):  # duplicate/null temps
            print("fail test 2: null device temps")
            return database

        temp_map = {str(v): k for k, v in thermometers.items() if v is not None}

        for zone_idx in database["zones"]:
            zone = database["zones"][zone_idx]
            sensor = temp_map.get(str(zone["temperature"]))
            if sensor:
                zone["sensor"] = sensor
                # if sensor in database["orphans"]:
                #     database["orphans"].remove(sensor)
                orphans = list(set(orphans) - set(sensor))

        # TODO: max 1 remaining zone without a sensor
        # if len(thermometers) == 0:
        # database.pop("thermometers")

        return database

    async def start(self):
        """This is a docstring."""

        def scan_tight(dest_id):
            for code in COMMAND_SCHEMA:
                cmd = Command(self, code, verb="RQ", dest_id=dest_id, payload="0100")
                yield cmd

        async def scan_loose():
            # # BEGIN crazy test block
            dest_id = "01:145038"  # "07:045960"  # "13:106039"  # "13:237335"  #

            i = 0x0
            while i < 0x4010:
                await _recv_message(source=self.reader)
                # pylint: disable=protected-access
                if self.reader._transport.serial.in_waiting != 0:
                    continue

                code = f"{i:04X}"

                cmd = Command(self, code, verb="RQ", dest_id=dest_id, payload="F9")
                self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
                await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short

                cmd = Command(self, code, verb="RQ", dest_id=dest_id, payload="FA")
                self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
                await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short

                cmd = Command(self, code, verb="RQ", dest_id=dest_id, payload="FC")
                self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
                await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short

                if i % 20 == 19:
                    await asyncio.sleep(20)  #  20 OK with 0.8, 30 OK with 1.0

                if not self.command_queue.empty():
                    self.command_queue.get()
                    self.command_queue.task_done()

                i += 1
            # # ENDS crazy test block

        async def _recv_message(source) -> None:
            """Receive a packet and validate it as a message."""
            raw_packet = await self._get_packet(source)

            if raw_packet is None:
                return

            if self.config.get("raw_output"):
                _LOGGER.info("%s %s", raw_packet[:23], raw_packet[27:])
                return

            try:
                msg = Message(raw_packet[27:], self, pkt_dt=raw_packet[:26])
            except (ValueError, AssertionError):
                _LOGGER.exception("%s ERR: %s", raw_packet[:23], raw_packet[27:])
                return True

            if msg.payload is None:
                _LOGGER.info("%s RAW: %s %s", raw_packet[:23], msg, msg.raw_payload)
            else:
                _LOGGER.info("%s MSG: %s %s", raw_packet[:23], msg, msg.payload)

            # UPDATE: only certain packets should become part of the canon
            try:
                if "HGI" in msg.device_type:  # leave in anyway?
                    return
                elif msg.device_type[0] == " --":
                    self.device_by_id[msg.device_id[2]].update(msg)
                else:
                    self.device_by_id[msg.device_id[0]].update(msg)
            except KeyError:
                pass

        async def _send_command(destination) -> None:
            """Send a command unless in listen_only mode."""
            if not self.command_queue.empty():
                cmd = self.command_queue.get()

                if destination is self.writer:
                    # TODO: if not cmd.entity._pkts.get(cmd.code):
                    self.writer.write(bytearray(f"{cmd}\r\n".encode("ascii")))
                    await asyncio.sleep(0.05)  # 0.05 works well, 0.03 too short
                elif destination is None:
                    pass

                self.command_queue.task_done()

        signal.signal(signal.SIGINT, self._signal_handler)

        if self.config.get("database"):
            self._output_db = sqlite3.connect(DEFAULT_DATABASE)  # TODO: self.config...
            self._db_cursor = self._output_db.cursor()
            _ = self._db_cursor.execute(TABLE_SQL)
            _ = self._db_cursor.execute(INDEX_SQL)
            self._output_db.commit()

        if self.config.get("output_file"):
            self._output_fp = open(self.config["output_file"], "a+")

        # source of packets is either a text file, or a serial port:
        if self.config.get("input_file"):
            try:
                self._input_fp = open(self.config["input_file"], "r")
            except OSError:
                raise  # TODO: do something better

            while self._input_fp:
                await _recv_message(source=self._input_fp)
                await _send_command(destination=None)  # to empty the buffer

        else:  # self.config["serial_port"]
            try:
                self.reader, self.writer = await serial_asyncio.open_serial_connection(
                    loop=self.loop,
                    url=self.serial_port,
                    baudrate=BAUDRATE,
                    timeout=READ_TIMEOUT,
                    xonxoff=True
                )
            except serial.serialutil.SerialException:
                raise  # TODO: do something better

            if self.config.get("execute_cmd"):  # e.g. "RQ 01:145038 0418 000000"
                cmd = self.config["execute_cmd"]
                # self.command_queue.put_nowait(
                #     Command(self, cmd[13:17], cmd[:2], cmd[3:12], cmd[18:])
                # )
                cmd = Command(self, cmd[13:17], cmd[:2], cmd[3:12], cmd[18:])
                self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
                await asyncio.sleep(0.05)  # 0.05 works well, 0.03 too short

            for code in COMMAND_SCHEMA:
                # pylint: disable=protected-access
                while self.reader._transport.serial.in_waiting > 0:
                    await _recv_message(source=self.reader)

                cmd = Command(self, code, verb="RQ", dest_id=CTL_DEV_ID, payload="FF")
                self.writer.write(bytearray(f"{str(cmd)}\r\n".encode("ascii")))
                await asyncio.sleep(0.7)  # 0.8, 1.0 OK, 0.5 too short

                while not self.command_queue.empty():
                    self.command_queue.get()
                    self.command_queue.task_done()

            while True:  # main loop when packets from serial port
                await _recv_message(source=self.reader)
                # pylint: disable=protected-access
                if self.reader._transport.serial.in_waiting == 0:
                    await _send_command(destination=self.writer)

    async def _get_packet(self, source) -> Optional[str]:
        """Get the next valid/wanted packet, stamped with an isoformat datetime."""

        def wanted_packet(raw_packet) -> bool:
            """Return True only if a packet is wanted."""
            if self.config.get("black_list"):
                return not any(dev in raw_packet for dev in self.config["black_list"])
            if self.config.get("white_list"):
                return any(dev in raw_packet for dev in self.config["white_list"])
            return True  # the two lists are mutex

        def valid_packet(timestamped_packet) -> bool:
            """Return True only if a packet is valid."""
            raw_packet = timestamped_packet[27:]
            if not MESSAGE_REGEX.match(raw_packet):
                _LOGGER.debug(
                    "%s Invalid packet: Structure is bad: >>>%s<<<",
                    timestamped_packet[:23],
                    raw_packet,
                )
                return False
            if int(raw_packet[46:49]) > 48:
                _LOGGER.debug(
                    "%s Invalid packet: Payload too long: >>>%s<<<",
                    timestamped_packet[:23],
                    raw_packet,
                )
                return False
            if len(raw_packet[50:]) != 2 * int(raw_packet[46:49]):
                _LOGGER.debug(
                    "%s Invalid packet: Length mismatch: >>>%s<<<",
                    timestamped_packet[:23],
                    raw_packet,
                )
                return False
            return True

        def get_packet_from_file() -> Optional[str]:  # ?async
            """Get the next valid packet from a log file."""
            raw_packet = self._input_fp.readline()
            return raw_packet.strip()  # includes a timestamp

        async def get_packet_from_port() -> Optional[str]:
            """Get the next valid packet from a serial port."""
            try:
                raw_packet = await self.reader.readline()
            except serial.SerialException:
                return

            # dt.now().isoformat() doesn't work well on Windows
            now = time.time()  # 1580666877.7795346
            if os.name == "nt":
                now = time_stamp()  # 1580666877.7795346
            mil = f"{now%1:.6f}".lstrip("0")  # .779535
            packet_dt = time.strftime(f"%Y-%m-%dT%H:%M:%S{mil}", time.localtime(now))

            try:
                raw_packet = raw_packet.decode("ascii").strip()
            except UnicodeDecodeError:
                return

            raw_packet = "".join(c for c in raw_packet if c in printable)
            if not raw_packet:
                return

            # firmware-level packet hacks, i.e. non-HGI80 devices, should be here
            if raw_packet[:3] == "???":  # do'nt send nanoCUL packets to DB
                if self.config.get("database"):
                    _LOGGER.warning("Forcing database off")
                    self.config["database"] = None
                raw_packet = f"000 {raw_packet[4:]}"

            return f"{packet_dt} {raw_packet}"

        # get the next packet
        if source == self._input_fp:
            timestamped_packet = get_packet_from_file()
            if not timestamped_packet:  # is EOF
                self._input_fp = None
                return

        elif source == self.reader:  # self.serial_port
            timestamped_packet = await get_packet_from_port()
            if not timestamped_packet:  # may have read timeout'd
                return None

        # dont keep/process invalid packets
        if not valid_packet(timestamped_packet):
            return None

        # log all valid packets (even if not wanted) to DB if enabled
        if self._output_db:
            w = [0, 27, 31, 34, 38, 48, 58, 68, 73, 77, 199]  # 165?
            data = tuple(
                [timestamped_packet[w[i - 1] : w[i] - 1] for i in range(1, len(w))]
            )

            _ = self._db_cursor.execute(INSERT_SQL, data)
            self._output_db.commit()

        # log all valid packets (even if not wanted) to file if enabled
        if self._output_fp:
            self._output_fp.write(f"{timestamped_packet}\n")  # TODO: make async

        # only return wanted packets for further processing
        if wanted_packet(timestamped_packet[27:]):
            return timestamped_packet  # in whitelist or not in blacklist
