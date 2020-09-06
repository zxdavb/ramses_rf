"""Evohome serial."""
import asyncio
from collections import deque
import json
import logging
import os
from queue import PriorityQueue
import signal
import sys
from threading import Lock
from typing import Dict, List

from .command import Command
from .const import __dev_mode__, ATTR_ORPHANS
from .devices import DEVICE_CLASSES, Device
from .logger import set_logging, BANDW_SUFFIX, COLOR_SUFFIX, CONSOLE_FMT, PKT_LOG_FMT
from .message import _LOGGER as msg_logger, Message
from .packet import (
    _LOGGER as pkt_logger,
    Packet,
    PortPktProvider,
    file_pkts,
    port_pkts,
)

from .schema import CONFIG_SCHEMA, KNOWNS_SCHEMA, load_schema
from .ser2net import Ser2NetServer
from .system import EvoSystem

# TODO: duplicated in schema.py
DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


async def schedule_task(delay, func, *args, **kwargs):
    """Start a coro after delay seconds."""

    async def scheduled_func(delay, func, *args, **kwargs):
        await asyncio.sleep(delay)
        await func(*args, **kwargs)

    asyncio.create_task(scheduled_func(delay, func, *args, **kwargs))


class GracefulExit(SystemExit):
    code = 1


class Gateway:
    """The gateway class."""

    def __init__(self, serial_port, loop=None, **config) -> None:
        """Initialise the class."""

        if config.get("debug_mode"):
            _LOGGER.setLevel(logging.DEBUG)  # should be INFO?
            _LOGGER.debug("Starting evohome_rf, **config = %s", config)

        self.serial_port = serial_port
        self._loop = loop if loop else asyncio.get_running_loop()  # get_event_loop()
        self.config = CONFIG_SCHEMA(config)

        if self.serial_port and self.config.get("input_file"):
            _LOGGER.warning(
                "Serial port specified (%s), so ignoring input file (%s)",
                self.serial_port,
                self.config["input_file"],
            )
            # self.config["input_file"] = None
        elif self.config.get("input_file") is not None:
            self.config["disable_sending"] = True

        self._execute_cmd = self.config.get("execute_cmd")

        if self.config["reduce_processing"] >= DONT_CREATE_MESSAGES:
            _stream = (None, sys.stdout)
        else:
            _stream = (sys.stdout, None)
        set_logging(msg_logger, stream=_stream[0], file_name=None)
        set_logging(
            pkt_logger,
            stream=_stream[1],
            file_name=self.config.get("packet_log"),
            file_fmt=PKT_LOG_FMT + BANDW_SUFFIX,
            cons_fmt=CONSOLE_FMT + COLOR_SUFFIX,
        )

        self.cmd_que = PriorityQueue()  # TODO: maxsize=200)
        self._buffer = deque()
        self._sched_zone = None
        self._sched_lock = Lock()

        self._prev_msg = None

        self._tasks = []
        self._setup_signal_handler()

        # if config.get("ser2net_server"):
        self._relay = None  # ser2net_server relay

        # if self.config["reduce_processing"] > 0:
        self.evo = None  # EvoSystem(controller=config["controller_id"])
        self.systems: List[EvoSystem] = []
        self.system_by_id: Dict = {}
        self.devices: List[Device] = []
        self.device_by_id: Dict = {}

        self._schema = config.pop("schema", {})
        self.known_devices = {}  # self._include_list + self._exclude_list
        self._known_devices = (
            load_schema(self, self._schema) if self.config["use_schema"] else {}
        )
        self.config["known_devices"] = False  # bool(self.known_devices)

        self._include_list = {}
        self._exclude_list = {}
        if self.config["enforce_allowlist"]:
            self._include_list = KNOWNS_SCHEMA(config.pop("allowlist", {}))
        elif self.config["enforce_blocklist"]:
            self._exclude_list = KNOWNS_SCHEMA(config.pop("blocklist", {}))

    def __repr__(self) -> str:
        return json.dumps(self.schema)

    def __str__(self) -> str:
        return json.dumps(self.schema, indent=2)

    def _setup_signal_handler(self):
        def _sig_handler_win32(signalnum, frame):
            """2 = signal.SIGINT (Ctrl-C)."""
            _LOGGER.info("Received a signal (signalnum=%s), processing...", signalnum)

            if signalnum == signal.SIGINT:  # is this the only useful win32 signal?
                self.cleanup("_sig_handler_win32()")

                raise GracefulExit()

        async def _sig_handler_posix(signal):
            """Handle signals on posix platform."""
            _LOGGER.info("Received a signal (%s), processing...", signal.name)

            if signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                self.cleanup("_sig_handler_posix()")  # OK for after tasks.cancel

                tasks = [
                    t for t in asyncio.all_tasks() if t is not asyncio.current_task()
                ]
                [task.cancel() for task in tasks]
                logging.debug(f"Cancelling {len(tasks)} outstanding tasks...")

                # raise CancelledError
                await asyncio.gather(*tasks, return_exceptions=True)

            elif signal == signal.SIGUSR1:
                _LOGGER.info("Params: \r\n%s", {self.evo.id: self.evo.params})

            elif signal == signal.SIGUSR2:
                _LOGGER.info("Status: \r\n%s", {self.evo.id: self.evo.status})

        _LOGGER.debug("Creating signal handlers...")
        signals = [signal.SIGINT, signal.SIGTERM]

        if os.name == "nt":  # TODO: or is sys.platform better?
            for sig in signals + [signal.SIGBREAK]:
                signal.signal(sig, _sig_handler_win32)

        else:  # if os.name == "posix":
            for sig in signals + [signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2]:
                self._loop.add_signal_handler(
                    sig, lambda sig=sig: asyncio.create_task(_sig_handler_posix(sig))
                )

    def cleanup(self, xxx=None) -> None:
        """Perform the non-async portion of a graceful shutdown."""

        _LOGGER.debug("cleanup() invoked by: %s", xxx)

        if self.config["known_devices"]:
            _LOGGER.debug("cleanup(): Updating known_devices file...")
            for d in self.devices:
                device_attrs = {
                    "friendly_name": d._friendly_name,
                    "ignore": d._ignored,
                }
                if d.id in self.known_devices:
                    self.known_devices[d.id].update(device_attrs)
                else:
                    self.known_devices[d.id] = device_attrs

            with open(self.config["known_devices"], "w") as json_file:
                json.dump(self.known_devices, json_file, sort_keys=True, indent=4)

    async def start(self) -> None:
        async def file_reader(fp):
            async for raw_pkt in file_pkts(
                fp, include=self._include_list, exclude=self._exclude_list
            ):
                self._process_packet(raw_pkt)
                # await asyncio.sleep(0)  # needed for Ctrl_C to work

        async def port_reader(manager):
            async for raw_pkt in port_pkts(
                manager,
                include=self._include_list,
                exclude=self._exclude_list,
                relay=self._relay,
            ):
                self._process_packet(raw_pkt)
                # await asyncio.sleep(0)  # NOTE: 0.005 works well

                # TODO: not elegant - move elsewhere?
                if self.config.get("evofw_flag") and "evofw3" in raw_pkt.packet:
                    # !V, !T - print the version, or the current mask
                    # !T00   - turn off all mask bits
                    # !T01   - cause raw data for all messages to be printed
                    await manager.put_pkt(self.config["evofw_flag"], _LOGGER)

                await asyncio.sleep(0.01)  # TODO: was: 0.005

        async def port_writer(manager):
            while True:
                await self._dispatch_pkt(destination=manager)
                await asyncio.sleep(0.01)  # NOTE: was: 0.05

        # if self.config["known_devices"]:
        #     self.known_devices = ...
        #     self._include_list = [
        #     self._exclude_list = [

        # Finally, source of packets is either a serial port, or a text stream
        if self.serial_port:  # , reader = port_reader(manager)
            if self.config.get("ser2net_server"):
                self._relay = Ser2NetServer(
                    self.config["ser2net_server"], self.cmd_que, loop=self._loop
                )
                self._tasks.append(asyncio.create_task(self._relay.start()))

            async with PortPktProvider(self.serial_port, loop=self._loop) as manager:
                if self._execute_cmd:  # e.g. "RQ 01:145038 1F09 00"
                    cmd = self._execute_cmd
                    cmd = Command(cmd[:2], cmd[3:12], cmd[13:17], cmd[18:])
                    await manager.put_pkt(cmd, _LOGGER)

                # RQ --- 18:013393 01:145038 --:------ 0404 007 09 20 0008 000100
                #                                               00 05 02C8

                # for device_type in ("0D", "0E", "0F"):  # CODE_000C_DEVICE_TYPE:
                #     cmd = Command("RQ", "01:145038", "000C", f"00{device_type}")
                #     await manager.put_pkt(cmd, _LOGGER)

                # for z in range(4):
                #     for x in range(12):
                #         cmd = Command("RQ", "01:145038", "000C", f"{z:02X}{x:02X}")
                #         await manager.put_pkt(cmd, _LOGGER)

                # for p in ("00", "01", "FF", "0000", "0100", "FF00"):
                #     for c in ("0003", "0007", "000B", "000D", "000F"):
                #         cmd = Command("RQ", "01:145038", c, f"0008{p}")
                #         print(cmd)
                #         await manager.put_pkt(cmd, _LOGGER)

                reader = asyncio.create_task(port_reader(manager))
                self._tasks.extend([asyncio.create_task(port_writer(manager)), reader])

        else:  # if self.config["input_file"]:
            reader = asyncio.create_task(file_reader(self.config["input_file"]))
            self._tasks.extend([asyncio.create_task(port_writer(None)), reader])

        await reader  # was: await asyncio.gather(*self._tasks)
        # await asyncio.gather(*self._tasks)
        self.cleanup("start()")

    async def _dispatch_pkt(self, destination=None) -> None:
        """Send a command unless in listen_only mode."""

        # # used for development only...
        # for code in range(0x4000):
        #     # cmd = Command("RQ", "01:145038", f"{code:04X}", "0000")
        #     cmd = Command("RQ", "13:035462", f"{code:04X}", "0000")
        #     await destination.put_pkt(cmd, _LOGGER)
        #     if code % 0x10 == 0:
        #         await asyncio.sleep(15)  # 10 too short - 15 seconds works OK

        # # used for development only...
        # for payload in ("0000", "0100", "F8", "F9", "FA", "FB", "FC", "FF"):
        #     cmd = Command("RQ", "01:145038", "11F0", payload)
        #     await destination.put_pkt(cmd, _LOGGER)
        #     cmd = Command("RQ", "13:035462", "11F0", payload)
        #     await destination.put_pkt(cmd, _LOGGER)

        while not self.cmd_que.empty():
            await asyncio.sleep(0.01)  # TODO: this was causing an issue...
            # if self.cmd_que.empty():
            #     await destination.put_pkt(None, _LOGGER)
            #     continue

            cmd = self.cmd_que.get()

            if destination is not None and str(cmd).startswith("!"):
                await destination.put_pkt(cmd, _LOGGER)

            elif destination is None or self.config["disable_sending"]:
                pass  # clear the whole queue

            else:
                await destination.put_pkt(cmd, _LOGGER)

            self.cmd_que.task_done()

    def _process_packet(self, pkt: Packet) -> None:
        """Decode the packet and its payload."""

        try:
            if self.config["reduce_processing"] >= DONT_CREATE_MESSAGES:
                return

            msg = Message(self, pkt)  # trap/logs all invalids msgs appropriately

            # 18:/RQs are unreliable, the corresponding RPs, if any, are required
            if msg.src.type == "18":
                return

            if self.config["reduce_processing"] >= DONT_CREATE_ENTITIES:
                return

            msg.create_devices()  # from pkt header & from msg payload (e.g. 000C)

            msg.create_zones()  # create zones & ufh_zones (TBD)

            if self.config["reduce_processing"] >= DONT_UPDATE_ENTITIES:
                return

            msg.update_entities(self._prev_msg)  # update the state database

        except (AssertionError, NotImplementedError):
            return

        self._prev_msg = msg if msg.is_valid else None

    # def get_ctl(self, ctl_addr) -> Device:
    #     return self.get_device(ctl_addr, controller=ctl_addr, domain_id="FF")

    def get_device(self, dev_addr, controller=None, domain_id=None) -> Device:
        """Return a device (will create it if required).

        Can also set a controller/system (will create as required). If a controller is
        provided, can also set the domain_id as one of: zone_idx, FF (controllers), FC
        (heater_relay), HW (DHW sensor, relay), or None (unknown, TBA).
        """

        ctl = (
            None if controller is None else self.get_device(controller, domain_id="FF")
        )
        if self.evo is None:
            self.evo = ctl

        if dev_addr.type in ("18", "63", "--"):  # valid addresses, but not devices
            return

        if isinstance(dev_addr, Device):
            device = dev_addr
        else:
            device = self.device_by_id.get(dev_addr.id)

        if device is None:
            if dev_addr.type in ("01", "23") or domain_id == "FF":
                device = EvoSystem(self, dev_addr, domain_id=domain_id)
            else:
                device = DEVICE_CLASSES.get(dev_addr.type, Device)(
                    self, dev_addr, controller=ctl, domain_id=domain_id
                )
        else:  # update the existing device with any metadata
            if ctl is not None:
                device.controller = ctl

            if domain_id in ("FC", "FF"):
                device._domain_id = domain_id
            elif domain_id is not None and ctl is not None:
                device.zone = ctl.get_zone(domain_id)

        return device

    @property
    def schema(self) -> dict:
        """Return the global schema."""

        schema = {"main_controller": self.evo.id if self.evo else None}

        if self.evo:
            schema[self.evo.id] = self.evo.schema
        for evo in self.systems:
            schema[evo.id] = evo.schema

        orphans = [d.id for d in self.devices if d.controller is None]
        orphans.sort()
        schema[ATTR_ORPHANS] = orphans

        return schema

    @property
    def params(self) -> dict:
        result = {}

        result["devices"] = {
            d.id: d.params for d in sorted(self.devices, key=lambda x: x.id)
        }

        return result

    @property
    def status(self) -> dict:
        result = {}

        result["devices"] = {
            d.id: d.status for d in sorted(self.devices, key=lambda x: x.id)
        }

        return result
