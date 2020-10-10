#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome serial."""

import asyncio
from collections import deque
import json
import logging
import os
from queue import PriorityQueue, Empty
import signal
import sys
from threading import Lock
from typing import Dict, List

from serial import serial_for_url
from serial_asyncio import SerialTransport

from .command import Command
from .const import __dev_mode__, ATTR_ORPHANS
from .devices import DEVICE_CLASSES, Device
from .discovery import probe_device, poll_device
from .logger import (
    set_logging,
    BANDW_SUFFIX,
    COLOR_SUFFIX,
    CONSOLE_FMT,
    PKT_LOG_FMT,
)
from .message import _LOGGER as msg_logger, Message
from .packet import (
    _LOGGER as pkt_logger,
    Packet,
    file_pkts,
    SerialProtocol,
    SERIAL_CONFIG,
)
from .schema import CONFIG_SCHEMA, KNOWNS_SCHEMA, load_schema

# from .ser2net import Ser2NetServer
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
        self._loop = loop if loop else asyncio.get_running_loop()
        self.config = CONFIG_SCHEMA(config)

        self._protocol = None

        if self.serial_port and self.config.get("input_file"):
            _LOGGER.warning(
                "Serial port specified (%s), so ignoring input file (%s)",
                self.serial_port,
                self.config["input_file"],
            )
            # self.config["input_file"] = None
        elif self.config.get("input_file") is not None:
            self.config["disable_sending"] = True

        # self._execute_cmd = self.config.get("execute_cmd")

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

        if self.config.get("execute_cmd"):  # e.g. "RQ 01:145038 1F09 00"
            cmd = self.config["execute_cmd"]
            self.cmd_que.put_nowait(
                Command(cmd[:2], cmd[3:12], cmd[13:17], cmd[18:], retry_limit=9)
            )

        if self.config.get("poll_devices"):
            [poll_device(self.cmd_que, d) for d in self.config["poll_devices"]]

        if self.config.get("probe_devices"):
            [probe_device(self.cmd_que, d) for d in self.config["probe_devices"]]

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return json.dumps(self.schema)

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""
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

    @asyncio.coroutine
    def _create_serial_interface(self):
        ser = serial_for_url(self.serial_port, **SERIAL_CONFIG)
        self._protocol = SerialProtocol(self.cmd_que, self._process_packet)
        transport = SerialTransport(self._loop, self._protocol, ser)
        return (transport, self._protocol)

    async def start(self) -> None:
        async def file_reader(fp):
            async for raw_pkt in file_pkts(fp):
                # include=self._include_list, exclude=self._exclude_list
                self._process_packet(raw_pkt)
                await asyncio.sleep(0)  # needed for Ctrl_C to work?

        async def port_writer():
            while True:
                if self.cmd_que.empty():
                    await asyncio.sleep(0.05)
                    continue

                try:
                    cmd = self.cmd_que.get(False)
                except Empty:
                    continue

                if self._protocol:  # or not self.config["disable_sending"]
                    await self._protocol.send_data(cmd)  # put_pkt(cmd, _LOGGER)

                self.cmd_que.task_done()

        # The source of packets is either a serial port, or a text stream
        if self.serial_port:
            reader = asyncio.create_task(self._create_serial_interface())
            writer = asyncio.create_task(port_writer())

            self._tasks.extend([reader, writer])
            await writer

        else:  # if self.config["input_file"]:
            reader = asyncio.create_task(file_reader(self.config["input_file"]))
            writer = asyncio.create_task(port_writer())  # to consume cmds

            self._tasks.extend([reader, writer])
            await reader

        self.cleanup("start()")  # await asyncio.gather(*self._tasks)

    def _process_packet(self, pkt: Packet) -> None:
        """Decode the packet and its payload."""

        if not pkt.is_wanted(include=self._include_list, exclude=self._exclude_list):
            return

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
