#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser.

Works with (amongst others):
- evohome (up to 12 zones)
- sundial (up to 2 zones)
- chronotherm (CM60xNG can do 4 zones)
- hometronics (16? zones)
"""

import asyncio
from collections import deque
from datetime import datetime as dt
import json
import logging
import os
from queue import PriorityQueue, Empty
import signal
import sys
from threading import Lock
from typing import Any, Dict, List, Tuple

from serial import serial_for_url  # SerialException
from serial_asyncio import SerialTransport

from .command import Command
from .const import __dev_mode__, ATTR_ORPHANS
from .devices import DEVICE_CLASSES, Device
from .discovery import probe_device, poll_device, spawn_scripts
from .exceptions import GracefulExit
from .logger import set_logging, BANDW_SUFFIX, COLOR_SUFFIX, CONSOLE_FMT, PKT_LOG_FMT
from .message import _LOGGER as msg_logger, Message
from .packet import (
    _LOGGER as pkt_logger,
    Packet,
    file_pkts,
    GatewayProtocol,
    SERIAL_CONFIG,
)
from .schema import CONFIG_SCHEMA, KNOWNS_SCHEMA, load_schema

# from .ser2net import Ser2NetServer
from .systems import SYSTEM_CLASSES, System, SystemBase
from .version import __version__  # noqa

# TODO: duplicated in schema.py
DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


class Gateway:
    """The gateway class."""

    def __init__(self, serial_port, loop=None, **config) -> None:
        """Initialise the class."""

        if config.get("debug_mode"):
            _LOGGER.setLevel(logging.DEBUG)  # should be INFO?
            _LOGGER.warning("Starting evohome_rf, **config = %s", config)
        else:
            _LOGGER.debug("Starting evohome_rf, **config = %s", config)

        self._loop = loop if loop else asyncio.get_running_loop()
        self._tasks = None
        self._setup_event_handlers()

        self.serial_port = serial_port
        self._protocol = None

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

        self._que = PriorityQueue()  # TODO: maxsize=200)
        self._buffer = deque()
        self._sched_zone = None
        self._sched_lock = Lock()
        self._callbacks = {}

        self._prev_msg = None

        # if config.get("ser2net_server"):
        self._relay = None  # ser2net_server relay

        # if self.config["reduce_processing"] > 0:
        self.evo = None  # Evohome(controller=config["controller_id"])
        self.systems: List[SystemBase] = []
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
            self._que.put_nowait(
                Command(cmd[:2], cmd[3:12], cmd[13:17], cmd[18:], retries=12)
            )

        if self.config.get("poll_devices"):
            [poll_device(self, d) for d in self.config["poll_devices"]]

        if self.config.get("probe_devices"):
            [probe_device(self, d) for d in self.config["probe_devices"]]

        if self.config.get("device_id"):
            _LOGGER.warning("Discovery scripts specified, so disabling probes")
            self.config["disable_discovery"] = True  # TODO: messey

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        return json.dumps(self.schema)

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""
        return json.dumps(self.schema, indent=2)

    def _setup_event_handlers(self):
        def handle_exception(loop, context):
            """Handle exceptions on any platform."""
            # asyncio.create_task(self.shutdown())  # TODO: doesn't work

            exc = context.get("exception")
            if exc:
                raise exc

            _LOGGER.error("Caught exception: %s", context["message"])

        async def handle_sig_posix(sig):
            """Handle signals on posix platform."""
            _LOGGER.info("Received a signal (%s), processing...", sig.name)

            if sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                await self.shutdown("handle_sig_posix()")  # OK for after tasks.cancel

            elif sig == signal.SIGUSR1:
                _LOGGER.info("Params: \r\n%s", {self.evo.id: self.evo.params})

            elif sig == signal.SIGUSR2:
                _LOGGER.info("Status: \r\n%s", {self.evo.id: self.evo.status})

        def handle_sig_win32(sig, frame):
            """Handle signals on win32 platform."""
            _LOGGER.info("Received a signal (signal=%s), processing...", sig.name)

            if sig == signal.SIGINT:  # Ctrl-C (is this the only useful win32 signal?)
                # await self.shutdown("handle_sig_win32()")

                raise GracefulExit()

        _LOGGER.debug("Creating exception handler...")
        self._loop.set_exception_handler(handle_exception)

        _LOGGER.debug("Creating signal handlers...")
        signals = [signal.SIGINT, signal.SIGTERM]

        if os.name == "posix":  # full support
            for sig in signals + [signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2]:
                self._loop.add_signal_handler(
                    sig, lambda sig=sig: asyncio.create_task(handle_sig_posix(sig))
                )
        elif os.name == "nt":  # limited support
            _LOGGER.warning("There is only limited support for Windows.")
            for sig in signals + [signal.SIGBREAK]:
                signal.signal(sig, handle_sig_win32)
        else:  # unsupported
            raise RuntimeError("Unsupported OS for this module: %s", os.name)

    async def shutdown(self, xxx=None) -> None:
        """Perform the non-async portion of a graceful shutdown."""

        _LOGGER.debug("shutdown(): Invoked by: %s...", xxx)
        _LOGGER.debug("shutdown(): Doing housekeeping...")

        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        [task.cancel() for task in tasks]
        logging.debug(f"shutdown(): Cancelling {len(tasks)} outstanding async tasks...")

        await asyncio.gather(*tasks, return_exceptions=True)  # raises CancelledError

    async def start(self) -> None:
        def create_gateway_interface(serial_port, callback) -> Tuple[Any, Any]:
            ser = serial_for_url(serial_port, **SERIAL_CONFIG)
            protocol = GatewayProtocol(self, callback)
            transport = SerialTransport(self._loop, protocol, ser)
            return (transport, protocol)

        async def file_reader(fp, callback):
            async for raw_pkt in file_pkts(fp):
                # include=self._include_list, exclude=self._exclude_list
                callback(raw_pkt)
                await asyncio.sleep(0)  # needed for Ctrl_C to work?

        async def port_writer(protocol):
            while True:
                if self._que.empty():
                    await asyncio.sleep(0.05)
                    continue

                try:
                    cmd = self._que.get(False)
                except Empty:
                    continue

                if protocol:  # or not self.config["disable_sending"]
                    await protocol.send_data(cmd)  # put_pkt(cmd, _LOGGER)

                self._que.task_done()

        if self.serial_port:  # source of packets is a serial port
            self._tasks = spawn_scripts(self)  # first, queue any discovery scripts

            _, self._protocol = create_gateway_interface(
                self.serial_port, self._process_packet
            )
            writer = asyncio.create_task(port_writer(self._protocol))

            self._tasks.append(writer)
            await writer

        else:  # if self.config["input_file"]:
            reader = asyncio.create_task(
                file_reader(self.config["input_file"], self._process_packet)
            )
            writer = asyncio.create_task(port_writer(None))  # to consume cmds

            self._tasks = [reader, writer]
            await reader
            writer.cancel()

        await self.shutdown("start()")  # await asyncio.gather(*self._tasks)

    def _process_packet(self, pkt: Packet) -> None:
        """Decode the packet and its payload."""

        def proc_callback(msg: Message) -> None:
            # TODO: this needs to be a queue
            dtm = dt.now()
            [
                v["func"](False, *v["args"], **v["kwargs"])
                for v in self._callbacks.values()
                if not v.get("daemon") and v.get("timeout", dt.max) <= dtm
            ]  # first, alert expired callbacks

            self._callbacks = {
                k: v
                for k, v in self._callbacks.items()
                if v.get("daemon") or v.get("timeout", dt.max) > dtm
            }  # then, discard expired callbacks

            if msg._pkt._header in self._callbacks:
                callback = self._callbacks[msg._pkt._header]
                callback["func"](msg, *callback["args"], **callback["kwargs"])
                if not callback.get("daemon"):
                    del self._callbacks[msg._pkt._header]

        if not pkt.is_wanted(include=self._include_list, exclude=self._exclude_list):
            return

        try:
            if self.config["reduce_processing"] >= DONT_CREATE_MESSAGES:
                return

            msg = Message(self, pkt)  # trap/logs all invalids msgs appropriately
            if msg._pkt._header in self._callbacks:
                proc_callback(msg)

            # 18:/RQs are unreliable, although any corresponding RPs are required
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

    def _get_device(self, dev_addr, ctl_addr=None, domain_id=None) -> Device:
        """Return a device (will create it if required).

        Can also set a controller/system (will create as required). If a controller is
        provided, can also set the domain_id as one of: zone_idx, FF (controllers), FC
        (heater_relay), HW (DHW sensor, relay), or None (unknown, TBA).
        """

        def create_system(ctl) -> SystemBase:
            assert ctl.id not in self.system_by_id, f"Duplicate system id: {ctl.id}"
            if ctl.id in self.system_by_id:
                raise LookupError(f"Duplicated system id: {ctl.id}")

            system = SYSTEM_CLASSES.get(ctl.type, System)(self, ctl)

            if not self.config["disable_discovery"]:
                system._discover()  # discover_flag=DISCOVER_ALL)

            return system

        def create_device(dev_addr, **kwargs) -> Device:
            if dev_addr.id in self.device_by_id:
                raise LookupError(f"Duplicated device id: {dev_addr.id}")

            device = DEVICE_CLASSES.get(dev_addr.type, Device)(self, dev_addr, **kwargs)

            if not self.config["disable_discovery"]:
                device._discover()  # discover_flag=DISCOVER_ALL)

            return device

        ctl = None if ctl_addr is None else self._get_device(ctl_addr, domain_id="FF")
        if ctl is not None and self.evo is None:
            self.evo = ctl._evo

        if dev_addr.type in ("18", "63", "--"):  # valid addresses, but not devices
            return

        if isinstance(dev_addr, Device):
            device = dev_addr
        else:
            device = self.device_by_id.get(dev_addr.id)

        if device is None:
            device = create_device(dev_addr, ctl=ctl, domain_id=domain_id)
            # if isinstance(device, Controller):
            # if device.is_controller:
            # if dev_addr.type in SYSTEM_CLASSES:
            if dev_addr.type in ("01", "23"):
                device._evo = create_system(device)

        else:  # update the existing device with any metadata
            if ctl is not None:
                device._set_ctl(ctl)

            if domain_id in ("F9", "FA", "FC", "FF"):
                device._domain_id = domain_id
            elif domain_id is not None and ctl is not None:
                device._set_zone(ctl._evo._get_zone(domain_id))

        return device

    @property
    def schema(self) -> dict:
        """Return the global schema."""

        schema = {"main_controller": self.evo._ctl.id if self.evo else None}

        if self.evo:
            schema[self.evo._ctl.id] = self.evo.schema
        for evo in self.systems:
            if evo is not self.evo:
                schema[evo._ctl.id] = evo.schema

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
