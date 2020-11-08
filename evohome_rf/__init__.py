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
import json
import logging
import os
import signal
import sys
from threading import Lock
from typing import Any, Dict, List  # Any, Tuple

from .const import __dev_mode__, ATTR_ORPHANS
from .devices import DEVICE_CLASSES, Device
from .discovery import spawn_scripts
from .logger import set_logging, BANDW_SUFFIX, COLOR_SUFFIX, CONSOLE_FMT, PKT_LOG_FMT
from .message import DONT_CREATE_MESSAGES, _LOGGER as msg_logger, process_msg
from .packet import _LOGGER as pkt_logger, file_pkts
from .schema import CONFIG_SCHEMA, KNOWNS_SCHEMA, load_schema

# from .ser2net import Ser2NetServer
from .systems import SYSTEM_CLASSES, System, SystemBase
from .transport import (
    WRITER_TASK,
    ClientProtocol,
    Ramses2Protocol,
    create_msg_stack,
    create_pkt_stack,
)
from .version import __version__  # noqa

_LOGGER = logging.getLogger(__name__)
if False and __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


class GracefulExit(SystemExit):
    code = 1


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
        self.msg_protocol, self.msg_transport = None, None
        self.pkt_protocol, self.pkt_transport = None, None
        self.msg_protocol, self.msg_transport = create_msg_stack(
            self, process_msg, Ramses2Protocol
        )

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
        # set_logging(msg_logger, stream=None, file_name=None)
        set_logging(
            pkt_logger,
            stream=_stream[1],
            file_name=self.config.get("packet_log"),
            file_fmt=PKT_LOG_FMT + BANDW_SUFFIX,
            cons_fmt=CONSOLE_FMT + COLOR_SUFFIX,
        )

        self._buffer = deque()
        self._sched_zone = None
        self._sched_lock = Lock()

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
            _LOGGER.error("handle_exception(): Caught: %s", context["message"])

            exc = context.get("exception")
            if exc:
                raise exc
            # asyncio.create_task(self.shutdown())  # TODO: doesn't work here?

        async def handle_sig_posix(sig):
            """Handle signals on posix platform."""
            _LOGGER.debug("handle_sig_posix(): Received %s, processing...", sig.name)

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

        _LOGGER.debug("_setup_event_handlers(): Creating exception handler...")
        self._loop.set_exception_handler(handle_exception)

        _LOGGER.debug("_setup_event_handlers(): Creating signal handlers...")
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
        """Perform a graceful shutdown."""

        _LOGGER.debug("shutdown(): Invoked by: %s, doing housekeeping...", xxx)
        # print(asyncio.current_task())
        tasks = [t for t in self._tasks if t is not asyncio.current_task()]

        logging.debug(f"shutdown(): Cancelling {len(tasks)} outstanding async tasks...")
        # [print(t) for t in tasks]
        # [print(t) for t in asyncio.all_tasks()]
        [task.cancel() for task in tasks]
        # await asyncio.gather(*tasks, return_exceptions=False)

        _LOGGER.debug("shutdown(): Complete.")

    async def start(self) -> None:
        async def file_reader(fp, callback):
            async for pkt in file_pkts(fp):
                # callback(Message(self, pkt))  # TODO: check include, exclude lists
                self.msg_transport._pkt_receiver(pkt)  # HACK: a hack

        if self.serial_port:  # source of packets is a serial port
            self.pkt_protocol, self.pkt_transport = create_pkt_stack(
                self, self.msg_transport, self.serial_port
            )
            self._tasks = [self.msg_transport.get_extra_info(WRITER_TASK)]
            self._tasks += await spawn_scripts(self)  # queue any discovery scripts

        else:  # if self.config["input_file"]:
            reader = asyncio.create_task(
                file_reader(self.config["input_file"], process_msg)
            )
            self._tasks = [reader]

        await asyncio.gather(*self._tasks)
        await self.shutdown("start()")

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

    def create_client(self, msg_handler, protocol_factory=ClientProtocol) -> Any:
        """Create a client protocol for the RAMSES-II message transport."""
        return create_msg_stack(self, msg_handler, protocol_factory=protocol_factory)
