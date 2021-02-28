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
from threading import Lock
from typing import Callable, Dict, List, Optional, Tuple

from .command import Command
from .const import _dev_mode_, ATTR_DEVICES, ATTR_ORPHANS
from .devices import DEVICE_CLASSES, Device
from .message import Message, process_msg
from .packet import _PKT_LOGGER as pkt_logger, set_pkt_logging
from .protocol import create_msg_stack
from .transport import POLLER_TASK, create_pkt_stack
from .schema import (
    load_config,
    load_schema,
    DISABLE_DISCOVERY,
    DONT_CREATE_MESSAGES,
    LOG_ROTATE_BYTES,
    LOG_ROTATE_COUNT,
    PACKET_LOG,
    REDUCE_PROCESSING,
    USE_NAMES,
)
from .systems import SYSTEM_CLASSES, System, SystemBase
from .version import __version__  # noqa: F401

DEV_MODE = _dev_mode_
VERSION = __version__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class GracefulExit(SystemExit):
    code = 1


class Gateway:
    """The gateway class."""

    def __init__(self, serial_port, input_file=None, loop=None, **kwargs) -> None:
        """Initialise the class."""

        if kwargs.pop("debug_mode", None):
            _LOGGER.setLevel(logging.DEBUG)  # should be INFO?
        _LOGGER.debug("Starting evohome_rf, **kwargs = %s", kwargs)

        self._loop = loop if loop else asyncio.get_running_loop()
        self._tasks = []

        self.serial_port = serial_port
        self._input_file = input_file

        (self.config, self._include, self._exclude) = load_config(
            serial_port, input_file, **kwargs
        )

        set_pkt_logging(
            pkt_logger,
            file_name=self.config.get(PACKET_LOG),
            cc_stdout=self.config[REDUCE_PROCESSING] >= DONT_CREATE_MESSAGES,
            backup_count=self.config[LOG_ROTATE_COUNT],
            max_bytes=self.config[LOG_ROTATE_BYTES],
        )

        self.pkt_protocol, self.pkt_transport = None, None
        self.msg_protocol, self.msg_transport = None, None

        # if self.config[REDUCE_PROCESSING] >= DONT_CREATE_MESSAGES:
        #     return

        if self.config[REDUCE_PROCESSING] < DONT_CREATE_MESSAGES:
            self.msg_protocol, self.msg_transport = self.create_client(process_msg)

        self._buffer = deque()
        self._sched_zone = None
        self._sched_lock = Lock()

        # if config.get("ser2net_server"):
        self._relay = None  # ser2net_server relay

        # if self.config[REDUCE_PROCESSING] > 0:
        self.evo = None  # Evohome(controller=config["controller_id"])
        self.systems: List[SystemBase] = []
        self.system_by_id: Dict = {}
        self.devices: List[Device] = []
        self.device_by_id: Dict = {}

        self._prev_msg = None

        self._schema, self.known_devices = load_schema(self, **kwargs)
        if not self.known_devices:
            self.config[USE_NAMES] = False

        self._setup_event_handlers()

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

        async def handle_sig_posix(sig):
            """Handle signals on posix platform."""
            _LOGGER.debug("Received a signal (%s), processing...", sig.name)

            if sig == signal.SIGUSR1:
                _LOGGER.info("Schema: \r\n%s", {self.evo.id: self.evo.schema})
                _LOGGER.info("Params: \r\n%s", {self.evo.id: self.evo.params})
                _LOGGER.info("Status: \r\n%s", {self.evo.id: self.evo.status})

            elif sig == signal.SIGUSR2:
                _LOGGER.info("Status: \r\n%s", {self.evo.id: self.evo.status})

        _LOGGER.debug("_setup_event_handlers(): Creating exception handler...")
        self._loop.set_exception_handler(handle_exception)

        _LOGGER.debug("_setup_event_handlers(): Creating signal handlers...")
        if os.name == "posix":  # full support
            for sig in [signal.SIGUSR1, signal.SIGUSR2]:
                self._loop.add_signal_handler(
                    sig, lambda sig=sig: self._loop.create_task(handle_sig_posix(sig))
                )
        elif os.name == "nt":  # supported, but YMMV
            _LOGGER.warning("Be aware, YMMV with Windows...")
        else:  # unsupported
            raise RuntimeError("Unsupported OS for this module: %s", os.name)

    async def start(self) -> None:
        if self.serial_port:  # source of packets is a serial port
            self.pkt_protocol, self.pkt_transport = create_pkt_stack(
                self,
                self.msg_transport._pkt_receiver if self.msg_transport else None,
                serial_port=self.serial_port,
            )
            if self.msg_transport:
                self._tasks.append(
                    self.msg_transport._set_dispatcher(self.pkt_protocol.send_data)
                )

            while not self._tasks:
                await asyncio.sleep(60)

        else:  # if self._input_file:
            self.pkt_protocol, self.pkt_transport = create_pkt_stack(
                self,
                self.msg_transport._pkt_receiver if self.msg_transport else None,
                packet_log=self._input_file,
            )

        if self.pkt_transport.get_extra_info(POLLER_TASK):
            self._tasks.append(self.pkt_transport.get_extra_info(POLLER_TASK))

        await asyncio.gather(*self._tasks)

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

            if not self.config[DISABLE_DISCOVERY]:
                system._discover()  # discover_flag=DISCOVER_ALL)

            return system

        def create_device(dev_addr, **kwargs) -> Device:
            if dev_addr.id in self.device_by_id:
                raise LookupError(f"Duplicated device id: {dev_addr.id}")

            device = DEVICE_CLASSES.get(dev_addr.type, Device)(self, dev_addr, **kwargs)

            if not self.config[DISABLE_DISCOVERY]:
                device._discover()  # discover_flag=DISCOVER_ALL)

            return device

        ctl = None if ctl_addr is None else self._get_device(ctl_addr, domain_id="FF")
        if ctl is not None and self.evo is None:
            self.evo = ctl._evo

        if dev_addr.type in ("18", "63", "--"):  # valid addresses, but not devices
            return
        if dev_addr.id == "01:000001":  # valid addresses, but not devices
            return

        if isinstance(dev_addr, Device):
            device = dev_addr
        else:
            device = self.device_by_id.get(dev_addr.id)

        if device is None:
            device = create_device(dev_addr, ctl=ctl, domain_id=domain_id)
            # if isinstance(device, Controller):
            # if device._is_controller:
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

        orphans = [d.id for d in self.devices]

        # orphans = [d.id for d in self.devices if d.controller is None]
        # orphans.sort()
        schema[ATTR_ORPHANS] = orphans

        return schema

    @property
    def params(self) -> dict:
        return {
            ATTR_DEVICES: {d.id: d.params for d in sorted(self.devices)},
        }

    @property
    def status(self) -> dict:
        return {
            ATTR_DEVICES: {d.id: d.status for d in sorted(self.devices)},
        }

    def create_client(self, msg_handler) -> Tuple[Callable, Callable]:
        """Create a client protocol for the RAMSES-II message transport."""
        return create_msg_stack(self, msg_handler)

    def send_cmd(
        self, cmd: Command, callback: Callable = None, **kwargs
    ) -> asyncio.Task:
        """Send a command with the option to return any response via callback.

        Response packets, if any, follow an RQ/W (as an RP/I), and have the same code.
        """
        if not self.msg_protocol:
            raise RuntimeError("there is no message protocol")
        return self._loop.create_task(
            self.msg_protocol.send_data(cmd, callback=callback, **kwargs)
        )

    async def async_send_cmd(
        self, cmd: Command, awaitable: bool = True, **kwargs
    ) -> Optional[Message]:
        """Send a command with the option to return any response.

        Response packets, if any, follow an RQ/W (as an RP/I), and have the same code.
        """
        if not self.msg_protocol:
            raise RuntimeError("there is no message protocol")
        return await self.msg_protocol.send_data(cmd, awaitable=awaitable, **kwargs)
