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
import json
import logging
import os
import signal
from collections import deque
from threading import Lock
from typing import Callable, Dict, List, Optional, Tuple

from .command import Command
from .const import ATTR_DEVICES, ATTR_ORPHANS, NUL_DEVICE_ID, __dev_mode__
from .devices import DEVICE_CLASSES, Device
from .message import Message, process_msg
from .packet import _PKT_LOGGER, set_pkt_logging
from .protocol import create_msg_stack
from .schema import (
    DEBUG_MODE,
    DISABLE_DISCOVERY,
    DISABLE_SENDING,
    DONT_CREATE_MESSAGES,
    GLOBAL_CONFIG_SCHEMA,
    INPUT_FILE,
    PACKET_LOG,
    REDUCE_PROCESSING,
    USE_NAMES,
    load_config_schema,
    load_system_schema,
)
from .systems import SYSTEM_CLASSES, System, SystemBase
from .transport import POLLER_TASK, create_pkt_stack
from .version import __version__  # noqa: F401

DEV_MODE = __dev_mode__ and False
VERSION = __version__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class GracefulExit(SystemExit):
    code = 1


class Gateway:
    """The gateway class."""

    def __init__(self, serial_port, loop=None, **kwargs) -> None:
        """Initialise the class."""

        if kwargs.pop(DEBUG_MODE, None):
            _LOGGER.setLevel(logging.DEBUG)  # should be INFO?
        _LOGGER.debug("Starting evohome_rf, **kwargs = %s", kwargs)

        self._loop = loop or asyncio.get_running_loop()
        self._tasks = []

        self.serial_port = serial_port
        self._input_file = kwargs.pop(INPUT_FILE, None)

        (self.config, self._include, self._exclude) = load_config_schema(
            serial_port, self._input_file, **GLOBAL_CONFIG_SCHEMA(kwargs)
        )

        set_pkt_logging(
            _PKT_LOGGER,
            cc_stdout=self.config[REDUCE_PROCESSING] >= DONT_CREATE_MESSAGES,
            **self.config[PACKET_LOG],  # TODO: ZZZ
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

        schema = {k: v for k, v in kwargs.items() if k not in self.config}
        self.known_devices = load_system_schema(self, **schema)
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

        if DEV_MODE:
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
                ser_port=self.serial_port,
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

    def _get_device(self, dev_addr, ctl_addr=None, domain_id=None, **kwargs) -> Device:
        """Return a device (will create it if required).

        Can also set a controller/system (will create as required). If a controller is
        provided, can also set the domain_id as one of: zone_idx, FF (controllers), FC
        (heater_relay), HW (DHW sensor, relay), or None (unknown, TBA).
        """

        def create_system(ctl, profile=None) -> SystemBase:
            # assert ctl.id not in self.system_by_id, f"Dup. sys_id: {ctl.id}"

            if profile is None:
                profile = "programmer" if dev_addr.type == "23" else "evohome"

            system = SYSTEM_CLASSES.get(profile, System)(self, ctl)
            if self.evo is None:
                self.evo = system

            if not self.config[DISABLE_DISCOVERY]:
                system._discover()  # discover_flag=DISCOVER_ALL)
            return system

        def create_device(dev_addr) -> Device:
            # assert dev_addr.id not in self.device_by_id, f"Dup. dev_id: {dev_addr.id}"

            device = DEVICE_CLASSES.get(dev_addr.type, Device)(self, dev_addr)

            # if isinstance(device, Controller):
            # if device._is_controller:
            # if dev_addr.type in SYSTEM_CLASSES:
            # if domain_id == "FF"
            if dev_addr.type in ("01", "23"):
                device._evo = create_system(device, profile=kwargs.get("profile"))

            if not self.config[DISABLE_DISCOVERY]:
                device._discover()  # discover_flag=DISCOVER_ALL)
            return device

        if ctl_addr is not None:
            ctl = self.device_by_id.get(ctl_addr.id)
            if ctl is None:
                ctl = self._get_device(ctl_addr, domain_id="FF", **kwargs)

        if dev_addr.type in ("18", "--") or dev_addr.id in (NUL_DEVICE_ID, "01:000001"):
            return  # not valid device types/real devices

        dev = self.device_by_id.get(dev_addr.id)
        if dev is None:  # TODO: take into account device filter?
            dev = create_device(dev_addr)

        # update the existing device with any metadata
        if ctl_addr is not None:
            dev._set_ctl(ctl)
        if domain_id in ("F9", "FA", "FC", "FF"):
            dev._domain_id = domain_id
        elif domain_id is not None and ctl_addr is not None:
            dev._set_zone(ctl._evo._get_zone(domain_id))

        return dev

    def _clear_state(self) -> None:
        gwy = self
        gwy._prev_msg = None

        gwy.evo = None
        gwy.systems = []
        gwy.system_by_id = {}
        gwy.device_by_id = {}
        gwy.devices = []

    def _pause_engine(self) -> Tuple[Callable, bool, bool]:
        callback = None

        if self.pkt_protocol:
            self.pkt_protocol.pause_writing()
            self.pkt_protocol._callback, callback = None, self.pkt_protocol._callback

        self.config[DISABLE_DISCOVERY], discovery = True, self.config[DISABLE_DISCOVERY]
        self.config[DISABLE_SENDING], sending = True, self.config[DISABLE_SENDING]

        return (callback, discovery, sending)

    def _resume_engine(
        self, callback: Callable, discovery: bool, sending: bool
    ) -> None:
        if self.pkt_protocol:
            self.pkt_protocol._callback = callback  # self.msg_transport._pkt_receiver
            self.pkt_protocol.resume_writing()

        self.config[DISABLE_DISCOVERY] = discovery
        self.config[DISABLE_SENDING] = sending

    def _get_state(self) -> Tuple[Dict, Dict]:
        engine_state = self._pause_engine()

        msgs = {v.dtm: v for d in self.devices for v in d._msgs.values()}
        for system in self.systems:
            msgs.update({v.dtm: v for v in system._msgs.values()})
            msgs.update({v.dtm: v for z in system.zones for v in z._msgs.values()})

        pkts = {
            dtm.isoformat(sep="T", timespec="auto"): repr(msg)
            for dtm, msg in msgs.items()
            if not msg.is_expired
        }

        schema, pkts = self.schema, dict(sorted(pkts.items()))

        self._resume_engine(*engine_state)
        return schema, pkts

    async def _set_state(self, schema: Dict, packets: Dict) -> None:
        engine_state = self._pause_engine()

        self.known_devices = load_system_schema(self, **schema)  # keep old known_devs?

        _, tmp_transport = create_pkt_stack(
            self,
            self.msg_transport._pkt_receiver if self.msg_transport else None,
            packet_dict=packets,
        )
        await tmp_transport.get_extra_info(POLLER_TASK)

        self._resume_engine(*engine_state)

    @property
    def schema(self) -> dict:
        """Return the global schema."""

        schema = {"main_controller": self.evo._ctl.id if self.evo else None}

        if self.evo:
            schema[self.evo._ctl.id] = self.evo.schema
        for evo in self.systems:
            if evo is not self.evo:
                schema[evo._ctl.id] = evo.schema

        orphans = [d.id for d in self.devices if d._ctl is None]

        # orphans = [d.id for d in self.devices if d.controller is None]
        # orphans.sort()
        schema[ATTR_ORPHANS] = orphans

        return schema

    @property
    def params(self) -> dict:
        return {ATTR_DEVICES: {d.id: d.params for d in sorted(self.devices)}}

    @property
    def status(self) -> dict:
        return {ATTR_DEVICES: {d.id: d.status for d in sorted(self.devices)}}

    def create_client(self, msg_handler) -> Tuple[Callable, Callable]:
        """Create a client protocol for the RAMSES-II message transport."""
        return create_msg_stack(self, msg_handler)

    def make_cmd(self, verb, device_id, code, payload, **kwargs) -> Command:
        """Make a command."""
        dest_id = device_id
        return Command(verb, dest_id, code, payload)

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
