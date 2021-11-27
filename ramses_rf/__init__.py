#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

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
from asyncio.futures import Future
from datetime import datetime as dt
from threading import Lock
from typing import Callable, Dict, List, Optional, Tuple

from .const import ATTR_FAKED, ATTR_ORPHANS, DONT_CREATE_MESSAGES, __dev_mode__
from .devices import Device, create_device
from .helpers import schedule_task
from .message import Message, process_msg
from .protocol import (
    _PKT_LOGGER,
    POLLER_TASK,
    Command,
    create_msg_stack,
    create_pkt_stack,
    is_valid_dev_id,
    set_logger_timesource,
    set_pkt_logging,
)
from .protocol.const import ATTR_DEVICES, NON_DEVICE_ID, NUL_DEVICE_ID
from .protocol.exceptions import ExpiredCallbackError
from .schema import (
    BLOCK_LIST,
    DEBUG_MODE,
    INPUT_FILE,
    KNOWN_LIST,
    load_config,
    load_schema,
)
from .systems import System
from .version import VERSION  # noqa: F401

from .protocol import I_, RP, RQ, W_  # noqa: F401, isort: skip

DEV_MODE = __dev_mode__ and False

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
        _LOGGER.debug("Starting RAMSES RF, **kwargs = %s", kwargs)

        self._loop = loop or asyncio.get_running_loop()
        self._tasks = []

        self.serial_port = serial_port
        self._input_file = kwargs.pop(INPUT_FILE, None)

        (self.config, self._schema, self._include, self._exclude) = load_config(
            self.serial_port, self._input_file, **kwargs
        )
        self._unwanted = [NON_DEVICE_ID, NUL_DEVICE_ID, "01:000001"]

        self.pkt_protocol, self.pkt_transport = None, None
        self.msg_protocol, self.msg_transport = None, None

        set_pkt_logging(
            _PKT_LOGGER,
            cc_console=self.config.reduce_processing >= DONT_CREATE_MESSAGES,
            **self.config.packet_log,
        )

        if self.config.reduce_processing < DONT_CREATE_MESSAGES:
            self.msg_protocol, self.msg_transport = self.create_client(process_msg)

        self._engine_lock = Lock()
        self._engine_state = None

        # if self.config.reduce_processing > 0:
        self._prev_msg = None  # see: _clear_state()
        self.evo: System = None
        self.systems: List[System] = []
        self.system_by_id: Dict = {}
        self.devices: List[Device] = []
        self.device_by_id: Dict = {}

        self._setup_event_handlers()

        load_schema(self, **self._schema)

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
        def start_discovery(devices, systems) -> None:
            _LOGGER.debug("ENGINE: Initiating/enabling discovery...")

            # [d._start_discovery() for d in devices]
            for d in devices:
                d._start_discovery()

            for system in systems:
                system._start_discovery()
                [z._start_discovery() for z in system.zones]
                if system._dhw:
                    system._dhw._start_discovery()

        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)("ENGINE: Starting poller...")

        # load_schema(self, **self._schema)

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

            start_discovery(self.devices, self.systems)

            while not self._tasks:
                await asyncio.sleep(60)

        else:  # if self._input_file:
            self.pkt_protocol, self.pkt_transport = create_pkt_stack(
                self,
                self.msg_transport._pkt_receiver if self.msg_transport else None,
                packet_log=self._input_file,
            )
            set_logger_timesource(self.pkt_protocol._dt_now)
            _LOGGER.warning("Datetimes maintained as most recent packet log timestamp")

        if self.pkt_transport.get_extra_info(POLLER_TASK):
            self._tasks.append(self.pkt_transport.get_extra_info(POLLER_TASK))

        await asyncio.gather(*self._tasks)

    def _get_device(self, dev_id, ctl_id=None, domain_id=None, **kwargs) -> Device:
        """Return a device (will create it if required).

        NB: devices are bound to a controller only when the controller says so.
        """

        def check_filter_lists(dev_id) -> None:
            """Raise an error if a device_id is filtered."""
            if dev_id in self._unwanted:
                raise LookupError(f"Unwanted/Invalid device_id: {dev_id}")

            if self.config.enforce_known_list and (
                dev_id not in self._include
                and dev_id != self.pkt_protocol._hgi80["device_id"]
            ):
                _LOGGER.warning(
                    f"Won't create a non-allowed device_id: {dev_id}"
                    f" (if required, add it to the {KNOWN_LIST})"
                )
                self._unwanted.append(dev_id)
                raise LookupError

            if dev_id in self._exclude:
                _LOGGER.warning(
                    f"Won't create a blocked device_id: {dev_id}"
                    f" (if required, remove it from the {BLOCK_LIST})"
                )
                self._unwanted.append(dev_id)
                raise LookupError

        dev = self.device_by_id.get(dev_id)
        if dev is None:
            check_filter_lists(dev_id)
            dev = create_device(self, dev_id, **kwargs)

        # update the existing device with any metadata  # TODO: messy?
        ctl = self.device_by_id.get(ctl_id)
        if ctl:
            dev._set_ctl(ctl)

        if domain_id in ("F9", "FA", "FC", "FF"):
            dev._domain_id = domain_id
        elif domain_id is not None and ctl:
            dev._set_parent(ctl._evo._get_zone(domain_id))

        return dev

    def _pause_engine(self) -> None:
        """Pause the (unpaused) engine or raise a RuntimeError."""

        (_LOGGER.info if DEV_MODE else _LOGGER.debug)("ENGINE: Pausing engine...")

        if not self.serial_port:
            raise RuntimeError("Unable to pause engine, no serial port configured")

        if not self._engine_lock.acquire(blocking=False):
            raise RuntimeError("Unable to pause engine, failed to acquire lock")

        if self._engine_state is not None:
            self._engine_lock.release()
            raise RuntimeError("Unable to pause engine, it is already paused")

        self._engine_state, callback = (None, None, None), None
        self._engine_lock.release()

        if self.pkt_protocol:
            self.pkt_protocol.pause_writing()
            self.pkt_protocol._callback, callback = None, self.pkt_protocol._callback

        # TODO: is disable_discovery = True necessary?
        self.config.disable_discovery, discovery = True, self.config.disable_discovery
        self.config.disable_sending, sending = True, self.config.disable_sending

        self._engine_state = (callback, discovery, sending)

    def _resume_engine(self) -> None:
        """Resume the (paused) engine or raise a RuntimeError."""

        (_LOGGER.info if DEV_MODE else _LOGGER.debug)("ENGINE: Resuming engine...")

        # if not self.serial_port:
        #     raise RuntimeError("Unable to resume engine, no serial port configured")

        if not self._engine_lock.acquire(timeout=0.1):
            raise RuntimeError("Unable to resume engine, failed to acquire lock")

        if self._engine_state is None:
            self._engine_lock.release()
            raise RuntimeError("Unable to resume engine, it was not paused")

        callback, discovery, sending = self._engine_state
        self._engine_lock.release()

        if self.pkt_protocol:
            self.pkt_protocol._callback = callback  # self.msg_transport._pkt_receiver
            self.pkt_protocol.resume_writing()

        # TODO: is disable_discovery = True necessary?
        self.config.disable_discovery = discovery
        self.config.disable_sending = sending

        self._engine_state = None

    def _get_state(self, include_expired=None) -> Tuple[Dict, Dict]:
        #

        (_LOGGER.warning if DEV_MODE else _LOGGER.info)(
            "ENGINE: Saving schema/state..."
        )
        self._pause_engine()

        msgs = {m.dtm: m for device in self.devices for m in device._msg_db}

        for system in self.systems:
            msgs.update({v.dtm: v for v in system._msgs.values()})
            msgs.update({v.dtm: v for z in system.zones for v in z._msgs.values()})
            # msgs.update({v.dtm: v for z in system._dhw for v in z._msgs.values()})

        pkts = {
            f"{repr(msg._pkt)[:26]}": f"{repr(msg._pkt)[27:]}"
            for msg in msgs.values()
            if msg.verb in (I_, RP) and (include_expired or not msg._expired)
        }

        self._resume_engine()
        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)("ENGINE: Saved schema/state.")

        return self.schema, dict(sorted(pkts.items()))

    async def _set_state(self, packets) -> None:
        def clear_state() -> None:
            _LOGGER.warning("ENGINE: Clearing exisiting schema/state...")

            self._prev_msg = None  # TODO: move to pause/resume?
            self.evo = None
            self.systems = []
            self.system_by_id = {}
            self.devices = []
            self.device_by_id = {}

        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)("ENGINE: Restoring state...")
        self._pause_engine()

        # clear_state()  # TODO: consider need for this (here, or at all)

        _, tmp_transport = create_pkt_stack(
            self,
            self.msg_transport._pkt_receiver if self.msg_transport else None,
            packet_dict=packets,
        )
        await tmp_transport.get_extra_info(POLLER_TASK)

        # self.msg_transport._clear_write_buffer()  # TODO: shouldn't be needed

        self._resume_engine()
        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)("ENGINE: Restored state.")

    def _dt_now(self):
        # return dt.now()
        return self.pkt_protocol._dt_now() if self.pkt_protocol else dt.now()

    @property
    def hgi(self) -> Optional[Device]:  # TODO: DEVICE_ID
        if self.pkt_protocol and self.pkt_protocol._hgi80["device_id"]:
            return self.device_by_id.get(self.pkt_protocol._hgi80["device_id"])

    @property
    def _config(self) -> dict:
        """Return the working configuration."""

        return {
            "gateway_id": self.hgi.id if self.hgi else None,
            "schema": self.evo._schema_min if self.evo else None,
            "config": {"enforce_known_list": self.config.enforce_known_list},
            "known_list": [{k: v} for k, v in self._include.items()],
            "block_list": [{k: v} for k, v in self._exclude.items()],
            "other_list": sorted(self.pkt_protocol._unwanted),
            "other_list_alt": sorted(self._unwanted),
        }

    @property
    def schema(self) -> dict:
        """Return the global schema."""

        schema = {"main_controller": self.evo._ctl.id if self.evo else None}

        for evo in self.systems:
            schema[evo._ctl.id] = evo.schema

        schema[ATTR_ORPHANS] = [
            d.id for d in self.devices if d._ctl is None and d._is_present
        ]

        schema["device_hints"] = {}
        for d in sorted(self.devices):
            device_schema = {}
            if d.schema.get(ATTR_FAKED):
                device_schema.update({ATTR_FAKED: d.schema[ATTR_FAKED]})
            if device_schema:
                schema["device_hints"][d.id] = device_schema

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

    def create_cmd(self, verb, device_id, code, payload, **kwargs) -> Command:
        """Make a command addressed to device_id."""
        try:
            return Command(verb, code, payload, device_id)
        except (
            AssertionError,
            AttributeError,
            LookupError,
            TypeError,
            ValueError,
        ) as exc:
            _LOGGER.exception(f"create_cmd(): {exc}")

    def send_cmd(self, cmd: Command, callback: Callable = None, **kwargs) -> Future:
        """Send a command with the option to return any response via callback.

        Response packets, if any, follow an RQ/W (as an RP/I), and have the same code.
        This routine is thread safe.
        """

        if not self.msg_protocol:
            raise RuntimeError("there is no message protocol")
        if self.config.disable_sending:
            raise RuntimeError("sending is disabled")

        return asyncio.run_coroutine_threadsafe(
            self.msg_protocol.send_data(cmd, callback=callback, **kwargs), self._loop
        )

    async def async_send_cmd(
        self, cmd: Command, awaitable: bool = True, **kwargs
    ) -> Optional[Message]:
        """Send a command with the option to not wait for a response (awaitable=False).

        Response packets, if any, follow an RQ/W (as an RP/I), and have the same code.
        This routine is thread safe.
        """
        if awaitable is None:
            awaitable = True

        future = self.send_cmd(cmd, awaitable=awaitable, **kwargs)

        await asyncio.sleep(5)
        try:
            result = future.result()

        except asyncio.TimeoutError as exc:
            _LOGGER.warning("The command took too long, cancelling the task...")
            future.cancel()
            raise ExpiredCallbackError(exc)

        except Exception as exc:
            _LOGGER.warning(f"The command raised an exception: {exc!r}")
            raise ExpiredCallbackError(exc)

        else:
            _LOGGER.debug(f"The command returned: {result!r}")
            return result

    def fake_device(self, device_id, create_device=None, start_binding=False) -> Device:
        """Create a faked device, and optionally set it to binding mode.

        Will make any neccesary changed to the device lists.
        """
        # TODO: what about using the HGI

        if not is_valid_dev_id(device_id):
            raise TypeError(f"The device id is not valid: {device_id}")

        if create_device and device_id in self.device_by_id:
            raise LookupError(f"The device id already exists: {device_id}")
        elif not create_device and device_id not in self.device_by_id:
            raise LookupError(f"The device id does not exist: {device_id}")

        if self.config.enforce_known_list and device_id not in self._include:
            self._include[device_id] = {}
        elif device_id in self._exclude:
            del self._exclude[device_id]

        return self._get_device(device_id)._make_fake(bind=start_binding)

    def _add_task(self, fnc, *args, delay=None, period=None, **kwargs) -> None:
        """Start a task after delay seconds and then repeat it every period seconds."""
        self._tasks.append(
            schedule_task(fnc, *args, delay=delay, period=period, **kwargs)
        )
