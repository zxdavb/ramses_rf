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
from datetime import datetime as dt
from queue import Empty
from threading import Lock
from typing import Callable, Dict, List, Optional, Tuple

from .const import ATTR_FAKED, ATTR_ORPHANS, DONT_CREATE_MESSAGES
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
from .protocol.const import ATTR_DEVICES, NUL_DEVICE_ID
from .schema import (
    BLOCK_LIST,
    DEBUG_MODE,
    INPUT_FILE,
    KNOWN_LIST,
    load_config,
    load_schema,
)
from .systems import System, create_system
from .version import VERSION  # noqa: F401

from .protocol import I_, RP, RQ, W_, __dev_mode__  # noqa: F401, isort: skip

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

        (self.config, self.__schema, self._include, self._exclude) = load_config(
            self.serial_port, self._input_file, **kwargs
        )

        self.pkt_protocol, self.pkt_transport = None, None
        self.msg_protocol, self.msg_transport = None, None

        set_pkt_logging(
            _PKT_LOGGER,
            cc_console=self.config.reduce_processing >= DONT_CREATE_MESSAGES,
            **self.config.packet_log,
        )

        if self.config.reduce_processing < DONT_CREATE_MESSAGES:
            self.msg_protocol, self.msg_transport = self.create_client(process_msg)

        self._state_lock = Lock()
        self._state_params = None

        # if self.config.reduce_processing > 0:
        self._prev_msg = None  # see: _clear_state()

        self.hgi = None
        self.evo = None

        self.systems: List[System] = []
        self.system_by_id: Dict = {}
        self.devices: List[Device] = []
        self.device_by_id: Dict = {}

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
        _LOGGER.info("ENGINE: Starting poller...")

        load_schema(self, **self.__schema)

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
            set_logger_timesource(self.pkt_protocol._dt_now)
            _LOGGER.warning(
                "System datetimes are now set to the most recent packet log timestamp"
            )

        if self.pkt_transport.get_extra_info(POLLER_TASK):
            self._tasks.append(self.pkt_transport.get_extra_info(POLLER_TASK))

        await asyncio.gather(*self._tasks)

    def _get_device(self, dev_id, ctl_id=None, domain_id=None, **kwargs) -> Device:
        """Return a device (will create it if required).

        NB: a device can be safely considered bound to a controller only if the
        controller says it is.

        Can also set a controller/system (will create as required). If a controller is
        provided, can also set the domain_id as one of: zone_idx, FF (controllers), FC
        (heater_relay), HW (DHW sensor, relay), or None (unknown, TBA).
        """

        # TODO: only create controller if it is confirmed by an RP

        if dev_id[:2] in ("18", "--") or dev_id in (NUL_DEVICE_ID, "01:000001"):
            return  # not valid device types/real devices

        if ctl_id is not None:
            ctl = self.device_by_id.get(ctl_id)
            if ctl is None:
                ctl = self._get_device(ctl_id, domain_id="FF", **kwargs)

        # These two are because Pkt.Transport.is_wanted() may still let some through
        if self.config.enforce_known_list and dev_id not in self._include:
            _LOGGER.warning(
                f"Ignoring a non-allowed device_id: {dev_id}"
                f" (if required, add it to the {KNOWN_LIST})"
            )
            return

        if dev_id in self._exclude:
            _LOGGER.warning(
                f"Ignoring a blocked device_id: {dev_id}"
                f" (if required, remove it from the {BLOCK_LIST})"
            )
            return

        dev = self.device_by_id.get(dev_id)
        if dev is None:  # TODO: take into account device filter?
            dev = create_device(self, dev_id)

        if dev.type == "01" and dev._is_controller and dev._evo is None:
            dev._evo = create_system(self, dev, profile=kwargs.get("profile"))

        if not self.hgi and dev.type == "18":
            self.hgi = dev

        # update the existing device with any metadata TODO: this is messy
        if ctl_id and ctl:
            dev._set_ctl(ctl)
        if domain_id in ("F9", "FA", "FC", "FF"):
            dev._domain_id = domain_id
        elif domain_id is not None and ctl_id and ctl:
            dev._set_parent(ctl._evo._get_zone(domain_id))

        return dev

    def _clear_state(self) -> None:
        gwy = self
        gwy._prev_msg = None

        gwy.hgi = None
        gwy.evo = None

        gwy.systems = []
        gwy.system_by_id = {}
        gwy.devices = []
        gwy.device_by_id = {}

    def _pause_engine(self) -> None:
        _LOGGER.info("ENGINE: Pausing engine...")

        self._state_lock.acquire()
        if self._state_params is not None:
            self._state_lock.release()
            raise RuntimeError("Unable to pause, the engine is already paused")

        callback = None

        if self.pkt_protocol:
            self.pkt_protocol.pause_writing()
            self.pkt_protocol._callback, callback = None, self.pkt_protocol._callback

        self.config.disable_discovery, discovery = True, self.config.disable_discovery
        self.config.disable_sending, sending = True, self.config.disable_sending

        self._state_params = (callback, discovery, sending)
        self._state_lock.release()

    def _resume_engine(self) -> None:
        _LOGGER.info("ENGINE: Resumed engine.")

        self._state_lock.acquire()
        if self._state_params is None:
            self._state_lock.release()
            raise RuntimeError("Unable to resume, the engine is not paused")

        self._state_params, (callback, discovery, sending) = None, self._state_params

        if self.pkt_protocol:
            self.pkt_protocol._callback = callback  # self.msg_transport._pkt_receiver
            self.pkt_protocol.resume_writing()

        self.config.disable_discovery = discovery
        self.config.disable_sending = sending

        # [
        #     zone._discover(discover_flag=6)
        #     for evo in self.systems
        #     for zone in evo.zones
        # ]
        self._state_lock.release()

    def _get_state(self, include_expired=None) -> Tuple[Dict, Dict]:
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

        schema, pkts = self.schema, dict(sorted(pkts.items()))

        _LOGGER.info("ENGINE: Saved state.")
        self._resume_engine()
        return schema, pkts

    async def _set_state(self, schema: Dict, packets: Dict) -> None:
        self._pause_engine()
        _LOGGER.info("ENGINE: Restoring schema...")

        self._clear_state()  # TODO: consider need for this (here, or at all)
        load_schema(self, **schema)  # keep old known_devs?

        _LOGGER.info("ENGINE: Restoring state...")
        _, tmp_transport = create_pkt_stack(
            self,
            self.msg_transport._pkt_receiver if self.msg_transport else None,
            packet_dict=packets,
        )
        await tmp_transport.get_extra_info(POLLER_TASK)

        while not self.msg_transport._que.empty():
            try:
                self.msg_transport._que.get_nowait()
            except Empty:
                continue
            self.msg_transport._que.task_done()

        _LOGGER.info("ENGINE: Restored schema/state.")
        self._resume_engine()

    def _dt_now(self):
        # return dt.now()
        return self.pkt_protocol._dt_now() if self.pkt_protocol else dt.now()

    @property
    def schema(self) -> dict:
        """Return the global schema."""

        schema = {
            # "rf_gateway": self.hgi and self.hgi.schema,
            "main_controller": self.evo._ctl.id
            if self.evo
            else None
        }

        if self.evo:
            schema[self.evo._ctl.id] = self.evo.schema
        for evo in self.systems:
            if evo is not self.evo:
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

    def send_cmd(self, cmd: Command, callback: Callable = None, **kwargs) -> None:
        """Send a command with the option to return any response via callback.

        Response packets, if any, follow an RQ/W (as an RP/I), and have the same code.
        This routine is thread safe.
        """

        if not cmd:
            return

        if not self.msg_protocol:
            raise RuntimeError("there is no message protocol")

        asyncio.run_coroutine_threadsafe(
            self.msg_protocol.send_data(cmd, callback=callback, **kwargs), self._loop
        )

    async def async_send_cmd(
        self, cmd: Command, awaitable: bool = True, **kwargs
    ) -> Optional[Message]:
        """Send a command with the option to not wait for a response (awaitable=False).

        Response packets, if any, follow an RQ/W (as an RP/I), and have the same code.
        This routine is thread safe.
        """
        if not self.msg_protocol:
            raise RuntimeError("there is no message protocol")

        future = asyncio.run_coroutine_threadsafe(
            self.msg_protocol.send_data(cmd, awaitable=awaitable, **kwargs), self._loop
        )

        asyncio.sleep(5)
        try:
            result = future.result()
        except asyncio.TimeoutError:
            print("The coroutine took too long, cancelling the task...")
            future.cancel()
        except Exception as exc:
            print(f"The coroutine raised an exception: {exc!r}")
        else:
            print(f"The coroutine returned: {result!r}")
            return result

    def fake_device(self, device_id, create_device=None, start_binding=False) -> Device:
        """Create a faked device, and optionally set it to binding mode.

        Will make any neccesary changed to the device lists.
        """
        # TODO: what about using the HGI

        if not is_valid_dev_id(device_id):
            raise TypeError(f"The device id is not valid: {device_id}")

        if create_device and device_id in self.device_by_id:
            raise ValueError(f"The device id already exists: {device_id}")
        elif not create_device and device_id not in self.device_by_id:
            raise ValueError(f"The device id does not exist: {device_id}")

        if self.config.enforce_known_list and device_id not in self._include:
            self._include[device_id] = {}
        elif device_id in self._exclude:
            del self._exclude[device_id]

        return self._get_device(device_id)._make_fake(bind=start_binding)

    def _add_task(self, *args, **kwargs) -> None:
        self._tasks.append(schedule_task(*args, **kwargs))
