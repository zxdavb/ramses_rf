#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#


# TODO:
# - create_client() should simply add a msg_handler callback to the protocol
# - setting ser_port config done 2x - create_client & _start
# - sort out gwy.config...
# - sort out send_cmd generally, and make awaitable=
# - sort out reduced processing

"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

The serial to RF gateway (HGI80, not RFG100).
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
from concurrent import futures
from datetime import datetime as dt
from io import TextIOWrapper
from threading import Lock
from types import SimpleNamespace
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from .device import Device
    from .protocol.frame import _CodeT, _DeviceIdT, _PayloadT, _VerbT

from .const import DONT_CREATE_MESSAGES, SZ_DEVICE_ID, SZ_DEVICES, __dev_mode__
from .device import DeviceHeat, DeviceHvac, Fakeable, device_factory
from .dispatcher import Message, detect_array_fragment, process_msg
from .helpers import schedule_task, shrink
from .protocol import (
    Address,
    Command,
    is_valid_dev_id,
    set_logger_timesource,
    set_pkt_logging_config,
)
from .protocol.address import HGI_DEV_ADDR, NON_DEV_ADDR, NUL_DEV_ADDR
from .protocol.protocol_new import MsgProtocolT, PktTransportT, create_stack
from .protocol.schemas import SZ_PACKET_LOG, SZ_PORT_CONFIG, SZ_PORT_NAME
from .protocol.transport_new import SZ_READER_TASK  # TODO: find a better way to await
from .schemas import (
    SCH_GLOBAL_CONFIG,
    SCH_TRAITS,
    SZ_ALIAS,
    SZ_BLOCK_LIST,
    SZ_CLASS,
    SZ_CONFIG,
    SZ_ENFORCE_KNOWN_LIST,
    SZ_FAKED,
    SZ_KNOWN_LIST,
    SZ_MAIN_TCS,
    SZ_ORPHANS,
    load_config,
    load_schema,
)
from .system import System

# skipcq: PY-W2000
from .protocol import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)


SZ_INPUT_FILE = "input_file"  # FIXME


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Engine:
    """The engine class."""

    def __init__(
        self,
        port_name: None | str,
        input_file: None | TextIOWrapper = None,
        port_config: None | dict = None,
        loop: None | asyncio.AbstractEventLoop = None,
    ) -> None:
        self.ser_name = port_name
        self._input_file = input_file
        self._port_config = port_config or {}
        self._loop = loop or asyncio.get_running_loop()

        self._include: dict[_DeviceIdT, dict] = {}  # aka known_list, and ?allow_list
        self._exclude: dict[_DeviceIdT, dict] = {}  # aka block_list
        self._unwanted: list[_DeviceIdT] = [
            NON_DEV_ADDR.id,
            NUL_DEV_ADDR.id,
            "01:000001",  # why this one?
        ]

        self.config = SimpleNamespace()  # **SCH_CONFIG_GATEWAY({}))

        self._protocol: MsgProtocolT = None  # type: ignore[assignment]
        self._transport: PktTransportT = None  # type: ignore[assignment]

        self._engine_lock = Lock()
        self._engine_state: None | tuple[None | Callable, tuple] = None
        self._prev_msg: Message | None = None  # used by the dispatcher
        self._this_msg: Message | None = None  # used by the dispatcher

    def __str__(self) -> str:
        if not self._transport:
            return f"{HGI_DEV_ADDR.id} ({self.ser_name})"

        device_id = self._transport.get_extra_info(
            SZ_DEVICE_ID, default=HGI_DEV_ADDR.id
        )
        return f"{device_id} ({self.ser_name})"

    def _setup_event_handlers(self) -> None:  # HACK: for dev/test only
        def handle_exception(loop, context):
            """Handle exceptions on any platform."""
            _LOGGER.error("handle_exception(): Caught: %s", context["message"])

            exc = context.get("exception")
            if exc:
                raise exc

        if DEV_MODE:
            _LOGGER.debug("_setup_event_handlers(): Creating exception handler...")
            self._loop.set_exception_handler(handle_exception)

    def _dt_now(self):
        return self._transport._dt_now() if self._transport else dt.now()

    def create_client(
        self,
        msg_handler: Callable[[Message, None | Message], None],
        /,
        **kwargs,
    ) -> tuple[MsgProtocolT, PktTransportT]:
        """Create a client protocol for the RAMSES-II message transport."""

        kwargs[SZ_PORT_NAME] = kwargs.get(SZ_PORT_NAME, self.ser_name)
        kwargs[SZ_PORT_CONFIG] = kwargs.get(SZ_PORT_CONFIG, self._port_config)
        kwargs[SZ_PACKET_LOG] = kwargs.pop(SZ_INPUT_FILE, self._input_file)

        return create_stack(msg_handler, **kwargs)

    async def start(self) -> None:
        """Initiate receiving (Messages) and sending (Commands)."""
        self._start()

    def _start(self) -> None:
        if self.ser_name:
            pkt_source = {
                SZ_PORT_NAME: self.ser_name,
                SZ_PORT_CONFIG: self._port_config,
            }
        else:
            pkt_source = {
                SZ_PACKET_LOG: self._input_file,
            }
            self.config.disable_discovery = True  # TODO: needed?
            self.config.disable_sending = True  # TODO: needed?

        self._protocol, self._transport = self.create_client(
            self._handle_msg, **pkt_source
        )  # TODO: may raise SerialException

        if self._input_file:  # FIXME: bad smell - move to transport
            set_logger_timesource(self._transport._dt_now)
            _LOGGER.warning("Datetimes maintained as most recent packet log timestamp")

    async def stop(self) -> None:
        """Cancel all outstanding low-level tasks."""

        # # FIXME: leaker_task, writer_task
        # if self._protocol and (t := self._protocol._leaker_task) and not t.done():
        #     try:
        #         await t
        #     except asyncio.CancelledError:
        #         pass

        if self._transport:
            self._transport.close()  # ? .abort()

    def _pause(self, *args) -> None:
        """Pause the (active) engine or raise a RuntimeError."""

        (_LOGGER.info if DEV_MODE else _LOGGER.debug)("ENGINE: Pausing engine...")

        if not self._engine_lock.acquire(blocking=False):
            raise RuntimeError("Unable to pause engine, failed to acquire lock")

        if self._engine_state is not None:
            self._engine_lock.release()
            raise RuntimeError("Unable to pause engine, it is already paused")

        self._engine_state, callback = (None, tuple()), None
        self._engine_lock.release()

        if self._protocol:
            self._protocol.pause_writing()
            self._protocol._msg_callback, callback = None, self._protocol._msg_callback

        self._engine_state = (callback, args)

    def _resume(self) -> tuple:  # FIXME: not atomic
        """Resume the (paused) engine or raise a RuntimeError."""

        (_LOGGER.info if DEV_MODE else _LOGGER.debug)("ENGINE: Resuming engine...")

        # if not self.ser_name:
        #     raise RuntimeError("Unable to resume engine, no serial port configured")

        if not self._engine_lock.acquire(timeout=0.1):
            raise RuntimeError("Unable to resume engine, failed to acquire lock")

        if self._engine_state is None:
            self._engine_lock.release()
            raise RuntimeError("Unable to resume engine, it was not paused")

        callback: None | Callable  # mypy
        args: tuple  # mypy
        callback, args = self._engine_state

        self._engine_lock.release()

        # TODO: is this needed, given it can buffer if required?
        if self._protocol:
            self._protocol._msg_callback = callback
            self._protocol.resume_writing()

        self._engine_state = None

        return args

    @staticmethod
    def create_cmd(
        verb: _VerbT, device_id: _DeviceIdT, code: _CodeT, payload: _PayloadT, **kwargs
    ) -> Command:
        """Make a command addressed to device_id."""
        return Command.from_attrs(verb, device_id, code, payload, **kwargs)

    def send_cmd(self, cmd: Command, callback: Callable = None, **kwargs):  # FIXME
        """Send a command with the option to return any response message via callback.

        Response packets, if any (an RP/I will follow an RQ/W), and have the same code.
        This routine is thread safe.
        """

        if not self._protocol:
            raise RuntimeError("there is no message protocol")

        # self._loop.call_soon_threadsafe(
        #     self._protocol.send_data(cmd, callback=callback, **kwargs)
        # )
        coro = self._protocol.send_data(cmd, callback=callback, **kwargs)
        fut: futures.Future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        # fut: asyncio.Future = asyncio.wrap_future(fut)
        return fut

    async def async_send_cmd(self, cmd: Command, **kwargs) -> None | Message:  # FIXME
        """Send a command with the option to not wait for a response message.

        Response packets, if any, follow an RQ/W (as an RP/I), and have the same code.
        This routine is thread safe.
        """

        # def callback(fut):
        #     print(fut.result())

        fut = self.send_cmd(cmd)  # , _make_awaitable=True, **kwargs)
        # fut.add_done_callback(callback)

        while True:
            try:
                result = fut.result(timeout=0)

            # except futures.CancelledError:  # fut ?was cancelled by a higher layer
            #     break

            except futures.TimeoutError:  # fut/cmd has not yet completed
                pass  # should be a pass

            except TimeoutError as exc:  # raised by send_cmd()
                raise TimeoutError(f"cmd ({cmd.tx_header}) timed out: {exc}")

            # except RuntimeError as exc:  # raised by send_cmd()
            #     _LOGGER.error(f"cmd ({cmd.tx_header}) raised an exception: {exc!r}")
            #     if self._transport.is_closing:
            #         pass

            except Exception as exc:
                _LOGGER.error(f"cmd ({cmd.tx_header}) raised an exception: {exc!r}")
                raise exc

            else:
                _LOGGER.debug(f"cmd ({cmd.tx_header}) returned: {result!r})")
                return result

            await asyncio.sleep(0.001)  # TODO: 0.001, 0.005 or other?

    def _handle_msg(self, msg) -> None:
        # HACK: This is one consequence of an unpleaseant anachronism
        msg.__class__ = Message  # HACK (next line too)
        msg._gwy = self

        self._this_msg, self._prev_msg = msg, self._this_msg


class Gateway(Engine):
    """The gateway class."""

    def __init__(
        self,
        port_name: None | str,
        debug_mode: None | bool = None,
        input_file: None | TextIOWrapper = None,
        loop: None | asyncio.AbstractEventLoop = None,
        port_config: None | dict = None,
        **kwargs,
    ) -> None:
        if debug_mode:
            _LOGGER.setLevel(logging.DEBUG)  # should be INFO?
        _LOGGER.debug("Starting RAMSES RF, **config = %s", kwargs)

        super().__init__(
            port_name, input_file=input_file, port_config=port_config, loop=loop
        )

        self._tasks: list = []  # TODO: used by discovery, move lower?
        self._schema: dict[str, dict] = {}

        (self.config, self._schema, self._include, self._exclude) = load_config(
            self.ser_name,
            self._input_file,
            **SCH_GLOBAL_CONFIG({k: v for k, v in kwargs.items() if k[:1] != "_"}),
        )
        set_pkt_logging_config(
            cc_console=self.config.reduce_processing >= DONT_CREATE_MESSAGES,
            **self.config.packet_log or {},
        )

        # if self.config.reduce_processing < DONT_CREATE_MESSAGES:
        # if self.config.reduce_processing > 0:
        self._tcs: None | System = None  # type: ignore[assignment]
        self.devices: list[Device] = []
        self.device_by_id: dict[str, Device] = {}

        self._setup_event_handlers()

        load_schema(self, **self._schema)

    def __repr__(self) -> str:
        if not self.ser_name:
            return f"Gateway(input_file={self._input_file})"
        return f"Gateway(port_name={self.ser_name}, port_config={self._port_config})"

    def _setup_event_handlers(self) -> None:  # HACK: for dev/test only
        async def handle_sig_posix(sig):
            """Handle signals on posix platform."""
            _LOGGER.debug("Received a signal (%s), processing...", sig.name)

            if sig == signal.SIGUSR1:
                _LOGGER.info("Schema: \r\n%s", {self.tcs.id: self.tcs.schema})
                _LOGGER.info("Params: \r\n%s", {self.tcs.id: self.tcs.params})
                _LOGGER.info("Status: \r\n%s", {self.tcs.id: self.tcs.status})

            elif sig == signal.SIGUSR2:
                _LOGGER.info("Status: \r\n%s", {self.tcs.id: self.tcs.status})

        super()._setup_event_handlers()

        _LOGGER.debug("_setup_event_handlers(): Creating signal handlers...")
        if os.name == "posix":  # full support
            for sig in [signal.SIGUSR1, signal.SIGUSR2]:
                self._loop.add_signal_handler(
                    sig, lambda sig=sig: self._loop.create_task(handle_sig_posix(sig))
                )
        elif os.name == "nt":  # supported, but YMMV
            _LOGGER.warning("Be aware, YMMV with Windows...")
        else:  # unsupported
            raise RuntimeError(f"Unsupported OS for this module: {os.name}")

    @property
    def hgi(self) -> None | Device:
        """Return the active HGI80-compatible gateway device, if known."""
        if self._transport and (
            device_id := self._transport.get_extra_info(SZ_DEVICE_ID)
        ):
            return self.device_by_id.get(device_id)

    def create_client(
        self,
        msg_handler: Callable[[Message, None | Message], None],
        /,
        # msg_filter: None | Callable[[Message], bool] = None,
        **kwargs,
    ) -> tuple[MsgProtocolT, PktTransportT]:
        """Create a client protocol for the RAMSES-II message transport."""

        # TODO: The optional filter will return True if the message is to be handled.
        # if msg_filter is not None and not is_callback(msg_filter):
        #     raise TypeError(f"Msg filter {msg_filter} is not a callback")

        return super().create_client(
            msg_handler,
            disable_sending=self.config.disable_sending,
            enforce_include_list=self.config.enforce_known_list,
            exclude_list=self._exclude,
            include_list=self._include,
            **kwargs,
        )

    async def start(self, *, start_discovery: bool = True) -> None:
        """Start the Gateway and Initiate discovery as required."""

        def initiate_discovery(dev_list, sys_list) -> None:
            _LOGGER.debug("ENGINE: Initiating/enabling discovery...")

            # [d._start_discovery_poller() for d in devs]
            for device in dev_list:
                device._start_discovery_poller()

            for system in sys_list:
                system._start_discovery_poller()
                for zone in system.zones:
                    zone._start_discovery_poller()
                if system.dhw:
                    system.dhw._start_discovery_poller()

        await super().start()

        if not self.ser_name:  # wait until have processed the entire packet log...
            await self._transport.get_extra_info(SZ_READER_TASK)

        # else: source of packets is a serial port
        # TODO: gwy.config.disable_discovery
        elif start_discovery:
            initiate_discovery(self.devices, self.systems)

    async def stop(self) -> None:  # FIXME: a mess
        """Cancel all outstanding high-level tasks."""
        # if self._engine_state is None:
        #     self._pause()

        _ = [t.cancel() for t in self._tasks if not t.done()]
        try:
            if tasks := (t for t in self._tasks if not t.done()):
                await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass

        await super().stop()

    def _pause(self, *args, clear_state: bool = False) -> None:
        """Pause the (unpaused) gateway (disables sending/discovery).

        There is the option to save other objects, as *args.
        """

        super()._pause(
            self.config.disable_discovery, self.config.disable_sending, *args
        )
        self.config.disable_discovery = True
        self.config.disable_sending = True

        if clear_state:
            self._clear_state()

    def _resume(self) -> tuple:
        """Resume the (paused) gateway (enables sending/discovery, if applicable).

        Will restore other objects, as *args.
        """

        (
            self.config.disable_discovery,
            self.config.disable_sending,
            *args,
        ) = super()._resume()

        return args  # type: ignore[return-value]

    def _clear_state(self) -> None:
        _LOGGER.warning("ENGINE: Clearing exisiting schema/state...")

        self._tcs = None
        self.devices = []
        self.device_by_id = {}

    def get_state(self, include_expired: bool = False) -> tuple[dict, dict]:
        """Return the current schema & state (will pause/resume the engine)."""

        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)("ENGINE: Getting state...")
        self._pause()

        result = self._get_state(include_expired=include_expired)

        self._resume()
        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)("ENGINE: Got schema/state.")

        return result

    def _get_state(self, include_expired: bool = False) -> tuple[dict, dict]:
        def wanted_msg(msg: Message, include_expired: bool = False) -> bool:
            if msg.code == Code._313F:
                return msg.verb in (I_, RP)  # usu. expired, useful 4 back-back restarts
            if msg._expired and not include_expired:
                return False
            if msg.code == Code._0404:
                return msg.verb in (I_, W_) and msg._pkt._len > 7
            if msg.verb in (W_, RQ):
                return False
            # if msg.code == Code._1FC9 and msg.verb != RP:
            #     return True
            return include_expired or not msg._expired

        msgs = [m for device in self.devices for m in device._msg_db]

        for system in self.systems:
            msgs.extend(list(system._msgs.values()))
            msgs.extend([m for z in system.zones for m in z._msgs.values()])
            # msgs.extend([m for z in system.dhw for m in z._msgs.values()])

        # BUG: assumes pkts have unique dtms: may not be true for contrived logs...
        pkts = {
            f"{repr(msg._pkt)[:26]}": f"{repr(msg._pkt)[27:]}"
            for msg in msgs
            if wanted_msg(msg, include_expired=include_expired)
        }  # BUG: assumes pkts have unique dtms

        return self.schema, dict(sorted(pkts.items()))

    async def set_state(self, packets: dict, *, schema: dict | None = None) -> None:
        """Restore a cached schema & state."""

        # TODO: add a feature to exclude expired packets?
        (_LOGGER.warning if DEV_MODE else _LOGGER.info)("ENGINE: Setting state...")

        if schema is None:  # TODO: also for known_list (device traits)?
            schema = shrink(self.schema)

        self._pause(clear_state=True)

        load_schema(self, **schema)
        await self._set_state(packets, schema=schema)

        self._resume()
        (_LOGGER.warning if DEV_MODE else _LOGGER.info)("ENGINE: Set state.")

    async def _set_state(self, packets: dict, *, schema: dict | None = None) -> None:
        tmp_transport: asyncio.Transport

        if self._transport:
            pkt_receiver = self._transport.get_extra_info(self._transport.READER)
        else:
            pkt_receiver = None

        _, tmp_transport = self._create_protocol_stack(
            pkt_receiver, packet_dict=packets
        )
        await tmp_transport.get_extra_info(SZ_READER_TASK)

        self._prev_msg = None
        self._this_msg = None

    def get_device(
        self,
        dev_id: _DeviceIdT,
        *,
        msg: None | Message = None,
        parent=None,
        child_id=None,
        is_sensor: None | bool = None,
    ) -> Device:  # TODO: **schema) -> Device:  # may: LookupError
        """Return a device, create it if required.

        First, use the traits to create/update it, then pass it any msg to handle.
        All devices have traits, but only controllers (CTL, UFC) have a schema.

        Devices are uniquely identified by a device id.
        If a device is created, attach it to the gateway.
        """

        def check_filter_lists(dev_id: _DeviceIdT) -> None:  # may: LookupError
            """Raise an LookupError if a device_id is filtered out by a list."""

            if dev_id in self._unwanted:  # TODO: shouldn't invalidate a msg
                raise LookupError(f"Can't create {dev_id}: it is unwanted or invalid")

            if self.config.enforce_known_list and (
                dev_id not in self._include and dev_id != getattr(self.hgi, "id", None)
            ):
                self._unwanted.append(dev_id)
                raise LookupError(
                    f"Can't create {dev_id}: it is not an allowed device_id"
                    f" (if required, add it to the {SZ_KNOWN_LIST})"
                )

            if dev_id in self._exclude:
                self._unwanted.append(dev_id)
                raise LookupError(
                    f"Can't create {dev_id}: it is a blocked device_id"
                    f" (if required, remove it from the {SZ_BLOCK_LIST})"
                )

        check_filter_lists(dev_id)
        traits = SCH_TRAITS(self._include.get(dev_id, {}))

        dev = self.device_by_id.get(dev_id)
        if not dev:
            dev = device_factory(self, Address(dev_id), msg=msg, **traits)

        # TODO: the exact order of the following may need refining...

        # if schema:  # Step 2: Only controllers have a schema...
        #     dev._update_schema(**schema)  # TODO: schema/traits

        if parent or child_id:
            dev.set_parent(parent, child_id=child_id, is_sensor=is_sensor)

        if traits.get(SZ_FAKED):
            if isinstance(dev, Fakeable):
                dev._make_fake()
            else:
                _LOGGER.warning(f"The device is not fakable: {dev}")

        if msg:
            dev._handle_msg(msg)

        return dev

    @property
    def tcs(self) -> Optional[System]:
        """Return the primary TCS, if any."""

        if self._tcs is None and self.systems:
            self._tcs = self.systems[0]
        return self._tcs

    @property
    def known_list(self) -> dict:
        """Return the working known_list (a superset of the provided known_list).

        Unlike orphans, which are always instantiated when a schema is loaded, these
        devices may/may not exist. However, if they are ever instantiated, they should
        be given these traits.
        """

        result = self._include  # could be devices here, not (yet) in gwy.devices
        result.update(
            {
                d.id: {k: d.traits[k] for k in (SZ_CLASS, SZ_ALIAS, SZ_FAKED)}
                for d in self.devices
                if not self.config.enforce_known_list or d.id in self._include
            }
        )
        return result

    @property
    def system_by_id(self) -> dict:
        return {
            d.id: d.tcs
            for d in self.devices
            if hasattr(d, "tcs") and getattr(d.tcs, "id", None) == d.id
        }  # why something so simple look so messy

    @property
    def systems(self) -> list:
        return list(self.system_by_id.values())

    @property
    def _config(self) -> dict:
        """Return the working configuration.

        Includes:
         - config
         - schema (everything else)
         - known_list
         - block_list
        """

        return {
            "_gateway_id": self.hgi.id if self.hgi else None,
            SZ_MAIN_TCS: self.tcs.id if self.tcs else None,
            SZ_CONFIG: {SZ_ENFORCE_KNOWN_LIST: self.config.enforce_known_list},
            SZ_KNOWN_LIST: self.known_list,
            SZ_BLOCK_LIST: [{k: v} for k, v in self._exclude.items()],
            "_unwanted": sorted(self._transport._unwanted),
            "_unwanted_alt": sorted(self._unwanted),
        }

    @property
    def schema(self) -> dict:
        """Return the global schema.

        This 'active' schema may exclude non-present devices from the configured schema
        that was loaded during initialisation.

        Orphans are devices that 'exist' but don't yet have a place in the schema
        hierachy (if ever): therefore, they are instantiated when the schema is loaded,
        just like the other devices in the schema.
        """

        schema = {SZ_MAIN_TCS: self.tcs.ctl.id if self.tcs else None}

        for tcs in self.systems:
            schema[tcs.ctl.id] = tcs.schema

        schema[f"{SZ_ORPHANS}_heat"] = sorted(
            [
                d.id
                for d in self.devices
                if not getattr(d, "tcs", None)
                and isinstance(d, DeviceHeat)
                and d._is_present
            ]
        )

        schema[f"{SZ_ORPHANS}_hvac"] = sorted(
            [d.id for d in self.devices if isinstance(d, DeviceHvac) and d._is_present]
        )

        return schema

    @property
    def params(self) -> dict:
        return {SZ_DEVICES: {d.id: d.params for d in sorted(self.devices)}}

    @property
    def status(self) -> dict:
        return {SZ_DEVICES: {d.id: d.status for d in sorted(self.devices)}}

    def send_cmd(  # FIXME
        self, cmd: Command, callback: Callable = None, **kwargs
    ) -> futures.Future:
        """Send a command with the option to return any response via callback."""

        if self.config.disable_sending:
            raise RuntimeError("sending is disabled")

        fut = super().send_cmd(cmd, callback, **kwargs)

        self._tasks = [t for t in self._tasks if not t.done()]
        self._tasks.append(fut)
        return fut

    def fake_device(
        self,
        device_id: _DeviceIdT,
        create_device: bool = False,
        start_binding: bool = False,
    ) -> Device:
        """Create a faked device, and optionally set it to binding mode.

        Will make any neccesary changed to the device lists.
        """
        # TODO: enable to use the HGI as a (say) sensor/actuator

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

        if (dev := self.get_device(device_id)) and isinstance(dev, Fakeable):
            return dev._make_fake(bind=start_binding)
        raise TypeError(f"The device is not fakable: {device_id}")

    def add_task(self, fnc, *args, delay=None, period=None, **kwargs) -> asyncio.Task:
        """Start a task after delay seconds and then repeat it every period seconds."""
        self._tasks = [t for t in self._tasks if not t.done()]
        task = schedule_task(fnc, *args, delay=delay, period=period, **kwargs)
        self._tasks.append(task)
        return task

    def _handle_msg(self, msg) -> None:
        # TODO: Remove this
        # # HACK: if CLI, double-logging with client.py proc_msg() & setLevel(DEBUG)
        # if (log_level := _LOGGER.getEffectiveLevel()) < logging.INFO:
        #     _LOGGER.info(msg)
        # elif log_level <= logging.INFO and not (
        #     msg.verb == RQ and msg.src.type == DEV_TYPE_MAP.HGI
        # ):
        #     _LOGGER.info(msg)

        super()._handle_msg(msg)

        # TODO: ideally remove this feature...
        if detect_array_fragment(self._this_msg, self._prev_msg):
            msg._pkt._force_has_array()  # may be an array of length 1
            msg._payload = self._prev_msg.payload + (
                msg.payload if isinstance(msg.payload, list) else [msg.payload]
            )

        process_msg(self, msg)
