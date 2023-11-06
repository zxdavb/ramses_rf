#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

# TODO:
# - self._tasks is not ThreadSafe
# - sort out gwy.config...
# - sort out reduced processing


"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

The serial to RF gateway (HGI80, not RFG100).
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime as dt
from io import TextIOWrapper
from threading import Lock
from types import SimpleNamespace
from typing import TYPE_CHECKING

from ramses_tx import (
    SZ_ACTIVE_HGI,
    Address,
    Command,
    Packet,
    SendPriority,
    exceptions,
    is_valid_dev_id,
    protocol_factory,
    set_pkt_logging_config,
    transport_factory,
)
from ramses_tx.address import HGI_DEV_ADDR, NON_DEV_ADDR, NUL_DEV_ADDR
from ramses_tx.protocol_fsm import DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT
from ramses_tx.schemas import (
    SCH_ENGINE_CONFIG,
    SZ_BLOCK_LIST,
    SZ_DISABLE_SENDING,
    SZ_ENFORCE_KNOWN_LIST,
    SZ_KNOWN_LIST,
    SZ_PACKET_LOG,
    SZ_PORT_CONFIG,
    SZ_PORT_NAME,
    select_device_filter_mode,
)

from .const import DONT_CREATE_MESSAGES, SZ_DEVICES, __dev_mode__
from .device import DeviceHeat, DeviceHvac, Fakeable, device_factory
from .dispatcher import Message, detect_array_fragment, process_msg
from .helpers import schedule_task, shrink
from .schemas import (
    SCH_GATEWAY_CONFIG,
    SCH_GLOBAL_SCHEMAS,
    SCH_TRAITS,
    SZ_ALIAS,
    SZ_CLASS,
    SZ_CONFIG,
    SZ_DISABLE_DISCOVERY,
    SZ_ENABLE_EAVESDROP,
    SZ_FAKED,
    SZ_MAIN_TCS,
    SZ_ORPHANS,
    load_schema,
)
from .system import System

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:  # mypy TypeVars and similar (e.g. Index, Verb)
    # skipcq: PY-W2000
    from .const import Index, Verb  # noqa: F401, pylint: disable=unused-import

if TYPE_CHECKING:
    from ramses_tx.frame import _DeviceIdT, _PayloadT
    from ramses_tx.protocol import RamsesProtocolT, RamsesTransportT

    from .device import Device

_MsgHandlerT = Callable[[Message], None]


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
        packet_log: dict = None,
        block_list: dict = None,
        known_list: dict = None,
        loop: None | asyncio.AbstractEventLoop = None,
        **kwargs,
    ) -> None:
        if port_name and input_file:
            _LOGGER.warning(
                "Port (%s) specified, so file (%s) ignored",
                port_name,
                input_file,
            )
            input_file = None

        self._disable_sending = kwargs.pop(SZ_DISABLE_SENDING, None)
        if input_file:
            self._disable_sending = True
        elif not port_name:
            raise TypeError("Either a port_name or a input_file must be specified")

        self.ser_name = port_name
        self._input_file = input_file

        self._port_config = port_config or {}
        self._packet_log = packet_log or {}
        self._loop = loop or asyncio.get_running_loop()

        self._exclude: dict[_DeviceIdT, dict] = block_list or {}
        self._include: dict[_DeviceIdT, dict] = known_list or {}
        self._unwanted: list[_DeviceIdT] = [
            NON_DEV_ADDR.id,
            NUL_DEV_ADDR.id,
            "01:000001",  # why this one?
        ]
        self._enforce_known_list = select_device_filter_mode(
            kwargs.pop(SZ_ENFORCE_KNOWN_LIST, None),
            self._include,
            self._exclude,
        )
        self._kwargs = kwargs  # HACK

        self._engine_lock = Lock()
        self._engine_state: None | tuple[None | Callable, tuple] = None

        self._protocol: None | RamsesProtocolT = None
        self._transport: None | RamsesTransportT = None

        self._prev_msg: None | Message = None
        self._this_msg: None | Message = None

        self._set_msg_handler(self._msg_handler)

    def __str__(self) -> str:
        if not self._transport:
            return f"{HGI_DEV_ADDR.id} ({self.ser_name})"

        device_id = self._transport.get_extra_info(
            SZ_ACTIVE_HGI, default=HGI_DEV_ADDR.id
        )
        return f"{device_id} ({self.ser_name})"

    def _dt_now(self):
        return self._transport._dt_now() if self._transport else dt.now()

    def _set_msg_handler(
        self, msg_handler: _MsgHandlerT
    ) -> tuple[RamsesProtocolT, RamsesTransportT]:
        """Create an appropriate protocol for the packet source (transport).

        The corresponding transport will be created later.
        """

        self._protocol = protocol_factory(
            msg_handler, disable_sending=self._disable_sending
        )

    def add_msg_handler(
        self,
        msg_handler: Callable[[Message], None],
        /,
        msg_filter: None | Callable[[Message], bool] = None,
    ) -> None:
        """Create a client protocol for the RAMSES-II message transport.

        The optional filter will return True if the message is to be handled.
        """

        # if msg_filter is not None and not is_callback(msg_filter):
        #     raise TypeError(f"Msg filter {msg_filter} is not a callback")

        if not msg_filter:
            msg_filter = lambda _: True  # noqa: E731
        else:
            raise NotImplementedError

        self._protocol.add_handler(msg_handler, msg_filter=msg_filter)

    async def start(self) -> None:
        """Create a suitable transport for the specified packet source.

        Initiate receiving (Messages) and sending (Commands).
        """

        pkt_source = {}
        if self.ser_name:
            pkt_source[SZ_PORT_NAME] = self.ser_name
            pkt_source[SZ_PORT_CONFIG] = self._port_config
        else:  # if self._input_file:
            pkt_source[SZ_PACKET_LOG] = self._input_file

        self._transport = await transport_factory(
            self._protocol,
            disable_sending=self._disable_sending,
            enforce_include_list=self._enforce_known_list,
            exclude_list=self._exclude,
            include_list=self._include,
            loop=self._loop,
            **pkt_source,
            **self._kwargs,  # HACK: only accept extra & use_regex
        )

        self._kwargs = None  # HACK

        if self._input_file:
            await self._wait_for_protocol_to_stop()

    async def stop(self) -> None:
        """Close the transport (will stop the protocol)."""

        if self._transport:
            self._transport.close()
        elif not self._protocol.wait_connection_lost.done():
            # the transport was never started
            self._protocol.connection_lost(None)
        return await self._wait_for_protocol_to_stop()

    async def _wait_for_protocol_to_stop(self) -> None:
        await self._protocol.wait_connection_lost
        return self._protocol.wait_connection_lost.result()  # may raise an exception

    def _pause(self, *args) -> None:
        """Pause the (active) engine or raise a RuntimeError."""
        (_LOGGER.info if DEV_MODE else _LOGGER.debug)("ENGINE: Pausing engine...")

        if not self._engine_lock.acquire(blocking=False):
            raise RuntimeError("Unable to pause engine, failed to acquire lock")

        if self._engine_state is not None:
            self._engine_lock.release()
            raise RuntimeError("Unable to pause engine, it is already paused")

        self._engine_state = (None, tuple())  # aka not None
        self._engine_lock.release()  # is ok to release now

        self._protocol.pause_writing()  # TODO: call_soon()?
        self._transport.pause_reading()  # TODO: call_soon()?

        self._protocol._msg_handler, handler = None, self._protocol._msg_handler
        self._disable_sending, read_only = True, self._disable_sending

        self._engine_state = (handler, read_only, args)

    def _resume(self) -> tuple:  # FIXME: not atomic
        """Resume the (paused) engine or raise a RuntimeError."""
        (_LOGGER.info if DEV_MODE else _LOGGER.debug)("ENGINE: Resuming engine...")

        args: tuple  # mypy

        if not self._engine_lock.acquire(timeout=0.1):
            raise RuntimeError("Unable to resume engine, failed to acquire lock")

        if self._engine_state is None:
            self._engine_lock.release()
            raise RuntimeError("Unable to resume engine, it was not paused")

        self._protocol._msg_handler, self._disable_sending, args = self._engine_state
        self._engine_lock.release()

        self._transport.resume_reading()
        if not self._disable_sending:
            self._protocol.resume_writing()

        self._engine_state = None

        return args

    @staticmethod
    def create_cmd(
        verb: Verb, device_id: _DeviceIdT, code: Code, payload: _PayloadT, **kwargs
    ) -> Command:
        """Make a command addressed to device_id."""
        return Command.from_attrs(verb, device_id, code, payload, **kwargs)

    async def async_send_cmd(
        self,
        cmd: Command,
        max_retries: int = DEFAULT_MAX_RETRIES,
        priority: SendPriority = SendPriority.DEFAULT,
        timeout: float = DEFAULT_TIMEOUT,
        wait_for_reply: None | bool = None,
    ) -> None | Packet:
        """Send a Command and, if QoS is enabled, return the corresponding Packet."""

        return await self._protocol.send_cmd(
            cmd,
            max_retries=max_retries,
            priority=priority,
            timeout=timeout,
            wait_for_reply=wait_for_reply,
        )

    def _msg_handler(self, msg: Message) -> None:
        # HACK: This is one consequence of an unpleaseant anachronism
        msg.__class__ = Message  # HACK (next line too)
        msg._gwy = self

        self._this_msg, self._prev_msg = msg, self._this_msg


class Gateway(Engine):
    """The gateway class."""

    def __init__(
        self,
        port_name: None | str,
        input_file: None | TextIOWrapper = None,
        port_config: None | dict = None,
        packet_log: dict = None,
        block_list: dict = None,
        known_list: dict = None,
        loop: None | asyncio.AbstractEventLoop = None,
        **kwargs,
    ) -> None:
        if kwargs.pop("debug_mode", None):
            _LOGGER.setLevel(logging.DEBUG)

        kwargs = {k: v for k, v in kwargs.items() if k[:1] != "_"}  # anachronism
        config = kwargs.pop(SZ_CONFIG, {})

        super().__init__(
            port_name,
            input_file=input_file,
            port_config=port_config,
            packet_log=packet_log,
            block_list=block_list,
            known_list=known_list,
            loop=loop,
            **SCH_ENGINE_CONFIG(config),
        )

        if self._disable_sending:
            config[SZ_DISABLE_DISCOVERY] = True
        if config.get(SZ_ENABLE_EAVESDROP):
            _LOGGER.warning(
                f"{SZ_ENABLE_EAVESDROP}=True: this is strongly discouraged"
                " for routine use (there be dragons here)"
            )

        self.config = SimpleNamespace(**SCH_GATEWAY_CONFIG(config))
        self._schema: dict = SCH_GLOBAL_SCHEMAS(kwargs)
        self._tasks: list[asyncio.Task] = []  # TODO: used by discovery, move lower?

        set_pkt_logging_config(
            cc_console=self.config.reduce_processing >= DONT_CREATE_MESSAGES,
            **self._packet_log,
        )

        # if self.config.reduce_processing < DONT_CREATE_MESSAGES:
        # if self.config.reduce_processing > 0:
        self._tcs: None | System = None  # type: ignore[assignment]
        self.devices: list[Device] = []
        self.device_by_id: dict[str, Device] = {}

    def __repr__(self) -> str:
        if not self.ser_name:
            return f"Gateway(input_file={self._input_file})"
        return f"Gateway(port_name={self.ser_name}, port_config={self._port_config})"

    @property
    def hgi(self) -> None | Device:
        """Return the active HGI80-compatible gateway device, if known."""
        if self._transport and (
            device_id := self._transport.get_extra_info(SZ_ACTIVE_HGI)
        ):
            return self.device_by_id.get(device_id)

    async def start(self, /, *, start_discovery: bool = True) -> None:
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

        load_schema(self, **self._schema)

        await super().start()

        if (
            not self._disable_sending
            and not self.config.disable_discovery
            and start_discovery
        ):
            initiate_discovery(self.devices, self.systems)

    async def stop(self) -> None:  # FIXME: a mess
        """Cancel all outstanding high-level tasks."""

        # if self._engine_state is None:
        #     self._pause()

        await super().stop()

        _ = [t.cancel() for t in self._tasks if not t.done()]
        try:  # FIXME: this is broken
            if tasks := (t for t in self._tasks if not t.done()):
                await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass

    def _pause(self, *args) -> None:
        """Pause the (unpaused) gateway (disables sending/discovery).

        There is the option to save other objects, as *args.
        """

        self.config.disable_discovery, disc_flag = True, self.config.disable_discovery

        try:
            super()._pause(disc_flag, *args)
        except RuntimeError:
            self.config.disable_discovery = disc_flag
            raise

    def _resume(self) -> tuple:
        """Resume the (paused) gateway (enables sending/discovery, if applicable).

        Will restore other objects, as *args.
        """

        self.config.disable_discovery, *args = super()._resume()

        return args  # type: ignore[return-value]

    def _clear_state(self) -> None:
        _LOGGER.warning("ENGINE: Clearing exisiting schema/state...")

        self._tcs = None
        self.devices = []
        self.device_by_id = {}

        self._prev_msg = None
        self._this_msg = None

    def get_state(self, include_expired: bool = False) -> tuple[dict, dict]:
        """Return the current schema & state (may include expired packets)."""

        self._pause()
        result = self._get_state(include_expired=include_expired)
        self._resume()

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
            # msgs.extend([m for z in system.dhw for m in z._msgs.values()])  # TODO

        pkts = {  # BUG: assumes pkts have unique dtms: may be untrue for contrived logs
            f"{repr(msg._pkt)[:26]}": f"{repr(msg._pkt)[27:]}"
            for msg in msgs
            if wanted_msg(msg, include_expired=include_expired)
        }

        return self.schema, dict(sorted(pkts.items()))

    async def set_state(
        self, packets: dict, *, schema: dict | None = None, clear_state: bool = True
    ) -> None:
        """Restore a cached schema & state (includes expired packets).

        is schema is None (rather than {}), use the existing schema.
        """

        _LOGGER.warning("ENGINE: Restoring a schema/state...")

        self._pause()

        if clear_state:
            schema = schema or {}
        elif schema is None:  # TODO: also for known_list (device traits)?
            schema = shrink(self.schema)

        if clear_state:
            self._clear_state()

        await self._set_state(packets, schema=schema)

        self._resume()

    async def _set_state(self, packets: dict, *, schema: dict | None = None) -> None:
        tmp_transport: RamsesTransportT  # mypy hint

        if schema:  # TODO: if is None -> make {} & set?
            load_schema(self, **schema)

        tmp_protocol = protocol_factory(self._msg_handler, disable_sending=True)

        tmp_transport = await transport_factory(
            tmp_protocol,
            packet_dict=packets,
            enforce_include_list=self._enforce_known_list,
            exclude_list=self._exclude,
            include_list=self._include,
        )

        await tmp_transport.get_extra_info(tmp_transport.READER_TASK)

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

            if self._enforce_known_list and (
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

        dev = self.device_by_id.get(dev_id)
        if not dev:
            traits = SCH_TRAITS(self._include.get(dev_id, {}))
            dev = device_factory(self, Address(dev_id), msg=msg, **traits)

            if traits.get(SZ_FAKED):
                if isinstance(dev, Fakeable):
                    dev._make_fake()
                else:
                    _LOGGER.warning(f"The device is not fakeable: {dev}")

        # TODO: the exact order of the following may need refining...
        # TODO: some will be done my devices themselves?

        # if schema:  # Step 2: Only controllers have a schema...
        #     dev._update_schema(**schema)  # TODO: schema/traits

        if parent or child_id:
            dev.set_parent(parent, child_id=child_id, is_sensor=is_sensor)

        # if msg:
        #     dev._handle_msg(msg)

        return dev

    @property
    def tcs(self) -> None | System:
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
                if not self._enforce_known_list or d.id in self._include
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
            SZ_CONFIG: {SZ_ENFORCE_KNOWN_LIST: self._enforce_known_list},
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

        if self._enforce_known_list and device_id not in self._include:
            self._include[device_id] = {}
        elif device_id in self._exclude:
            del self._exclude[device_id]

        if (dev := self.get_device(device_id)) and isinstance(dev, Fakeable):
            return dev._make_fake(bind=start_binding)
        raise TypeError(f"The device is not fakable: {device_id}")

    def add_task(self, fnc, *args, delay=None, period=None, **kwargs) -> asyncio.Task:
        """Start a task after delay seconds and then repeat it every period seconds."""
        task = schedule_task(fnc, *args, delay=delay, period=period, **kwargs)
        # keep a track of tasks, so we can tidy-up
        self._tasks = [t for t in self._tasks if not t.done()]
        self._tasks.append(task)
        return task

    def _msg_handler(self, msg: Message) -> None:
        """A callback to handle messages from the protocol stack."""
        # TODO: Remove this
        # # HACK: if CLI, double-logging with client.py proc_msg() & setLevel(DEBUG)
        # if (log_level := _LOGGER.getEffectiveLevel()) < logging.INFO:
        #     _LOGGER.info(msg)
        # elif log_level <= logging.INFO and not (
        #     msg.verb == RQ and msg.src.type == DEV_TYPE_MAP.HGI
        # ):
        #     _LOGGER.info(msg)

        super()._msg_handler(msg)

        # TODO: ideally remove this feature...
        if detect_array_fragment(self._this_msg, self._prev_msg):
            msg._pkt._force_has_array()  # may be an array of length 1
            msg._payload = self._prev_msg.payload + (
                msg.payload if isinstance(msg.payload, list) else [msg.payload]
            )

        process_msg(self, msg)

    def send_cmd(
        self, cmd: Command, callback: Callable = None, **kwargs
    ) -> asyncio.Task:
        """Wrapper to schedule an async_send_cmd() and return the Task."""

        assert kwargs == {}

        # keep a track of tasks, so we can tidy-up
        self._tasks = [t for t in self._tasks if not t.done()]
        self._tasks.append(
            self._loop.create_task(self.async_send_cmd(cmd, callback=callback))
        )

    async def async_send_cmd(
        self,
        cmd: Command,
        max_retries: int = DEFAULT_MAX_RETRIES,
        priority: SendPriority = SendPriority.DEFAULT,
        timeout: float = DEFAULT_TIMEOUT,
        wait_for_reply: None | bool = None,
        **kwargs,
    ) -> None | Packet:
        """Send a Command and, if QoS is enabled, return the corresponding Packet."""

        callback = kwargs.pop("callback", None)
        assert kwargs == {}, kwargs

        try:
            pkt = await super().async_send_cmd(
                cmd,
                max_retries=max_retries,
                priority=priority,
                timeout=timeout,
                wait_for_reply=wait_for_reply,
            )
        except exceptions.ProtocolSendFailed as exc:
            _LOGGER.error(f"Failed to send {cmd._hdr}: {exc}")
            return

        if callback:
            # keep a track of tasks, so we can tidy-up
            self._tasks = [t for t in self._tasks if not t.done()]
            self._tasks.append(self._loop.create_task(callback(pkt)))
        return pkt
