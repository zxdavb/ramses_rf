#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

# TODO:
# - sort out gwy.config...
# - sort out reduced processing


"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

The serial to RF gateway (HGI80, not RFG100).
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from io import TextIOWrapper
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from ramses_tx import (
    Address,
    Command,
    Engine,
    Packet,
    Priority,
    exceptions as exc,
    is_valid_dev_id,
    protocol_factory,
    set_pkt_logging_config,
    transport_factory,
)
from ramses_tx.const import (
    DEFAULT_GAP_DURATION,
    DEFAULT_MAX_RETRIES,
    DEFAULT_NUM_REPEATS,
    DEFAULT_TIMEOUT,
    SZ_ACTIVE_HGI,
)
from ramses_tx.schemas import (
    SCH_ENGINE_CONFIG,
    SZ_BLOCK_LIST,
    SZ_ENFORCE_KNOWN_LIST,
    SZ_KNOWN_LIST,
)

from .const import DONT_CREATE_MESSAGES, SZ_DEVICES
from .device import DeviceHeat, DeviceHvac, Fakeable, device_factory
from .dispatcher import Message, detect_array_fragment, process_msg
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

from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:
    from ramses_tx.frame import DeviceIdT
    from ramses_tx.protocol import RamsesTransportT

    from .device import Device

_MsgHandlerT = Callable[[Message], None]


_LOGGER = logging.getLogger(__name__)


class Gateway(Engine):
    """The gateway class."""

    def __init__(
        self,
        port_name: str | None,
        input_file: TextIOWrapper | None = None,
        port_config: dict | None = None,
        packet_log: dict | None = None,
        block_list: dict | None = None,
        known_list: dict | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
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

        set_pkt_logging_config(
            cc_console=self.config.reduce_processing >= DONT_CREATE_MESSAGES,
            **self._packet_log,
        )

        # if self.config.reduce_processing < DONT_CREATE_MESSAGES:
        # if self.config.reduce_processing > 0:
        self._tcs: System | None = None
        self.devices: list[Device] = []
        self.device_by_id: dict[str, Device] = {}

    def __repr__(self) -> str:
        if not self.ser_name:
            return f"Gateway(input_file={self._input_file})"
        return f"Gateway(port_name={self.ser_name}, port_config={self._port_config})"

    @property
    def hgi(self) -> Device | None:
        """Return the active HGI80-compatible gateway device, if known."""
        if self._transport and (
            device_id := self._transport.get_extra_info(SZ_ACTIVE_HGI)
        ):
            return self.device_by_id.get(device_id)
        return None

    async def start(
        self, /, *, start_discovery: bool = True, cached_packets: dict | None = None
    ) -> None:
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

        self.config.disable_discovery, disable_discovery = (
            True,
            self.config.disable_discovery,
        )

        load_schema(self, known_list=self._include, **self._schema)  # create faked too

        await super().start()  # TODO: do this *after* restore cache
        if cached_packets:
            await self._restore_cached_packets(cached_packets)

        self.config.disable_discovery = disable_discovery

        if (
            not self._disable_sending
            and not self.config.disable_discovery
            and start_discovery
        ):
            initiate_discovery(self.devices, self.systems)

    def _pause(self, *args) -> None:
        """Pause the (unpaused) gateway (disables sending/discovery).

        There is the option to save other objects, as *args.
        """
        _LOGGER.debug("Gateway: Pausing engine...")

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
        _LOGGER.debug("Gateway: Resuming engine...")

        self.config.disable_discovery, *args = super()._resume()

        return args  # type: ignore[return-value]

    def get_state(self, include_expired: bool = False) -> tuple[dict, dict]:
        """Return the current schema & state (may include expired packets)."""

        self._pause()

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

        self._resume()

        return self.schema, dict(sorted(pkts.items()))

    async def _restore_cached_packets(
        self, packets: dict[str, str], _clear_state: bool = False
    ) -> None:
        """Restore cached packets (may include expired packets)."""

        def clear_state() -> None:
            _LOGGER.info("GATEWAY: Clearing existing schema/state...")

            # self._schema = {}

            self._tcs = None
            self.devices = []
            self.device_by_id = {}

            self._prev_msg = None
            self._this_msg = None

        tmp_transport: RamsesTransportT  # mypy hint

        _LOGGER.warning("GATEWAY: Restoring a cached packet log...")
        self._pause()

        if _clear_state:  # only intended for test suite use
            clear_state()

        tmp_protocol = protocol_factory(self._msg_handler, disable_sending=True)

        tmp_transport = await transport_factory(
            tmp_protocol,
            packet_dict=packets,
            enforce_include_list=self._enforce_known_list,
            exclude_list=self._exclude,
            include_list=self._include,
        )

        await tmp_transport.get_extra_info(tmp_transport.READER_TASK)

        _LOGGER.warning("GATEWAY: Restored, resuming")
        self._resume()

    def get_device(
        self,
        device_id: DeviceIdT,
        *,
        msg: Message | None = None,
        parent=None,
        child_id=None,
        is_sensor: bool | None = None,
    ) -> Device:  # TODO: **schema/traits) -> Device:  # may: LookupError
        """Return a device, create it if required.

        First, use the traits to create/update it, then pass it any msg to handle.
        All devices have traits, but only controllers (CTL, UFC) have a schema.

        Devices are uniquely identified by a device id.
        If a device is created, attach it to the gateway.
        """

        def check_filter_lists(dev_id: DeviceIdT) -> None:  # may: LookupError
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

        try:
            check_filter_lists(device_id)
        except LookupError:
            # have to allow for GWY not being in known_list...
            if device_id != self._protocol.hgi_id:
                raise  # TODO: make parochial

        dev = self.device_by_id.get(device_id)

        if not dev:
            traits: dict = SCH_TRAITS(self._include.get(device_id, {}))

            dev = device_factory(self, Address(device_id), msg=msg, **traits)

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

    def fake_device(
        self,
        device_id: DeviceIdT,
        create_device: bool = False,
    ) -> Device:
        """Create a faked device."""

        if not is_valid_dev_id(device_id):
            raise TypeError(f"The device id is not valid: {device_id}")

        if not create_device and device_id not in self.device_by_id:
            raise LookupError(f"The device id does not exist: {device_id}")
        elif create_device and device_id not in self.known_list:
            raise LookupError(f"The device id is not in the known_list: {device_id}")

        if (dev := self.get_device(device_id)) and isinstance(dev, Fakeable):
            dev._make_fake()
            return dev

        raise TypeError(f"The device is not fakable: {device_id}")

    @property
    def tcs(self) -> System | None:
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
            "_unwanted": sorted(self._unwanted),
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
        assert self._this_msg  # mypy check

        if self._prev_msg and detect_array_fragment(self._this_msg, self._prev_msg):
            msg._pkt._force_has_array()  # may be an array of length 1
            msg._payload = self._prev_msg.payload + (
                msg.payload if isinstance(msg.payload, list) else [msg.payload]
            )

        process_msg(self, msg)

    def send_cmd(
        self,
        cmd: Command,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        callback: Callable | None = None,
    ) -> asyncio.Task:
        """Wrapper to schedule an async_send_cmd() and return the Task.

        num_repeats:  0 = send once, 1 = send twice, etc.
        gap_duration: the gap between repeats (in seconds)
        priority:     the priority of the command
        callback:     a callback to run when the command is sent (needs QoS)
        """

        coro = self.async_send_cmd(
            cmd,
            gap_duration=gap_duration,
            num_repeats=num_repeats,
            priority=priority,
            callback=callback,
        )

        task = self._loop.create_task(coro)
        self.add_task(task)
        return task

    async def async_send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        max_retries: int = DEFAULT_MAX_RETRIES,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        timeout: float = DEFAULT_TIMEOUT,
        wait_for_reply: bool | None = None,
        **kwargs: Any,
    ) -> Packet | None:
        """Send a Command and, if QoS is enabled, return the corresponding Packet."""

        callback = kwargs.pop("callback", None)  # warn if no Qos
        assert not kwargs, kwargs

        # if callback and self._protocol. disable_qos is not False:
        #     raise

        try:  # TODO: remove this try/except
            pkt = await super().async_send_cmd(
                cmd,
                gap_duration=gap_duration,
                max_retries=max_retries,
                num_repeats=num_repeats,
                priority=priority,
                timeout=timeout,
                wait_for_reply=wait_for_reply,
            )
        except exc.ProtocolSendFailed as err:
            _LOGGER.error(f"Failed to send {cmd._hdr}: {err}")
            return None

        if callback:
            self.add_task(self._loop.create_task(callback(pkt)))

        return pkt
