#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

# TODO:
# - self._tasks is not ThreadSafe


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
from typing import TYPE_CHECKING, Any

from .address import ALL_DEV_ADDR, HGI_DEV_ADDR, NON_DEV_ADDR
from .command import Command
from .const import (
    DEFAULT_GAP_DURATION,
    DEFAULT_MAX_RETRIES,
    DEFAULT_NUM_REPEATS,
    DEFAULT_TIMEOUT,
    Priority,
)
from .message import Message
from .packet import Packet
from .protocol import QosParams, protocol_factory
from .schemas import (
    SZ_DISABLE_QOS,
    SZ_DISABLE_SENDING,
    SZ_ENFORCE_KNOWN_LIST,
    SZ_PACKET_LOG,
    SZ_PORT_CONFIG,
    SZ_PORT_NAME,
    select_device_filter_mode,
)
from .transport import SZ_ACTIVE_HGI, is_hgi80, transport_factory

from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:
    from .const import VerbT
    from .frame import DeviceIdT, PayloadT
    from .protocol import RamsesProtocolT, RamsesTransportT

_MsgHandlerT = Callable[[Message], None]


DEV_MODE = False

_LOGGER = logging.getLogger(__name__)


class Engine:
    """The engine class."""

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
        elif port_name:
            is_hgi80(port_name)  # raise an exception if the port is not found
        else:
            raise TypeError("Either a port_name or a input_file must be specified")

        self.ser_name = port_name
        self._input_file = input_file

        self._port_config = port_config or {}
        self._packet_log = packet_log or {}
        self._loop = loop or asyncio.get_running_loop()

        self._exclude: dict[DeviceIdT, dict] = block_list or {}
        self._include: dict[DeviceIdT, dict] = known_list or {}
        self._unwanted: list[DeviceIdT] = [
            NON_DEV_ADDR.id,
            ALL_DEV_ADDR.id,
            "01:000001",  # why this one?
        ]
        self._enforce_known_list = select_device_filter_mode(
            kwargs.pop(SZ_ENFORCE_KNOWN_LIST, None),
            self._include,
            self._exclude,
        )
        self._kwargs: dict[str, Any] = kwargs  # HACK

        self._engine_lock = Lock()
        self._engine_state: tuple[Callable | None, tuple] | None = None

        self._protocol: RamsesProtocolT = None  # type: ignore[assignment]
        self._transport: RamsesTransportT | None = None  # None until self.start()

        self._prev_msg: Message | None = None
        self._this_msg: Message | None = None

        self._tasks: list[asyncio.Task] = []

        self._set_msg_handler(self._msg_handler)  # sets self._protocol

    def __str__(self) -> str:
        if not self._transport:
            return f"{HGI_DEV_ADDR.id} ({self.ser_name})"

        device_id = self._transport.get_extra_info(
            SZ_ACTIVE_HGI, default=HGI_DEV_ADDR.id
        )
        return f"{device_id} ({self.ser_name})"

    def _dt_now(self):
        return self._transport._dt_now() if self._transport else dt.now()

    def _set_msg_handler(self, msg_handler: _MsgHandlerT) -> None:
        """Create an appropriate protocol for the packet source (transport).

        The corresponding transport will be created later.
        """

        self._protocol = protocol_factory(
            msg_handler,
            disable_sending=self._disable_sending,
            disable_qos=self._kwargs.get(SZ_DISABLE_QOS, False),
        )

    def add_msg_handler(
        self,
        msg_handler: Callable[[Message], None],
        /,
        msg_filter: Callable[[Message], bool] | None = None,
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

        pkt_source: dict[str, Any] = {}  # [str, dict | str | TextIO]
        if self.ser_name:
            pkt_source[SZ_PORT_NAME] = self.ser_name
            pkt_source[SZ_PORT_CONFIG] = self._port_config
        else:  # if self._input_file:
            pkt_source[SZ_PACKET_LOG] = self._input_file  # io.TextIOWrapper

        self._transport = await transport_factory(
            self._protocol,
            disable_sending=self._disable_sending,
            enforce_include_list=self._enforce_known_list,
            exclude_list=self._exclude,
            include_list=self._include,
            loop=self._loop,
            **pkt_source,
            **self._kwargs,  # HACK: only accept disable_qos, extra & one other
        )

        self._kwargs = {}  # HACK

        if self._input_file:
            await self._wait_for_protocol_to_stop()

    async def stop(self) -> None:
        """Close the transport (will stop the protocol)."""

        async def cancel_all_tasks() -> None:  # TODO: needs a lock?
            _ = [t.cancel() for t in self._tasks if not t.done()]
            try:  # FIXME: this is broken
                if tasks := (t for t in self._tasks if not t.done()):
                    await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                pass

        await cancel_all_tasks()

        if self._transport:
            self._transport.close()
        elif (
            self._protocol.wait_connection_lost
            and not self._protocol.wait_connection_lost.done()
        ):
            # the transport was never started
            self._protocol.connection_lost(None)

        await self._wait_for_protocol_to_stop()

        return None

    async def _wait_for_protocol_to_stop(self) -> None:
        await self._protocol.wait_connection_lost
        self._protocol.wait_connection_lost.result()  # may raise an exception
        return

    def _pause(self, *args) -> None:
        """Pause the (active) engine or raise a RuntimeError."""

        if not self._engine_lock.acquire(blocking=False):
            raise RuntimeError("Unable to pause engine, failed to acquire lock")

        if self._engine_state is not None:
            self._engine_lock.release()
            raise RuntimeError("Unable to pause engine, it is already paused")

        self._engine_state = (None, tuple())  # aka not None
        self._engine_lock.release()  # is ok to release now

        self._protocol.pause_writing()  # TODO: call_soon()?
        if self._transport:
            self._transport.pause_reading()  # TODO: call_soon()?

        self._protocol._msg_handler, handler = None, self._protocol._msg_handler  # type: ignore[assignment]
        self._disable_sending, read_only = True, self._disable_sending

        self._engine_state = (handler, read_only, *args)

    def _resume(self) -> tuple:  # FIXME: not atomic
        """Resume the (paused) engine or raise a RuntimeError."""

        args: tuple  # mypy

        if not self._engine_lock.acquire(timeout=0.1):
            raise RuntimeError("Unable to resume engine, failed to acquire lock")

        if self._engine_state is None:
            self._engine_lock.release()
            raise RuntimeError("Unable to resume engine, it was not paused")

        self._protocol._msg_handler, self._disable_sending, *args = self._engine_state  # type: ignore[assignment]
        self._engine_lock.release()

        if self._transport:
            self._transport.resume_reading()
        if not self._disable_sending:
            self._protocol.resume_writing()

        self._engine_state = None

        return args

    def add_task(self, task: asyncio.Task) -> None:  # TODO: needs a lock?
        # keep a track of tasks, so we can tidy-up
        self._tasks = [t for t in self._tasks if not t.done()]
        self._tasks.append(task)

    @staticmethod
    def create_cmd(
        verb: VerbT, device_id: DeviceIdT, code: Code, payload: PayloadT, **kwargs
    ) -> Command:
        """Make a command addressed to device_id."""

        if [
            k for k in kwargs if k not in ("from_id", "seqn")
        ]:  # FIXME: deprecate QoS in kwargs
            raise RuntimeError("Deprecated kwargs: %s", kwargs)

        return Command.from_attrs(verb, device_id, code, payload, **kwargs)

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
    ) -> Packet | None:
        """Send a Command and, if QoS is enabled, return the corresponding Packet.

        If wait_for_reply is None, then it acts as True for 1FC9, 0006, etc.
        """

        qos = QosParams(
            max_retries=max_retries,
            timeout=timeout,
            wait_for_reply=wait_for_reply,
        )

        return await self._protocol.send_cmd(
            cmd,
            gap_duration=gap_duration,
            num_repeats=num_repeats,
            priority=priority,
            qos=qos,
        )

    def _msg_handler(self, msg: Message) -> None:
        # HACK: This is one consequence of an unpleaseant anachronism
        msg.__class__ = Message  # HACK (next line too)
        msg._gwy = self  # type: ignore[assignment]

        self._this_msg, self._prev_msg = msg, self._this_msg
