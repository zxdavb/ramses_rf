#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible packet protocol."""
from __future__ import annotations

import asyncio
import logging

# import signal
from collections import deque
from datetime import datetime as dt
from datetime import timedelta as td
from functools import wraps

# from queue import Empty, Full, PriorityQueue, SimpleQueue
from time import perf_counter
from typing import Any, Awaitable, Callable, TypeVar

from .address import HGI_DEV_ADDR  # , NON_DEV_ADDR, NUL_DEV_ADDR
from .command import Command
from .const import __dev_mode__

#     DEV_TYPE,
#     DEV_TYPE_MAP,
#     SZ_DAEMON,
#     SZ_DEVICE_ID,
#     SZ_EXPIRES,
#     SZ_FUNC,
#     SZ_TIMEOUT,
#     __dev_mode__,
# )
from .exceptions import InvalidPacketError
from .helpers import dt_now
from .logger import set_logger_timesource
from .message import Message
from .packet import Packet
from .protocol_fsm import ProtocolContext
from .schemas import SZ_PORT_NAME
from .transport_new import SZ_IS_EVOFW3, PktTransportT
from .transport_new import transport_factory as _transport_factory

# from .version import VERSION

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)


MsgProtocolT = TypeVar("MsgProtocolT", bound="_BaseProtocol")


MIN_GAP_BETWEEN_WRITES = 0.2  # seconds


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class ProtocolError(Exception):
    """Base class for exceptions in this module."""

    pass


_global_sync_cycles: deque = (
    deque()
)  # used by @avoid_system_syncs / @track_system_syncs


def avoid_system_syncs(fnc: Callable[..., Awaitable]):
    """Take measures to avoid Tx when any controller is doing a sync cycle."""

    DURATION_PKT_GAP = 0.020  # 0.0200 for evohome, or 0.0127 for DTS92
    DURATION_LONG_PKT = 0.022  # time to tx I|2309|048 (or 30C9, or 000A)
    DURATION_SYNC_PKT = 0.010  # time to tx I|1F09|003

    SYNC_WAIT_LONG = (DURATION_PKT_GAP + DURATION_LONG_PKT) * 2
    SYNC_WAIT_SHORT = DURATION_SYNC_PKT
    SYNC_WINDOW_LOWER = td(seconds=SYNC_WAIT_SHORT * 0.8)  # could be * 0
    SYNC_WINDOW_UPPER = SYNC_WINDOW_LOWER + td(seconds=SYNC_WAIT_LONG * 1.2)  #

    times_0 = []  # FIXME: remove

    async def wrapper(*args, **kwargs):
        global _global_sync_cycles  # skipcq: PYL-W0602

        def is_imminent(p):
            """Return True if a sync cycle is imminent."""
            return (
                SYNC_WINDOW_LOWER
                < (p.dtm + td(seconds=int(p.payload[2:6], 16) / 10) - dt_now())
                < SYNC_WINDOW_UPPER
            )

        start = perf_counter()  # TODO: remove

        # wait for the start of the sync cycle (I|1F09|003, Tx time ~0.009)
        while any(is_imminent(p) for p in _global_sync_cycles):
            await asyncio.sleep(SYNC_WAIT_SHORT)

        # wait for the remainder of sync cycle (I|2309/30C9) to complete
        if (x := perf_counter() - start) > SYNC_WAIT_SHORT:
            await asyncio.sleep(SYNC_WAIT_LONG)
            # FIXME: remove this block, and merge both ifs
            times_0.append(x)
            _LOGGER.warning(
                f"*** sync cycle stats: {x:.3f}, "
                f"avg: {sum(times_0) / len(times_0):.3f}, "
                f"lower: {min(times_0):.3f}, "
                f"upper: {max(times_0):.3f}, "
                f"times: {[f'{t:.3f}' for t in times_0]}"
            )  # TODO: wrap with if effectiveloglevel

        await fnc(*args, **kwargs)

    return wrapper


def track_system_syncs(fnc: Callable):
    """Track/remember the any new/outstanding TCS sync cycle."""

    MAX_SYNCS_TRACKED = 3

    def wrapper(self, pkt: Packet, *args, **kwargs) -> None:
        global _global_sync_cycles

        def is_pending(p):
            """Return True if a sync cycle is still pending (ignores drift)."""
            return p.dtm + td(seconds=int(p.payload[2:6], 16) / 10) > dt_now()

        if pkt.code != Code._1F09 or pkt.verb != I_ or pkt._len != 3:
            return fnc(self, pkt, *args, **kwargs)

        _global_sync_cycles = deque(
            p for p in _global_sync_cycles if p.src != pkt.src and is_pending(p)
        )
        _global_sync_cycles.append(pkt)  # TODO: sort

        if (
            len(_global_sync_cycles) > MAX_SYNCS_TRACKED
        ):  # safety net for corrupted payloads
            _global_sync_cycles.popleft()

        fnc(self, pkt, *args, **kwargs)

    return wrapper


def limit_duty_cycle(max_duty_cycle: float, time_window: int = 60):
    """Limit the Tx rate to the RF duty cycle regulations (e.g. 1% per hour).

    max_duty_cycle: bandwidth available per observation window (%)
    time_window: duration of the sliding observation window (default 60 seconds)
    """

    TX_RATE_AVAIL: int = 38400  # bits per second (deemed)
    FILL_RATE: float = TX_RATE_AVAIL * max_duty_cycle  # bits per second
    BUCKET_CAPACITY: float = FILL_RATE * time_window

    def decorator(fnc: Callable[..., Awaitable]):
        # start with a full bit bucket
        bits_in_bucket: float = BUCKET_CAPACITY
        last_time_bit_added = perf_counter()

        @wraps(fnc)
        async def wrapper(self, packet: str, *args, **kwargs):
            nonlocal bits_in_bucket
            nonlocal last_time_bit_added

            rf_frame_size = 330 + len(packet[46:]) * 10

            # top-up the bit bucket
            elapsed_time = perf_counter() - last_time_bit_added
            bits_in_bucket = min(
                bits_in_bucket + elapsed_time * FILL_RATE, BUCKET_CAPACITY
            )
            last_time_bit_added = perf_counter()

            # if required, wait for the bit bucket to refill (not for SETs/PUTs)
            if bits_in_bucket < rf_frame_size:
                await asyncio.sleep((rf_frame_size - bits_in_bucket) / FILL_RATE)

            # consume the bits from the bit bucket
            try:
                await fnc(self, packet, *args, **kwargs)  # was return ...
            finally:
                bits_in_bucket -= rf_frame_size

        @wraps(fnc)
        async def null_wrapper(*args, **kwargs) -> Any:
            return await fnc(*args, **kwargs)

        if max_duty_cycle <= 0:
            return null_wrapper

        return wrapper

    return decorator


def limit_transmit_rate(max_tokens: float, time_window: int = 60):
    """Limit the Tx rate as # packets per period of time.

    Rate-limits the decorated function locally, for one process (Token Bucket).

    max_tokens: maximum number of calls of function in time_window
    time_window: duration of the sliding observation window (default 60 seconds)
    """
    # thanks, kudos to: Thomas Meschede, license: MIT
    # see: https://gist.github.com/yeus/dff02dce88c6da9073425b5309f524dd

    token_fill_rate: float = max_tokens / time_window

    def decorator(fnc: Callable):
        token_bucket: float = max_tokens  # initialize with max tokens
        last_time_token_added = perf_counter()

        @wraps(fnc)
        async def wrapper(*args, **kwargs):
            nonlocal token_bucket
            nonlocal last_time_token_added

            # top-up the bit bucket
            elapsed = perf_counter() - last_time_token_added
            token_bucket = min(token_bucket + elapsed * token_fill_rate, max_tokens)
            last_time_token_added = perf_counter()

            # if required, wait for a token (not for SETs/PUTs)
            if token_bucket < 1.0:
                await asyncio.sleep((1 - token_bucket) / token_fill_rate)

            # consume one token for every call
            try:
                await fnc(*args, **kwargs)
            finally:
                token_bucket -= 1.0

        return wrapper

        @wraps(fnc)
        async def null_wrapper(*args, **kwargs) -> Any:
            return await fnc(*args, **kwargs)

        if max_tokens <= 0:
            return null_wrapper

    return decorator


_MsgHandlerT = Callable[[Message], None]
_MsgFilterT = Callable[[Message], bool]


class _BaseProtocol(asyncio.Protocol):
    WRITER_TASK = "writer_task"

    _this_msg: None | Message = None
    _prev_msg: None | Message = None

    def __init__(self, msg_handler: _MsgHandlerT):  # , **kwargs) -> None:
        self._msg_handler = msg_handler
        self._msg_handlers: list[_MsgHandlerT] = []

        self._transport: PktTransportT = None  # type: ignore[assignment]
        self._loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

        self._pause_writing = False

    def add_handler(
        self,
        msg_handler: _MsgHandlerT,
        msg_filter: None | _MsgFilterT = None,
    ) -> Callable[[None], None]:
        """Add a Message handler to the list of such callbacks.

        Returns a callback that can be used to subsequently remove the Message handler.
        """

        def del_handler() -> None:
            if msg_handler in self._msg_handlers:
                self._msg_handlers.remove(msg_handler)

        if msg_handler not in self._msg_handlers:
            self._msg_handlers.append(msg_handler)

        return del_handler

    def connection_made(self, transport: PktTransportT) -> None:
        """Called by the Transport when a connection is made with it.

        The argument is the transport representing the pipe connection. To receive data,
        wait for data_received() calls. When the connection is closed, connection_lost()
        is called.
        """

        self._transport = transport

    def connection_lost(self, exc: None | Exception) -> None:
        """Called when the connection to the Transport is lost or closed.

        The argument is an exception object or None (the latter meaning a regular EOF is
        received or the connection was aborted or closed).
        """

        if exc:
            raise exc

    def pause_writing(self) -> None:
        """Called when the transport's buffer goes over the high-water mark.

        Pause and resume calls are paired -- pause_writing() is called once when the
        buffer goes strictly over the high-water mark (even if subsequent writes
        increases the buffer size even more), and eventually resume_writing() is called
        once when the buffer size reaches the low-water mark.

        Note that if the buffer size equals the high-water mark, pause_writing() is not
        called -- it must go strictly over. Conversely, resume_writing() is called when
        the buffer size is equal or lower than the low-water mark.  These end conditions
        are important to ensure that things go as expected when either mark is zero.

        NOTE: This is the only Protocol callback that is not called through
        EventLoop.call_soon() -- if it were, it would have no effect when it's most
        needed (when the app keeps writing without yielding until pause_writing() is
        called).
        """

        self._pause_writing = True

    def resume_writing(self) -> None:
        """Called when the transport's buffer drains below the low-water mark.

        See pause_writing() for details.
        """

        self._pause_writing = False

    # NOTE: wrapper for _send_cmd(cmd)
    async def send_data(self, cmd: Command, callback: None | Callable = None) -> None:
        """A wrapper for self._send_cmd(cmd)."""

        if not self._transport:
            raise RuntimeError  # TODO
        if self._pause_writing:
            raise RuntimeError  # TODO

        # This is necessary to track state via the context.
        await self._send_cmd(cmd)  # self._transport.write(...)

    async def _send_cmd(self, cmd: Command) -> None:
        """Called when a Command is to be sent to the Transport.

        The Protocol must be given a Command (not bytes).
        """
        await self._send_bytes(bytes(str(cmd), "ascii") + b"\r\n")

    async def _send_bytes(self, data: bytes) -> None:
        """Write some bytes to the transport."""
        self._transport.write(data)

    # NOTE: wrapper for _pkt_received(pkt)
    def data_received(self, pkt: Packet) -> None:
        """A wrapper for self._pkt_received(pkt)."""
        self._pkt_received(pkt)

    def _pkt_received(self, pkt: Packet) -> None:
        """Called by the Transport when a Packet is received."""
        try:
            msg = Message(pkt)  # should log all invalid msgs appropriately
        except InvalidPacketError:  # TODO: InvalidMessageError (packet is valid)
            return

        self._this_msg, self._prev_msg = msg, self._this_msg
        self._msg_received(msg)

    def _msg_received(self, msg: Message) -> None:
        """Pass any valid/wanted Messages to the client's callback.

        Also maintain _prev_msg, _this_msg attrs.
        """

        self._loop.call_soon(self._msg_handler, msg)  # to the internal state machine
        for callback in self._msg_handlers:
            # TODO: if it's filter returns True:
            self._loop.call_soon(callback, msg)

    def eof_received(self) -> None:
        raise NotImplementedError

    def error_received(self, exc) -> None:
        """Called when a send or receive operation raises an OSError.

        (Other than BlockingIOError or InterruptedError.)
        """
        raise NotImplementedError


class _ProtImpersonate(_BaseProtocol):  # warn of impersonation
    """A mixin for warning that impersonation is being performed."""

    _is_evofw3: None | bool = None

    def connection_made(self, transport: PktTransportT) -> None:
        super().connection_made(transport)
        self._is_evofw3 = self._transport.get_extra_info(SZ_IS_EVOFW3)

    async def _send_impersonation_alert(self, cmd: Command) -> None:
        """Send an puzzle packet warning that impersonation is occurring."""

        msg = f"Impersonating device: {cmd.src}, for pkt: {cmd.tx_header}"
        if self._is_evofw3:
            _LOGGER.info(msg)
        else:
            _LOGGER.warning(f"{msg}, NB: non-evofw3 gateways can't impersonate!")

        await self._send_cmd(Command._puzzle(msg_type="11", message=cmd.tx_header))

    async def send_data(self, cmd: Command, callback: Callable = None) -> None:
        """Write some data bytes to the transport."""
        if cmd.src.id != HGI_DEV_ADDR.id:
            await self._send_impersonation_alert(cmd)

        await self._send_cmd(cmd)


class _ProtQosTimers(_BaseProtocol):  # context/state
    """A mixin for maintaining state via a FSM."""

    def __init__(self, msg_handler: _MsgHandlerT) -> None:
        super().__init__(msg_handler)

        self._context = ProtocolContext()

    def connection_made(self, transport: PktTransportT) -> Any:
        self._context.connection_made(transport)
        return super().connection_made(transport)

    def connection_lost(self, exc: None | Exception) -> Any:
        self._context.connection_lost(exc)
        return super().connection_lost(exc)

    def _pkt_received(self, pkt: Packet) -> Any:
        self._context._pkt_received(pkt)
        return super()._pkt_received(pkt)

    async def send_cmd(self, cmd: Command) -> Any:
        self._context.send_cmd(cmd)
        return await super().send_cmd(cmd)


class _ProtSyncCycle(_BaseProtocol):  # avoid sync cycles
    """A mixin for avoiding sync cycles."""

    @track_system_syncs
    def data_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted packets to the callback."""
        super().data_received(pkt)

    @avoid_system_syncs
    # @limit_duty_cycle(0.01)  # @limit_transmit_rate(45)
    async def _send_bytes(self, data: bytes) -> None:
        """Write some data bytes to the transport."""
        await super()._send_bytes(data)


class _ProtDutyCycle(_BaseProtocol):  # stay within duty cycle limits
    """A mixin for staying within duty cycle limits."""

    @limit_duty_cycle(0.01)  # @limit_transmit_rate(45)
    async def _send_bytes(self, cmd: Command) -> None:
        """Write some data bytes to the transport."""
        await super()._send_bytes(cmd)


class _ProtGapped(_BaseProtocol):  # minimum gap between writes
    """A mixin for enforcing a minimum gap between writes."""

    def __init__(self, msg_handler: _MsgHandlerT) -> None:
        super().__init__(msg_handler)

        self._leaker_sem = asyncio.BoundedSemaphore()
        self._leaker_task = None

    async def _leak_sem(self) -> None:
        """Used to enforce a minimum time between calls to self._transport.write()."""
        while True:
            await asyncio.sleep(MIN_GAP_BETWEEN_WRITES)
            try:
                self._leaker_sem.release()
            except ValueError:
                pass

    def connection_made(self, transport: PktTransportT) -> None:  # type: ignore[override]
        """Called when a connection is made."""
        super().connection_made(transport)

        if not self._leaker_task:
            self._leaker_task = self._loop.create_task(self._leak_sem())

    def connection_lost(self, exc: None | Exception) -> None:
        """Called when the connection is lost or closed."""
        if self._leaker_task:
            self._leaker_task.cancel()

        super().connection_lost(exc)

    async def _send_bytes(self, cmd: Command) -> None:
        """Write some data bytes to the transport."""
        await self._leaker_sem.acquire()  # asyncio.sleep() a minimum time between Tx

        await super()._send_bytes(cmd)


# NOTE: MRO: Impersonate -> Gapped/DutyCycle -> SyncCycle -> Context -> Base
# Impersonate first, as the Puzzle Packet needs to be sent before the Command
# Order of DutyCycle/Gapped doesn't matter, but both before SyncCycle
# QosTimers last, to start any timers immediately after Tx of Command


# ### Read-Only Protocol for FileTransport ############################################
class ReadProtocol(_BaseProtocol):
    """A protocol that can only receive Packets."""

    def __init__(self, msg_handler: _MsgHandlerT) -> None:
        super().__init__(msg_handler)

        self._pause_writing = True

    def resume_writing(self) -> None:
        raise NotImplementedError

    # TODO: remove me (a convenience wrapper for breakpoint)
    def connection_made(self, transport: PktTransportT) -> None:
        super().connection_made(transport)

    # TODO: remove me (a convenience wrapper for breakpoint)
    def data_received(self, data) -> None:
        super().data_received(data)

    async def send_data(self, cmd: Command, callback: Callable = None) -> None:
        raise NotImplementedError

    # TODO: remove me (a convenience wrapper for breakpoint)
    def connection_lost(self, exc) -> None:
        super().connection_lost(exc)


# ### Read-Write Protocol for PortTransport ###########################################
class PortProtocol(_ProtImpersonate, _ProtGapped, _ProtDutyCycle, _ProtSyncCycle):
    """A protocol that can receive Packets and send Commands."""

    # TODO: remove me (a convenience wrapper for breakpoint)
    def data_received(self, data) -> None:
        super().data_received(data)

    # TODO: remove me (a convenience wrapper for breakpoint)
    async def send_data(self, cmd: Command, **kwargs) -> Any:
        return await super().send_data(cmd, **kwargs)


# ### Read-Write Protocol for QosTransport ############################################
class QosProtocol(PortProtocol, _ProtQosTimers):
    """A protocol that can receive Packets and send Commands with QoS."""

    _expecting_cmd: None | Command = None

    def _msg_received(self, msg: Message) -> None:
        """Check if Message this is the expected response (if any)."""

        if not self._expecting_cmd:
            pass

        #     if cmd._cbk:
        #         self._expecting_cmd = cmd

        elif self._expecting_cmd.callback.expires <= dt.now():
            if self._expecting_cmd.callback.retries == 0:
                self._expecting_cmd.callback.callback(None, cmd=self._expecting_cmd)
                self._expecting_cmd = None
            else:
                self._expecting_cmd.callback.retries -= 1
                self._expecting_cmd.callback.expires = dt.now()  # FIXME: + ???

        elif self._expecting_cmd._hdr == msg._pkt._hdr:  # TODO
            self._expecting_cmd.callback.callback(msg, cmd=self._expecting_cmd)
            self._expecting_cmd = None

        super()._msg_received(msg)

    async def _send_cmd(self, cmd: Command) -> None:
        """Check if this Command is expecting a response."""

        if self._expecting_cmd:
            raise  # should have cleared / expired any outstanding echo/callbacks

        # we're sending a cmd, so should expect an echo
        # self._context.send_cmd(cmd)

        await super()._send_cmd(cmd)

    # TODO: remove me (a convenience wrapper for breakpoint)
    def data_received(self, data) -> None:
        super().data_received(data)

    # TODO: remove me (a convenience wrapper for breakpoint)
    async def send_data(self, cmd: Command, **kwargs) -> Any:
        return await super().send_data(cmd, **kwargs)


def protocol_factory(  # TODO: no_qos default should be None
    msg_handler: _MsgHandlerT, /, *, read_only: bool = None, disable_qos: bool = None
) -> MsgProtocolT:
    if read_only:
        return ReadProtocol(msg_handler)
    if disable_qos:
        return PortProtocol(msg_handler)
    return QosProtocol(msg_handler)


def create_stack(
    msg_handler: Callable[[Message, None | Message], None],
    /,
    *,
    protocol_factory: Callable = None,
    transport_factory: Callable = None,
    **kwargs,
) -> tuple[MsgProtocolT, PktTransportT]:
    """Utility function to provide a Protocol / Transport pair.

    Architecture: gwy (client) -> msg (Protocol) -> pkt (Transport) -> HGI/log (or dict)
    - send Commands via Protocol.send_cmd(cmd)
    - receive Messages via Gateway._handle_msg(msg)
    """

    KEYS = ("disable_sending", "packet_dict", "packet_log")

    if protocol_factory:
        protocol = protocol_factory(msg_handler, **kwargs)
    else:
        protocol = protocol_factory(
            msg_handler,
            read_only=any([bool(kwargs.get(k)) for k in KEYS]),
        )

    transport = (transport_factory or _transport_factory)(protocol, **kwargs)

    if not kwargs.get(SZ_PORT_NAME):
        set_logger_timesource(transport._dt_now)
        _LOGGER.error("Datetimes maintained as most recent packet log timestamp")

    return protocol, transport
