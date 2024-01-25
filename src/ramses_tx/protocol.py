#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible packet protocol."""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import timedelta as td
from functools import wraps
from time import perf_counter
from typing import TYPE_CHECKING, Any, Final

from . import exceptions as exc
from .address import HGI_DEV_ADDR  # , NON_DEV_ADDR, NUL_DEV_ADDR
from .command import Command
from .const import (
    DEFAULT_GAP_DURATION,
    DEFAULT_NUM_REPEATS,
    MINIMUM_GAP_DURATION,
    SZ_ACTIVE_HGI,
    SZ_IS_EVOFW3,
    SZ_KNOWN_HGI,
    Priority,
)
from .helpers import dt_now
from .logger import set_logger_timesource
from .message import Message
from .packet import Packet
from .protocol_fsm import (
    ProtocolContext,
)
from .schemas import SZ_PORT_NAME
from .transport import transport_factory
from .typing import (
    ExceptionT,
    MsgFilterT,
    MsgHandlerT,
    QosParams,
)

from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:
    from .address import DeviceIdT
    from .transport import RamsesTransportT


_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.WARNING)

# all debug flags should be False for published code
_DBG_DISABLE_DUTY_CYCLE_LIMIT: Final[bool] = False
_DBG_DISABLE_IMPERSONATION_ALERTS: Final[bool] = False
_DBG_DISABLE_QOS: Final[bool] = False
_DBG_FORCE_LOG_PACKETS: Final[bool] = False

# other constants
_GAP_BETWEEN_WRITES: Final[float] = MINIMUM_GAP_DURATION

_MAX_DUTY_CYCLE = 0.01  # % bandwidth used per cycle (default 60 secs)
_MAX_TOKENS = 45  # number of Tx per cycle (default 60 secs)
_CYCLE_DURATION = 60  # seconds


_global_sync_cycles: deque = deque()  # used by @avoid_system_syncs/@track_system_syncs


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
        global _global_sync_cycles

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


def track_system_syncs(fnc: Callable[[Any, Packet], None]):
    """Track/remember the any new/outstanding TCS sync cycle."""

    MAX_SYNCS_TRACKED = 3

    def wrapper(self, pkt: Packet) -> None:
        global _global_sync_cycles

        def is_pending(p: Packet) -> bool:
            """Return True if a sync cycle is still pending (ignores drift)."""
            return bool(p.dtm + td(seconds=int(p.payload[2:6], 16) / 10) > dt_now())

        if pkt.code != Code._1F09 or pkt.verb != I_ or pkt._len != 3:
            fnc(self, pkt)
            return None

        _global_sync_cycles = deque(
            p for p in _global_sync_cycles if p.src != pkt.src and is_pending(p)
        )
        _global_sync_cycles.append(pkt)  # TODO: sort

        if (
            len(_global_sync_cycles) > MAX_SYNCS_TRACKED
        ):  # safety net for corrupted payloads
            _global_sync_cycles.popleft()

        fnc(self, pkt)
        return None

    return wrapper


def limit_duty_cycle(max_duty_cycle: float, time_window: int = _CYCLE_DURATION):
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
        async def wrapper(self, frame: str, *args, **kwargs) -> None:
            nonlocal bits_in_bucket
            nonlocal last_time_bit_added

            rf_frame_size = 330 + len(frame[46:]) * 10

            # top-up the bit bucket
            elapsed_time = perf_counter() - last_time_bit_added
            bits_in_bucket = min(
                bits_in_bucket + elapsed_time * FILL_RATE, BUCKET_CAPACITY
            )
            last_time_bit_added = perf_counter()

            if _DBG_DISABLE_DUTY_CYCLE_LIMIT:
                bits_in_bucket = BUCKET_CAPACITY

            # if required, wait for the bit bucket to refill (not for SETs/PUTs)
            if bits_in_bucket < rf_frame_size:
                await asyncio.sleep((rf_frame_size - bits_in_bucket) / FILL_RATE)

            # consume the bits from the bit bucket
            try:
                await fnc(self, frame, *args, **kwargs)
            finally:
                bits_in_bucket -= rf_frame_size

        @wraps(fnc)
        async def null_wrapper(self, frame: str, *args, **kwargs) -> None:
            await fnc(self, frame, *args, **kwargs)

        if 0 < max_duty_cycle <= 1:
            return wrapper

        return null_wrapper

    return decorator


def limit_transmit_rate(max_tokens: float, time_window: int = _CYCLE_DURATION):
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

        @wraps(fnc)  # type: ignore[unreachable]
        async def null_wrapper(*args, **kwargs) -> Any:
            return await fnc(*args, **kwargs)

        if max_tokens <= 0:
            return null_wrapper

    return decorator


# send_cmd(), _send_cmd(), _send_frame()
class _BaseProtocol(asyncio.Protocol):
    """Base class for RAMSES II protocols."""

    WRITER_TASK = "writer_task"

    _this_msg: None | Message = None
    _prev_msg: None | Message = None

    def __init__(self, msg_handler: MsgHandlerT):  # , **kwargs) -> None:
        self._msg_handler = msg_handler
        self._msg_handlers: list[MsgHandlerT] = []

        self._transport: RamsesTransportT = None  # type: ignore[assignment]
        self._loop = asyncio.get_running_loop()

        # FIXME: Should start in read-only mode as no connection yet
        self._pause_writing = False
        self._wait_connection_lost = self._loop.create_future()

    @property
    def hgi_id(self) -> DeviceIdT:
        if not self._transport:
            return HGI_DEV_ADDR.id  # better: known_hgi or HGI_DEV_ADDR.id?
        hgi_id: DeviceIdT | None = self._transport.get_extra_info(SZ_ACTIVE_HGI)
        if hgi_id is not None:
            return hgi_id
        return self._transport.get_extra_info(SZ_KNOWN_HGI, HGI_DEV_ADDR.id)  # type: ignore[no-any-return]

    def add_handler(
        self,
        msg_handler: MsgHandlerT,
        /,
        *,
        msg_filter: None | MsgFilterT = None,
    ) -> Callable[[], None]:
        """Add a Message handler to the list of such callbacks.

        Returns a callback that can be used to subsequently remove the Message handler.
        """

        def del_handler() -> None:
            if msg_handler in self._msg_handlers:
                self._msg_handlers.remove(msg_handler)

        if msg_handler not in self._msg_handlers:
            self._msg_handlers.append(msg_handler)

        return del_handler

    def connection_made(self, transport: RamsesTransportT) -> None:  # type: ignore[override]
        """Called when the connection to the Transport is established.

        The argument is the transport representing the pipe connection. To receive data,
        wait for pkt_received() calls. When the connection is closed, connection_lost()
        is called.
        """

        self._transport = transport

    def connection_lost(self, err: ExceptionT | None) -> None:  # type: ignore[override]
        """Called when the connection to the Transport is lost or closed.

        The argument is an exception object or None (the latter meaning a regular EOF is
        received or the connection was aborted or closed).
        """

        if self._wait_connection_lost.done():  # BUG: why is callback invoked twice?
            return

        if err:
            self._wait_connection_lost.set_exception(err)
        else:
            self._wait_connection_lost.set_result(None)

    @property
    def wait_connection_lost(self) -> asyncio.Future:
        """Return a future that will block until connection_lost() has been invoked.

        Can call fut.result() to check for result/any exception.
        """
        return self._wait_connection_lost

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

    async def send_cmd(  # send_cmd() -> _send_cmd()
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:
        """This is the wrapper for self._send_cmd(cmd)."""

        if _DBG_FORCE_LOG_PACKETS:
            _LOGGER.warning(f"QUEUED:     {cmd}")
        else:
            _LOGGER.debug(f"QUEUED:     {cmd}")

        # if not self._transport:
        #     raise exc.ProtocolSendFailed("There is no connected Transport")
        if self._pause_writing:
            raise exc.ProtocolSendFailed("The Protocol is currently read-only")

        return await self._send_cmd(
            cmd,
            gap_duration=gap_duration,
            num_repeats=num_repeats,
            priority=priority,
            qos=qos,
        )

    async def _send_cmd(  # _send_cmd() *-> _send_frame()
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:  # only cmd, no args, kwargs
        """This is the wrapper for self._send_frame(cmd), with repeats.

        Repeats are distinct from retries (a QoS feature): you wouldn't have both.
        """

        await self._send_frame(str(cmd))
        for _ in range(num_repeats - 1):
            await asyncio.sleep(gap_duration)
            await self._send_frame(str(cmd))

        return None

    async def _send_frame(self, frame: str) -> None:  # _send_frame() -> transport
        """Write some bytes to the transport."""
        self._transport.send_frame(frame)

    def pkt_received(self, pkt: Packet) -> None:
        """A wrapper for self._pkt_received(pkt)."""
        if _DBG_FORCE_LOG_PACKETS:
            _LOGGER.warning(f"Recv'd: {pkt._rssi} {pkt}")
        elif _LOGGER.getEffectiveLevel() > logging.DEBUG:
            _LOGGER.info(f"Recv'd: {pkt._rssi} {pkt}")
        else:
            _LOGGER.debug(f"Recv'd: {pkt._rssi} {pkt}")

        self._pkt_received(pkt)

    def _pkt_received(self, pkt: Packet) -> None:
        """Called by the Transport when a Packet is received."""
        try:
            msg = Message(pkt)  # should log all invalid msgs appropriately
        except exc.PacketInvalid:  # TODO: InvalidMessageError (packet is valid)
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


# NOTE: MRO: Impersonate -> Gapped/DutyCycle -> SyncCycle -> Qos/Context -> Base
# Impersonate first, as the Puzzle Packet needs to be sent before the Command
# Order of DutyCycle/Gapped doesn't matter, but both before SyncCycle
# QosTimers last, to start any timers immediately after Tx of Command

# NOTE: The duty cycle limts & minimum gaps between write are in this layer, and not
# in the Transport layer (as you might expect), because they are best enforced *before*
# the code that avoids the controller sync cycles


# ### Read-Only Protocol for FileTransport, PortTransport #############################
class ReadProtocol(_BaseProtocol):
    """A protocol that can only receive Packets."""

    def __init__(self, msg_handler: MsgHandlerT) -> None:
        super().__init__(msg_handler)

        self._pause_writing = True

    def connection_made(  # type: ignore[override]
        self, transport: RamsesTransportT, /, *, ramses: bool = False
    ) -> None:
        """Consume the callback if invoked by SerialTransport rather than PortTransport.

        Our PortTransport wraps SerialTransport and will wait for the signature echo
        to be received (c.f. FileTransport) before calling connection_made(ramses=True).
        """
        super().connection_made(transport)

    def resume_writing(self) -> None:
        raise NotImplementedError(f"{self}: The chosen Protocol is Read-Only")

    async def send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:
        """Raise an exception as the Protocol cannot send Commands."""
        raise NotImplementedError(f"{self}: The chosen Protocol is Read-Only")


# ### Read-Write (sans QoS) Protocol for PortTransport ################################
class PortProtocol(_BaseProtocol):
    """A protocol that can receive Packets and send Commands."""

    _is_evofw3: bool | None = None

    def __init__(self, msg_handler: MsgHandlerT) -> None:
        super().__init__(msg_handler)

        self._leaker_sem = asyncio.BoundedSemaphore()
        self._leaker_task: None | asyncio.Task = None

    async def _leak_sem(self) -> None:
        """Used to enforce a minimum time between calls to self._transport.write()."""
        while True:
            await asyncio.sleep(_GAP_BETWEEN_WRITES)
            try:
                self._leaker_sem.release()
            except ValueError:
                pass

    def connection_made(  # type: ignore[override]
        self, transport: RamsesTransportT, /, *, ramses: bool = False
    ) -> None:
        """Consume the callback if invoked by SerialTransport rather than PortTransport.

        Our PortTransport wraps SerialTransport and will wait for the signature echo
        to be received (c.f. FileTransport) before calling connection_made(ramses=True).
        """

        if not ramses:
            return None

        super().connection_made(transport)
        # TODO: needed? self.resume_writing()

        self._is_evofw3 = self._transport.get_extra_info(SZ_IS_EVOFW3)

        if not self._leaker_task:  # Invoke the leaky bucket algorithm
            self._leaker_task = self._loop.create_task(self._leak_sem())

    def connection_lost(self, err: ExceptionT | None) -> None:  # type: ignore[override]
        """Called when the connection is lost or closed."""
        if self._leaker_task:
            self._leaker_task.cancel()

        super().connection_lost(err)

    @track_system_syncs
    def pkt_received(self, pkt: Packet) -> None:
        """Pass any valid/wanted packets to the callback."""
        super().pkt_received(pkt)

    @avoid_system_syncs
    @limit_duty_cycle(_MAX_DUTY_CYCLE)  # type: ignore[misc]  # @limit_transmit_rate(_MAX_TOKENS)
    async def _send_frame(self, frame: str) -> None:
        """Write some data bytes to the transport."""
        await self._leaker_sem.acquire()  # asyncio.sleep() a minimum time between Tx

        await super()._send_frame(frame)

    async def _send_impersonation_alert(self, cmd: Command) -> None:
        """Send an puzzle packet warning that impersonation is occurring."""

        if _DBG_DISABLE_IMPERSONATION_ALERTS:
            return

        msg = f"{self}: Impersonating device: {cmd.src}, for pkt: {cmd.tx_header}"
        if self._is_evofw3 is False:
            _LOGGER.error(f"{msg}, NB: non-evofw3 gateways can't impersonate!")
        else:
            _LOGGER.info(msg)

        await self._send_cmd(Command._puzzle(msg_type="11", message=cmd.tx_header))

    async def send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:
        """Send a Command without QoS (send an impersonation alert if required)."""

        assert gap_duration == DEFAULT_GAP_DURATION
        assert DEFAULT_NUM_REPEATS <= num_repeats <= 3

        if cmd.src.id != HGI_DEV_ADDR.id:  # or actual HGI addr
            await self._send_impersonation_alert(cmd)

        return await super().send_cmd(
            cmd,
            gap_duration=gap_duration,
            num_repeats=num_repeats,
            priority=priority,
            qos=qos,
        )


# ### Read-Write Protocol for QosTransport ############################################
class QosProtocol(PortProtocol):
    """A protocol that can receive Packets and send Commands with QoS (using a FSM)."""

    def __init__(self, msg_handler: MsgHandlerT, selective_qos: bool = False) -> None:
        """Add a FSM to the Protocol, to provide QoS."""
        super().__init__(msg_handler)

        self._context = ProtocolContext(self)
        self._selective_qos = selective_qos  # QoS for some commands

    def __repr__(self) -> str:
        cls = self._context.state.__class__.__name__
        return f"QosProtocol({cls}, len(queue)={self._context._que.unfinished_tasks})"

    def connection_made(  # type: ignore[override]
        self, transport: RamsesTransportT, /, *, ramses: bool = False
    ) -> None:
        """Consume the callback if invoked by SerialTransport rather than PortTransport.

        Our PortTransport wraps SerialTransport and will wait for the signature echo
        to be received (c.f. FileTransport) before calling connection_made(ramses=True).
        """

        if not ramses:
            return

        super().connection_made(transport, ramses=ramses)
        self._context.connection_made(transport)

        if self._pause_writing:
            self._context.pause_writing()
        else:
            self._context.resume_writing()

    def connection_lost(self, err: ExceptionT | None) -> None:  # type: ignore[override]
        """Inform the FSM that the connection with the Transport has been lost."""

        super().connection_lost(err)
        self._context.connection_lost(err)  # is this safe, when KeyboardInterrupt?

    def pkt_received(self, pkt: Packet) -> None:
        """Inform the FSM that a Packet has been received."""

        super().pkt_received(pkt)
        self._context.pkt_received(pkt)

    def pause_writing(self) -> None:
        """Inform the FSM that the Protocol has been paused."""

        super().pause_writing()
        self._context.pause_writing()

    def resume_writing(self) -> None:
        """Inform the FSM that the Protocol has been paused."""

        super().resume_writing()
        self._context.resume_writing()

    async def _send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,
    ) -> Packet | None:
        """Wrapper to send a Command with QoS (retries, until success or exception)."""

        # Should do the same as super()._send_cmd()
        async def send_cmd(kmd: Command) -> None:
            """Wrapper to for self._send_frame(cmd) with x re-transmits.

            Repeats are distinct from retries (a QoS feature): you wouldn't have both.
            """

            assert kmd is cmd  # maybe the FSM is confused

            await self._send_frame(str(kmd))
            for _ in range(num_repeats - 1):
                await asyncio.sleep(gap_duration)
                await self._send_frame(str(kmd))

        # if cmd.code == Code._PUZZ:  # NOTE: not as simple as this
        #     priority = Priority.HIGHEST  # FIXME: hack for _7FFF

        _CODES = (Code._0006, Code._0404, Code._1FC9)  # must have QoS

        # selective QoS (HACK) or the cmd does not want QoS
        if (self._selective_qos and cmd.code not in _CODES) or qos is None:
            return await send_cmd(cmd)  # type: ignore[func-returns-value]

        if not self._transport._is_wanted_addrs(cmd.src.id, cmd.dst.id, sending=True):
            raise exc.ProtocolError(
                f"{self}: Failed to send {cmd._hdr}: excluded by list"
            )

        try:
            return await self._context.send_cmd(send_cmd, cmd, priority, qos)
        # except InvalidStateError as err:  # TODO: handle InvalidStateError separately
        #     # reset protocol stack
        except exc.ProtocolError as err:
            # raise exc.ProtocolError(
            #     f"{self}: Failed to send {cmd._hdr}: {err}"
            # ) from err
            _LOGGER.info(f"{self}: Failed to send {cmd._hdr}: {err}")
            raise

    async def send_cmd(
        self,
        cmd: Command,
        /,
        *,
        gap_duration: float = DEFAULT_GAP_DURATION,
        num_repeats: int = DEFAULT_NUM_REPEATS,
        priority: Priority = Priority.DEFAULT,
        qos: QosParams | None = None,  # max_retries, timeout, wait_for_reply
    ) -> Packet | None:
        """Send a Command with Qos (with retries, until success or ProtocolError).

        Returns the Command's response Packet or the Command echo if a response is not
        expected (e.g. sending an RP).

        If wait_for_reply is True, return the RQ's RP (or W's I), or raise an exception
        if one doesn't arrive. If it is False, return the echo of the Command only. If
        it is None (the default), act as True for RQs, and False for all other Commands.

        Commands are queued and sent FIFO, except higher-priority Commands are always
        sent first.
        """

        assert gap_duration == DEFAULT_GAP_DURATION
        assert num_repeats == DEFAULT_NUM_REPEATS

        return await super().send_cmd(
            cmd,
            gap_duration=gap_duration,
            num_repeats=num_repeats,
            priority=priority,
            qos=qos,
        )


RamsesProtocolT = QosProtocol | PortProtocol | ReadProtocol


def protocol_factory(
    msg_handler: MsgHandlerT,
    /,
    *,
    disable_qos: bool | None = False,
    disable_sending: bool | None = False,
) -> RamsesProtocolT:
    """Create and return a Ramses-specific async packet Protocol."""

    # The intention is, that once we are read-only, we're always read-only, but
    # until the QoS state machine is stable:
    #   disable_qos is True,  means QoS is always disabled
    #               is False, means QoS is never disabled
    #               is None,  means QoS is disabled, but enabled by the command

    if disable_sending:
        _LOGGER.debug("ReadProtocol: sending has been disabled")
        return ReadProtocol(msg_handler)

    if disable_qos or _DBG_DISABLE_QOS:
        _LOGGER.debug("PortProtocol: QoS has been disabled")
        return PortProtocol(msg_handler)

    _LOGGER.debug("QosProtocol: QoS has been enabled")
    return QosProtocol(msg_handler, selective_qos=disable_qos is None)


async def create_stack(
    msg_handler: MsgHandlerT,
    /,
    *,
    protocol_factory_: None | Callable = None,
    transport_factory_: None | Callable = None,
    disable_qos: bool | None = False,
    disable_sending: bool | None = False,
    **kwargs,  # TODO: these are for the transport_factory
) -> tuple[RamsesProtocolT, RamsesTransportT]:
    """Utility function to provide a Protocol / Transport pair.

    Architecture: gwy (client) -> msg (Protocol) -> pkt (Transport) -> HGI/log (or dict)
    - send Commands via awaitable Protocol.send_cmd(cmd)
    - receive Messages via Gateway._handle_msg(msg) callback
    """

    read_only = kwargs.get("packet_dict") or kwargs.get("packet_log")
    disable_sending = disable_sending or read_only

    if protocol_factory_:
        protocol = protocol_factory_(
            msg_handler, disable_qos=disable_qos, disable_sending=disable_sending
        )

    else:
        protocol = protocol_factory(
            msg_handler, disable_qos=disable_qos, disable_sending=disable_sending
        )

    transport = await (transport_factory_ or transport_factory)(
        protocol, disable_qos=disable_qos, disable_sending=disable_sending, **kwargs
    )

    if not kwargs.get(SZ_PORT_NAME):
        set_logger_timesource(transport._dt_now)
        _LOGGER.warning("Logger datetimes maintained as most recent packet timestamp")

    return protocol, transport
