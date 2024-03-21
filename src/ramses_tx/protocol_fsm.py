#!/usr/bin/env python3
#
"""RAMSES RF - RAMSES-II compatible packet protocol finite state machine."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from datetime import datetime as dt, timedelta as td
from queue import Empty, Full, PriorityQueue
from typing import TYPE_CHECKING, Any, Final, TypeAlias, TypeVar

from . import exceptions as exc
from .command import Command
from .const import MINIMUM_GAP_DURATION, Code, Priority
from .packet import Packet
from .typing import ExceptionT, QosParams

if TYPE_CHECKING:
    # these would be circular imports
    from .protocol import RamsesProtocolT
    from .transport import RamsesTransportT

ProtocolStateBase = TypeVar("ProtocolStateBase")

_LOGGER = logging.getLogger(__name__)

# All debug flags should be False for end-users
_DBG_MAINTAIN_STATE_CHAIN: Final[bool] = False  # maintain Context._prev_state
_DBG_USE_STRICT_TRANSITIONS: Final[bool] = False

MAX_BUFFER_SIZE: Final[int] = 32
DEFAULT_ECHO_TIMEOUT: Final[float] = 0.04  # waiting for echo pkt after cmd sent
DEFAULT_RPLY_TIMEOUT: Final[float] = 0.20  # waiting for reply pkt after echo pkt rcvd

MAX_SEND_TIMEOUT: Final[float] = 3.0  # for a command to be sent, incl. retries, etc.
MAX_RETRY_LIMIT: Final[int] = 3  # for a command to be re-sent (not incl. 1st send)


#######################################################################################


class _ProtocolWaitFailed(exc.ProtocolSendFailed):
    """The Command timed out when waiting for its turn to send."""


class _ProtocolEchoFailed(exc.ProtocolSendFailed):
    """The Command was sent OK, but failed to elicit its echo."""


class _ProtocolRplyFailed(exc.ProtocolSendFailed):
    """The Command received an echo OK, but failed to elicit the expected reply."""


#######################################################################################


class ProtocolContext:
    def __init__(
        self,
        protocol: RamsesProtocolT,
        /,
        *,
        echo_timeout: float = DEFAULT_ECHO_TIMEOUT,
        reply_timeout: float = DEFAULT_RPLY_TIMEOUT,
        min_gap_duration: float = MINIMUM_GAP_DURATION,
        max_retry_limit: int = MAX_RETRY_LIMIT,
        max_buffer_size: int = MAX_BUFFER_SIZE,
    ) -> None:
        self._protocol = protocol
        self.echo_timeout = td(seconds=echo_timeout)
        self.reply_timeout = td(seconds=reply_timeout)
        self.min_gap_duration = td(seconds=min_gap_duration)
        self.max_retry_limit = min(max_retry_limit, MAX_RETRY_LIMIT)
        self.max_buffer_size = min(max_buffer_size, MAX_BUFFER_SIZE)

        self._loop = protocol._loop
        self._fut: asyncio.Future | None = None
        self._que: PriorityQueue = PriorityQueue(maxsize=self.max_buffer_size)

        self._expiry_timer: asyncio.Task = None  # type: ignore[assignment]
        self._state: ProtocolStateBase = None  # type: ignore[assignment]

        # TODO: pass this over as an instance paramater
        self._send_fnc: Callable[[Command], Coroutine[Any, Any, None]] = None  # type: ignore[assignment]

        self._cmd: Command = None  # type: ignore[assignment]
        self._qos: QosParams = None  # type: ignore[assignment]
        self._cmd_tx_count: int = 0
        self._cmd_tx_limit: int = 0

        self.set_state(Inactive)

    def set_state(
        self,
        state: ProtocolStateBase,
        expired: bool = False,
        timed_out: bool = False,
        exception: Exception | None = None,
        result: Packet | None = None,
    ) -> None:
        async def expire_state_on_timeout() -> None:
            if isinstance(self._state, WantEcho):
                await asyncio.sleep(self.echo_timeout)
            else:
                await asyncio.sleep(self.reply_timeout)

            # Timer has expired, can we retry?
            if self._cmd_tx_count < self._cmd_tx_limit:
                self.set_state(WantEcho, timed_out=True)
            else:
                self.set_state(IsInIdle, expired=True)

        if self._expiry_timer is not None:
            self._expiry_timer.cancel()
            self._expiry_timer = None

        self._state = state(self)

        if result:
            self._fut.set_result(result)
        elif exception:
            self._fut.set_exception(exception)
        elif expired:
            self._fut.set_exception(exc.ProtocolSendFailed("Exceeded maximum retries"))
        elif timed_out:
            self._send_cmd(is_retry=True)

        if isinstance(self._state, IsInIdle):
            self._check_buffer_for_cmd()

        elif isinstance(self._state, WantRply) and not self._qos.wait_for_reply:
            self.set_state(IsInIdle, result=self._state._echo_pkt)

        elif isinstance(self._state, WantEcho | WantRply):
            self._expiry_timer = self._loop.create_task(expire_state_on_timeout())

    @property
    def state(self) -> _ProtocolStateT:
        return self._state

    def connection_made(self, transport: RamsesTransportT) -> None:
        # may want to set some instance variables, according to type of transport
        self._state.connection_made()

    def connection_lost(self, err: ExceptionT | None) -> None:
        self._state.connection_lost()

    def pkt_received(self, pkt: Packet) -> Any:
        self._state.pkt_rcvd(pkt)

    def pause_writing(self) -> None:
        self._state.writing_paused()

    def resume_writing(self) -> None:
        self._state.writing_resumed()

    async def send_cmd(
        self,
        send_fnc: Callable[[Command], Coroutine[Any, Any, None]],  # TODO: remove
        cmd: Command,
        priority: Priority,
        qos: QosParams,
    ) -> Packet:
        self._send_fnc = send_fnc  # TODO: REMOVE: make per Context, not per Command

        fut = self._loop.create_future()
        await self._push_cmd_to_buffer(cmd, priority, qos, fut)

        if isinstance(self._state, IsInIdle):
            self._loop.call_soon_threadsafe(self._check_buffer_for_cmd)

        try:
            await asyncio.wait_for(fut, timeout=min(qos.timeout, MAX_SEND_TIMEOUT))
        except TimeoutError as err:
            self.set_state(IsInIdle)
            raise exc.ProtocolSendFailed("Send timeout has expired") from err
        return fut.result()  # may raise ProtocolFsmError

    async def _push_cmd_to_buffer(
        self,
        cmd: Command,
        priority: Priority,
        qos: QosParams,
        fut: asyncio.Future,
    ):
        try:
            self._que.put_nowait((priority, dt.now(), cmd, qos, fut))
        except Full:
            fut.set_exception(_ProtocolWaitFailed("Send buffer full, cmd discarded"))

    def _check_buffer_for_cmd(self):
        if not isinstance(self._state, IsInIdle):  # TODO: make assert? or remove?
            raise exc.ProtocolFsmError("Incorrect state to check the buffer")

        while True:
            try:
                *_, self._cmd, self._qos, self._fut = self._que.get_nowait()
            except Empty:
                self._cmd = self._qos = self._fut = None
                return

            assert isinstance(self._fut, asyncio.Future)  # mypy hint
            if self._fut.done():  # e.g. TimeoutError
                self._que.task_done()
                continue

            break

        try:
            self._send_cmd()
        finally:
            self._que.task_done()

    def _send_cmd(self, is_retry: bool = False) -> Packet:
        """Wrapper to send a command with retries, until success or exception.

        Supported Exceptions are limited to:
         - _ProtocolWaitFailed - issue sending Command
         - _ProtocolEchoFailed - issue receiving echo Packet
         - _ProtocolRplyFailed - issue receiving expected reply pPacket
        """

        async def send_fnc_wrapper(cmd: Command) -> None:
            if self._cmd is None:
                pass

            try:  # the wrapped function (actual Tx.write)
                await self._send_fnc(cmd)
            except exc.TransportError as err:
                self.set_state(IsInIdle, exception=err)

        if is_retry:
            self._cmd_tx_count += 1
        else:
            # TODO: check what happens when exception here - why does it hang?
            self._cmd_tx_limit = min(self._qos.max_retries, self.max_retry_limit) + 1
            self._cmd_tx_count = 0

        try:  # the wrapped function (actual Tx.write)
            self._state.cmd_sent(self._cmd)
        except exc.ProtocolError as err:
            self.set_state(IsInIdle, exception=err)
            return

        self._loop.create_task(send_fnc_wrapper(self._cmd))


#######################################################################################


class ProtocolStateBase:
    def __init__(self, context: ProtocolContext) -> None:
        self._context = context

        self._sent_cmd: Command | None = None
        self._echo_pkt: Packet | None = None
        self._rply_pkt: Packet | None = None

    def connection_made(self) -> None:  # Same for all states except Inactive
        """Do nothing, as (except for InActive) we're already connected."""
        pass

    def connection_lost(self) -> None:  # Same for all states (not needed if Inactive)
        """Transition to Inactive, regardless of current state."""
        self._context.set_state(Inactive)

    def pkt_rcvd(self, pkt: Packet) -> None:  # Different for each state
        """Raise a NotImplementedError."""
        raise NotImplementedError  # this method should never be called

    def writing_paused(self) -> None:  # Currently same for all states (TBD)
        """Do nothing."""
        pass

    def writing_resumed(self) -> None:  # Currently same for all states (TBD)
        """Do nothing."""
        pass

    def cmd_sent(self, cmd: Command) -> None:  # Same for all states except IsInIdle
        raise exc.ProtocolFsmError("In the wrong state to send a command")

    def _warn_or_raise(self, error: str) -> None:
        if _DBG_USE_STRICT_TRANSITIONS:
            err = exc.ProtocolFsmError(error)
            self._context.set_state(self.__class__, exception=err)
        else:
            _LOGGER.warning(error)


class Inactive(ProtocolStateBase):
    def connection_made(self) -> None:
        """Transition to IsInIdle."""
        self._context.set_state(IsInIdle)

    def pkt_rcvd(self, pkt: Packet) -> None:  # raise ProtocolFsmError
        """Raise an exception, as a packet is not expected in this state."""
        if pkt.code != Code._PUZZ:
            self._warn_or_raise("Not expecting to receive a packet")


class IsInIdle(ProtocolStateBase):
    def pkt_rcvd(self, pkt: Packet) -> None:  # Do nothing
        """Do nothing as we're not expecting an echo, nor a reply."""
        pass

    def cmd_sent(self, cmd: Command) -> None:  # Will expect an Echo
        """Transition to WantEcho."""
        self._sent_cmd = cmd
        self._context.set_state(WantEcho)


class WantEcho(ProtocolStateBase):
    def __init__(self, context: ProtocolContext) -> None:
        super().__init__(context)

        self._sent_cmd = context._state._sent_cmd

    def pkt_rcvd(self, pkt: Packet) -> None:  # Check if pkt is expected Echo
        """If the pkt is the expected Echo, transition to IsInIdle, or WantRply."""

        # RQ --- 18:002563 01:078710 --:------ 2349 002 0200                # 2349|RQ|01:078710|02
        # RP --- 01:078710 18:002563 --:------ 2349 007 0201F400FFFFFF      # 2349|RP|01:078710|02
        #  W --- 30:257306 01:096339 --:------ 313F 009 0060002916050B07E7  # 313F| W|01:096339
        #  I --- 01:096339 30:257306 --:------ 313F 009 00FC0029D6050B07E7  # 313F| I|01:096339

        if (
            self._sent_cmd.rx_header
            and pkt._hdr == self._sent_cmd.rx_header
            and pkt.dst.id == self._sent_cmd.src.id
        ):  # TODO: just skip to idle?
            self._warn_or_raise("Expecting an echo, but received the reply")
            return

        if pkt._hdr != self._sent_cmd.tx_header:
            return

        self._echo_pkt = pkt
        if self._sent_cmd.rx_header:
            self._context.set_state(WantRply)
        else:
            self._context.set_state(IsInIdle, result=pkt)


class WantRply(ProtocolStateBase):
    def __init__(self, context: ProtocolContext) -> None:
        super().__init__(context)

        self._sent_cmd = context._state._sent_cmd
        self._echo_pkt = context._state._echo_pkt

    def pkt_rcvd(self, pkt: Packet) -> None:  # Check if pkt is expected Reply
        """If the pkt is the expected reply, transition to IsInIdle."""

        if pkt == self._sent_cmd:  # pkt._hdr == self._sent_cmd.tx_header and ...
            self._warn_or_raise("Expecting a reply, but received the echo")
            return

        if pkt._hdr != self._sent_cmd.rx_header:
            return

        self._rply_pkt = pkt
        self._context.set_state(IsInIdle, result=pkt)


class IsFailed(ProtocolStateBase):  # TODO: remove?
    pass


#######################################################################################


_ProtocolStateT: TypeAlias = Inactive | IsInIdle | WantEcho | WantRply
