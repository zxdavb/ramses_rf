#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible packet protocol finite state machine."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime as dt
from datetime import timedelta as td
from queue import Empty, PriorityQueue
from threading import BoundedSemaphore
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from .command import Command
    from .packet import Packet


_TransportT = TypeVar("_TransportT", bound=asyncio.BaseTransport)


_LOGGER = logging.getLogger(__name__)

DEFAULT_SEND_PRIORITY = 1

DEFAULT_WAIT_TIMEOUT = 3.0  # waiting in queue to send
DEFAULT_ECHO_TIMEOUT = 0.05  # waiting for echo pkt after cmd sent
DEFAULT_RPLY_TIMEOUT = 0.20  # waiting for reply pkt after echo pkt received

POLLING_INTERVAL = 0.0005


class ProtocolContext:  # asyncio.Protocol):  # mixin for tracking state
    """A mixin is to add state to a Protocol."""

    MAX_BUFFER_SIZE: int = 5

    _state: _StateT = None

    def __init__(self, protocol, *args, **kwargs) -> None:
        # super().__init__(*args, **kwargs)
        self._protocol = protocol

        self._loop = asyncio.get_running_loop()
        self._cmd: None | Command = None
        self._que = PriorityQueue(maxsize=self.MAX_BUFFER_SIZE)
        self._sem = BoundedSemaphore(value=1)

        self._set_state(IsInactive)  # set initial state

    def __repr__(self) -> str:
        state_name = self._state.__class__.__name__
        cmd_hdr = self._cmd._hdr if self._cmd else None
        que_length = self._que.unfinished_tasks
        return f"Context({state_name}, hdr={cmd_hdr}, len(buffer)={que_length})"

    def _set_state(
        self, state: type[_StateT], cmd: None | Command = None, cmd_sends: int = 0
    ) -> None:
        """Set the State of the Protocol (context)."""

        assert not isinstance(self._state, state)  # check transition has occurred
        _LOGGER.error(f" *** State moved from {self._state!r} to {state.__name__}")

        if state == HasFailed:  # FailedRetryLimit?
            _LOGGER.warning(f"!!! failed: {self}")

        if state is IsInIdle:
            self._state = state(self)

        else:
            self._state = state(self, cmd=cmd, cmd_sends=cmd_sends)

        if not self.is_sending:
            self._cmd = None
            self._get_next_to_send()

    def connection_made(self, transport: _TransportT) -> None:
        self._state.made_connection(transport)

    def connection_lost(self, exc: None | Exception) -> None:
        fut: asyncio.Future  # mypy

        while True:
            try:
                (_, _, _, _, fut) = self._que.get_nowait()
            except Empty:
                break
            fut.cancel()

        self._state.lost_connection(exc)

    def pause_writing(self) -> None:  # not required?
        self._state.writing_paused()

    def resume_writing(self) -> None:
        self._state.writing_resumed()

    async def _wait_for_state(self, state: _StateT, until: dt) -> None:
        """Poll the state machine until it moves to the expected state."""

        while until > dt.now():
            if isinstance(self._state, state):
                break
            await asyncio.sleep(POLLING_INTERVAL)
        else:
            _LOGGER.error(f"---  - failed to attain {state.__name__} in time")
            raise asyncio.TimeoutError

    async def wait_until_echo_rcvd(
        self, cmd: Command, timeout: float = DEFAULT_ECHO_TIMEOUT
    ) -> None:
        """Wait until the state machine has received the echo pkt."""

        if not isinstance(self._state, WantEcho):  # FIXME
            raise asyncio.InvalidStateError
        if not self._state._is_active_cmd(cmd):
            raise asyncio.InvalidStateError

        await self._wait_for_state(WantRply, dt.now() + td(seconds=timeout))

    async def wait_until_rply_rcvd(
        self, cmd: Command, timeout: float = DEFAULT_RPLY_TIMEOUT
    ) -> None:
        """Wait until the state machine has received the reply pkt."""

        if not isinstance(self._state, WantRply):  # FIXME
            raise asyncio.InvalidStateError
        if not self._state._is_active_cmd(cmd):
            raise asyncio.InvalidStateError

        await self._wait_for_state(IsInIdle, dt.now() + td(seconds=timeout))

    async def send_cmd(
        self, cmd: Command, timeout: float = DEFAULT_WAIT_TIMEOUT
    ) -> None:
        """Wait until the state machine is clear to send."""

        if isinstance(self._state, (IsInactive, HasFailed)):
            raise asyncio.InvalidStateError
        if self._cmd and self._state._is_active_cmd(cmd):
            self._state.sent_cmd(cmd)
            return

        dt_sent = dt.now()
        expires = dt_sent + td(seconds=timeout)

        fut: asyncio.Future = self._set_ready_to_send(cmd, dt_sent, expires)

        _LOGGER.error(f"*** Sending a cmd:  {cmd}")
        try:
            await self._wait_for_state(IsInIdle, expires)
        except (asyncio.TimeoutError, asyncio.TimeoutError) as exc:
            _LOGGER.debug("!!! expired/failed.")
            fut.set_exception(exc)

        fut.result()  # may raise exception
        self._state.sent_cmd(cmd)

    def pkt_received(self, pkt: Packet) -> None:
        _LOGGER.error(f"*** Received a pkt: {pkt}")
        self._state.rcvd_pkt(pkt)

    @property
    def is_sending(self) -> bool:
        """Return True if the protocol is sending a packet/waiting for a response."""
        return isinstance(self._state, (WantEcho, WantRply))

    def _set_ready_to_send(self, cmd: Command, sent: dt, expires: dt) -> asyncio.Future:
        """Return a Future that will be done when the protocol is ready to send."""

        fut = self._loop.create_future()

        if self._sem.acquire():
            self._cmd = self._cmd or cmd
            self._sem.release()

        if self._cmd is cmd:  # a retry or a re-transmit?
            fut.set_result(None)
        else:
            self._que.put_nowait((DEFAULT_SEND_PRIORITY, sent, cmd, expires, fut))

        return fut

    def _get_next_to_send(self) -> None:  # called by context
        """If there are cmds waiting to be sent, inform the next Future in the queue.

        WIll recursively removed all expired cmds.
        """
        fut: asyncio.Future  # mypy

        try:
            (_, _, cmd, expires, fut) = self._que.get_nowait()
        except Empty:
            return

        if fut.cancelled():
            _LOGGER.error("---  - future cancelled (e.g. connection_lost())")

        elif fut.done():  # handled in send_cmd()
            _LOGGER.error("---  - future done (handled in send_cmd())")

        # elif expires <= dt.now():  # handled in send_cmd()
        #     _LOGGER.error("---  - fut expired")
        #     fut.set_exception(asyncio.TimeoutError)  # TODO: make a ramses Exception

        else:
            _LOGGER.error("---  - fut is good to go")
            fut.set_result(None)
            return

        self._get_next_to_send()


_ContextT = ProtocolContext  # TypeVar("_ContextT", bound=ProtocolContext)


class ProtocolStateBase:
    # state attrs
    cmd: None | Command
    cmd_sends: int

    _next_state: None | _StateT = None

    def __init__(
        self,
        context: _ContextT,
        cmd: None | Command = None,
        cmd_sends: int = 0,
    ) -> None:
        self._context = context  # a Protocol

        self.cmd: None | Command = cmd
        self.cmd_sends: None | int = cmd_sends

    def __repr__(self) -> str:
        hdr = self.cmd.tx_header if self.cmd else None
        if hdr:
            return f"{self.__class__.__name__}(hdr={hdr}, tx={self.cmd_sends})"
        assert self.cmd_sends == 0
        return f"{self.__class__.__name__}(hdr={hdr})"

    def __str__(self) -> str:
        return self.__class__.__name__

    def _set_context_state(self, state: _StateT, *args, **kwargs) -> None:
        self._next_state = state
        self._context._set_state(state, *args, **kwargs)  # pylint: disable=W0212

    def _retry_limit_exceeded(self):
        self._set_context_state(HasFailedRetries)

    def _is_active_cmd(self, cmd: Command) -> bool:
        return (
            cmd._hdr == self.cmd._hdr
            and cmd._addrs == self.cmd._addrs
            and cmd.payload == self.cmd.payload
        )

    def made_connection(self, transport: _TransportT) -> None:  # FIXME: may be paused
        self._set_context_state(IsInIdle)  # initial state (assumes not paused)

    def lost_connection(self, exc: None | Exception) -> None:
        self._set_context_state(IsInactive)

    def writing_paused(self) -> None:
        self._set_context_state(IsInactive)

    def writing_resumed(self) -> None:
        self._set_context_state(IsInIdle)

    def rcvd_pkt(self, pkt: Packet) -> None:
        pass

    def sent_cmd(self, cmd: Command) -> None:
        raise NotImplementedError


class IsInactive(ProtocolStateBase):
    """Protocol has no active connection with a Transport."""

    def __repr__(self) -> str:
        assert self.cmd is None
        return f"{self.__class__.__name__}()"

    def rcvd_pkt(self, pkt: Packet) -> None:  # raise an exception
        raise RuntimeError(f"Shouldn't rcvd whilst not connected: {pkt._hdr}")

    async def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError(f"Shouldn't send whilst not connected: {cmd._hdr}")


class IsPaused(ProtocolStateBase):
    """Protocol has active connection with a Transport, but should not send."""

    async def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError(f"Shouldn't send whilst paused: {cmd._hdr}")


class IsInIdle(ProtocolStateBase):
    """Protocol is available to send a Command (has no outstanding Commands)."""

    def sent_cmd(self, cmd: Command) -> None:
        _LOGGER.error(f"...  - sending a cmd: {cmd._hdr}")
        self._set_context_state(WantEcho, cmd=cmd, cmd_sends=1)


class WantEcho(ProtocolStateBase):
    """Protocol is waiting for the local echo (has sent a Command)."""

    _fut: asyncio.Future
    _loop: asyncio.BaseEventLoop

    def __init__(
        self,
        context: _ContextT,
        cmd: None | Command = None,
        cmd_sends: int = 0,
    ) -> None:
        super().__init__(context, cmd=cmd, cmd_sends=cmd_sends)

        if self.cmd_sends > self.cmd._qos.retry_limit:  # first send was not a retry
            self._retry_limit_exceeded()

    def rcvd_pkt(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected echo."""

        if self.cmd.rx_header and pkt._hdr == self.cmd.rx_header:  # expected pkt
            raise RuntimeError(f"Response received before echo: {pkt}")

        elif pkt._hdr != self.cmd.tx_header:
            _LOGGER.error(f"...  - received ????: {pkt._hdr} (unexpected, ignored)")

        elif self.cmd.rx_header:
            _LOGGER.error(f"...  - received echo: {pkt._hdr} (& expecting a reply)")
            self._set_context_state(WantRply, cmd=self.cmd, cmd_sends=self.cmd_sends)

        else:
            _LOGGER.error(f"...  - received echo: {pkt._hdr} (no reply expected)")
            self._set_context_state(IsInIdle)

    def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        if self._is_active_cmd(cmd):
            _LOGGER.error(f"...  - sending a cmd: {cmd._hdr} (again 1)")
            self.cmd_sends += 1
            return

        raise RuntimeError(f"Shouldn't send whilst expecting an echo: {cmd._hdr}")


class WantRply(ProtocolStateBase):
    """Protocol is now waiting for a response (has received the Command echo)."""

    def rcvd_pkt(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected response."""

        if pkt._hdr == self.cmd.tx_header:  # expected pkt
            _LOGGER.error(f"...  - received echo: {pkt._hdr} (again 3)")

        elif pkt._hdr != self.cmd.rx_header:
            _LOGGER.error(f"...  - received ????: {pkt._hdr} (unexpected, ignored)")

        elif pkt._hdr == self.cmd.rx_header:  # expected pkt
            _LOGGER.error(f"...  - received rply: {pkt._hdr} (as expected)")
            self._set_context_state(IsInIdle)

    def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        if self._is_active_cmd(cmd):
            _LOGGER.error(f"...  - sending a cmd: {cmd._hdr} (again 3)")
            self.cmd_sends += 1
            return

        raise RuntimeError(f"Shouldn't send whilst expecting a response: {cmd._hdr}")


class HasFailed(ProtocolStateBase):
    """Protocol has rcvd the Command echo and is waiting for a response to be Rx'd."""

    def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError(f"Shouldn't send whilst in a failed state: {cmd._hdr}")


class HasFailedRetries(HasFailed):
    pass


_StateT = ProtocolStateBase  # TypeVar("_StateT", bound=ProtocolStateBase)


class ProtocolState:
    DEAD = IsInactive  # #      #
    IDLE = IsInIdle  # ##
    ECHO = WantEcho  # #     #
    RPLY = WantRply  # #
