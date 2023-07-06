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

MAINTAIN_STATE_CHAIN = False  # HACK: use for debugging


DEFAULT_SEND_PRIORITY = 1

DEFAULT_WAIT_TIMEOUT = 3.0  # waiting in queue to send
DEFAULT_ECHO_TIMEOUT = 300.05  # waiting for echo pkt after cmd sent
DEFAULT_RPLY_TIMEOUT = 300.50  # waiting for reply pkt after echo pkt received

_DEFAULT_WAIT_TIMEOUT = td(seconds=DEFAULT_WAIT_TIMEOUT)
_DEFAULT_ECHO_TIMEOUT = td(seconds=DEFAULT_ECHO_TIMEOUT)
_DEFAULT_RPLY_TIMEOUT = td(seconds=DEFAULT_RPLY_TIMEOUT)

POLLING_INTERVAL = 0.0005


class ProtocolContext:  # asyncio.Protocol):  # mixin for tracking state
    """A mixin is to add state to a Protocol."""

    MAX_BUFFER_SIZE: int = 5

    state: _StateT = None

    def __init__(self, protocol, *args, **kwargs) -> None:
        # super().__init__(*args, **kwargs)
        self._protocol = protocol

        self._loop = asyncio.get_running_loop()
        self._cmd: None | Command = None
        self._que = PriorityQueue(maxsize=self.MAX_BUFFER_SIZE)
        self._sem = BoundedSemaphore(value=1)

        self.set_state(IsInactive)  # set initial state

    def __repr__(self) -> str:
        state_name = self.state.__class__.__name__
        cmd_hdr = self._cmd._hdr if self._cmd else None
        que_length = self._que.unfinished_tasks
        return f"Context({state_name}, hdr={cmd_hdr}, len(buffer)={que_length})"

    def set_state(
        self, state: type[_StateT], cmd: None | Command = None, cmd_sends: int = 0
    ) -> None:
        """Set the State of the Protocol (context)."""

        assert not isinstance(self.state, state)  # check transition has occurred
        _LOGGER.info(f" *** State was moved from {self.state!r} to {state.__name__}")

        if state == HasFailed:  # FailedRetryLimit?
            _LOGGER.warning(f"!!! failed: {self}")

        if MAINTAIN_STATE_CHAIN:  # HACK for debugging
            prev_state = self.state

        if state is IsInIdle:
            self.state = state(self)
        else:
            self.state = state(self, cmd=cmd, cmd_sends=cmd_sends)

        if MAINTAIN_STATE_CHAIN:  # HACK for debugging
            setattr(self.state, "_prev_state", prev_state)

        if not self.is_sending:
            self._cmd = None
            self._get_next_to_send()

    def connection_made(self, transport: _TransportT) -> None:
        _LOGGER.info(
            f" *** Connection made when {self.state!r}: {transport.__class__.__name__}"
        )
        self.state.made_connection(transport)

    def connection_lost(self, exc: None | Exception) -> None:
        """Called when the connection to the Transport is lost or closed.

        If there is a SerialException of Serial.read() in SerialTransport._read_ready(),
        then SerialTransport will invoke _close(exc) directly (i.e. bypass close()),
        which then invokes Protocol.connection_lost(exc) via a Loop.call_soon().
        """
        fut: asyncio.Future  # mypy

        while True:
            try:
                (_, _, _, _, fut) = self._que.get_nowait()
            except Empty:
                break
            fut.cancel()  # if not fut.done(): not required

        _LOGGER.info(f"*** Connection lost when {self.state!r}, Exception: {exc}")
        self.state.lost_connection(exc)

    def pause_writing(self) -> None:  # not required?
        _LOGGER.info(f"*** Writing paused, when {self.state!r}")
        self.state.writing_paused()

    def resume_writing(self) -> None:
        _LOGGER.info(f"*** Writing resumed when {self.state!r}")
        self.state.writing_resumed()

    async def _wait_for_transition(self, old_state: _StateT, until: dt) -> _StateT:
        """Poll the state machine until it moves its context to another state.

        Raises an asyncio.TimeoutError if the default timeout is exceeded.
        """

        _LOGGER.error(f"---  - WAITING to leave {old_state}...")
        while until > dt.now():
            if not isinstance(self.state, old_state.__class__):
                break
            await asyncio.sleep(POLLING_INTERVAL)
        else:
            _LOGGER.error(f"---  - FAILURE to leave {old_state} (timed out)")
            raise asyncio.TimeoutError(f"Failed to leave {old_state} (timed out)")

        _LOGGER.error(f"---  - SUCCESS leaving {old_state}, now {self.state}")
        return self.state

    async def _wait_for_expected_state(
        self, expected: type[_StateT], until: dt
    ) -> None:
        """Poll the state machine until it moves to the expected state.

        Raises an asyncio.TimeoutError if the default timeout is exceeded.
        """

        _LOGGER.error(f"---  - WAITING to reach {expected.__name__}...")
        state = await self._wait_for_transition(self.state, until)

        if not isinstance(state, expected):
            _LOGGER.error(f"---  - FAILURE to reach {expected.__name__} in time")
            raise asyncio.TimeoutError(f"Failed to reach {expected.__name__} in time")

        _LOGGER.error(f"---  - SUCCESS reaching {expected.__name__}")

    async def wait_for_rcvd_echo(
        self, this_state: _StateT, cmd: Command, timeout: float = _DEFAULT_ECHO_TIMEOUT
    ) -> None:
        """Wait until the state machine has received the expected echo pkt.

        Raises an asyncio.TimeoutError if the default timeout is exceeded.
        """

        if not isinstance(self.state, WantEcho):  # FIXME
            raise asyncio.InvalidStateError
        if not self.state._is_active_cmd(cmd):
            raise asyncio.InvalidStateError

        # next_state = WantRply if cmd.rx_header else IsInIdle
        # await self._wait_for_expected_state(next_state, dt.now() + timeout)
        # # active cmd should be None or cmd (expecting a reply, cmd.rx_header not None)
        await self._wait_for_transition(this_state, dt.now() + timeout)

        if not isinstance(self.state, WantRply if cmd.rx_header else IsInIdle):  # FIXME
            raise asyncio.InvalidStateError(f"Unexpected state: {self.state}")

    async def wait_for_rcvd_rply(
        self, this_state: _StateT, cmd: Command, timeout: float = _DEFAULT_RPLY_TIMEOUT
    ) -> None:
        """Wait until the state machine has received the expected reply pkt.

        Raises an asyncio.TimeoutError if the default timeout is exceeded.
        """

        if not isinstance(self.state, WantRply):  # FIXME
            raise asyncio.InvalidStateError
        if not self.state._is_active_cmd(cmd):
            raise asyncio.InvalidStateError

        # await self._wait_for_expected_state(IsInIdle, dt.now() + timeout)
        # # active cmd should now be None
        await self._wait_for_transition(this_state, dt.now() + timeout)

        if not isinstance(self.state, IsInIdle):  # FIXME
            raise asyncio.InvalidStateError(f"Unexpected state: {self.state}")

    async def _wait_for_state(self, state: _StateT, until: dt) -> None:  # TODO: REMOVE
        """Poll the state machine until it moves to the expected state."""

        while until > dt.now():
            if isinstance(self.state, state):
                break
            await asyncio.sleep(POLLING_INTERVAL)
        else:
            _LOGGER.error(f"---  - failed to attain {state.__name__} in time")
            raise asyncio.TimeoutError

    async def send_cmd(
        self, cmd: Command, timeout: float = DEFAULT_WAIT_TIMEOUT
    ) -> None:
        """Wait until the state machine is clear to send."""

        _LOGGER.info(f"... Sending a cmd: {cmd}")

        if isinstance(self.state, (IsInactive, HasFailed)):
            raise asyncio.InvalidStateError(f"Invalid Context: {self!r}")
        if self._cmd and self.state._is_active_cmd(cmd):
            self.state.sent_cmd(cmd)  # assume re-transmit
            return

        dt_sent = dt.now()
        until = dt_sent + td(seconds=timeout)

        fut: asyncio.Future = self._set_ready_to_send(cmd, dt_sent, until)

        try:
            await self._wait_for_state(IsInIdle, until)
            # await self._wait_for_expected_state(IsInIdle, until)
        except asyncio.TimeoutError as exc:
            _LOGGER.warning("!!! wait_for_state(IsInIdle) has expired/failed.")
            fut.set_exception(exc)

        fut.result()  # may raise exception
        self.state.sent_cmd(cmd)

    def pkt_received(self, pkt: Packet) -> None:
        _LOGGER.info(f"... Receivd a pkt: {pkt}")
        self.state.rcvd_pkt(pkt)

    @property
    def is_sending(self) -> bool:
        """Return True if the protocol is sending a packet/waiting for a response."""
        return isinstance(self.state, (WantEcho, WantRply))

    def _set_ready_to_send(self, cmd: Command, sent: dt, until: dt) -> asyncio.Future:
        """Return a Future that will be done when the protocol is ready to send."""

        fut = self._loop.create_future()

        if self._sem.acquire():
            self._cmd = self._cmd or cmd
            self._sem.release()

        if self._cmd is cmd:  # a retry or a re-transmit?
            fut.set_result(None)
        else:
            self._que.put_nowait((DEFAULT_SEND_PRIORITY, sent, cmd, until, fut))

        return fut

    def _get_next_to_send(self) -> None:  # called by context
        """If there are cmds waiting to be sent, inform the next Future in the queue.

        WIll recursively removed all expired cmds.
        """
        fut: asyncio.Future  # mypy

        try:
            (_, _, cmd, until, fut) = self._que.get_nowait()
        except Empty:
            return

        if fut.cancelled():
            _LOGGER.debug("---  - future cancelled (e.g. connection_lost())")

        elif fut.done():  # handled in send_cmd()
            _LOGGER.debug("---  - future done (handled in send_cmd())")

        # elif until <= dt.now():  # handled in send_cmd()
        #     _LOGGER.debug("---  - future expired")
        #     fut.set_exception(asyncio.TimeoutError)  # TODO: make a ramses Exception

        else:
            _LOGGER.debug("---  - future is good to go")
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
        self._context.set_state(state, *args, **kwargs)  # pylint: disable=W0212

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
        _LOGGER.debug(f"     - sending a cmd: {cmd._hdr}")
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
            _LOGGER.debug(f"     - received ????: {pkt._hdr} (unexpected, ignored)")

        elif self.cmd.rx_header:
            _LOGGER.debug(f"     - received echo: {pkt._hdr} (& expecting a reply)")
            self._set_context_state(WantRply, cmd=self.cmd, cmd_sends=self.cmd_sends)

        else:
            _LOGGER.debug(f"     - received echo: {pkt._hdr} (no reply expected)")
            self._set_context_state(IsInIdle)

    def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        if self._is_active_cmd(cmd):
            _LOGGER.debug(f"     - sending a cmd: {cmd._hdr} (again 1)")
            self.cmd_sends += 1
            return

        raise RuntimeError(f"Shouldn't send whilst expecting an echo: {cmd._hdr}")


class WantRply(ProtocolStateBase):
    """Protocol is now waiting for a response (has received the Command echo)."""

    def rcvd_pkt(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected response."""

        if pkt._hdr == self.cmd.tx_header:  # expected pkt
            _LOGGER.debug(f"     - received echo: {pkt._hdr} (again 3)")

        elif pkt._hdr != self.cmd.rx_header:
            _LOGGER.debug(f"     - received ????: {pkt._hdr} (unexpected, ignored)")

        elif pkt._hdr == self.cmd.rx_header:  # expected pkt
            _LOGGER.debug(f"     - received rply: {pkt._hdr} (as expected)")
            self._set_context_state(IsInIdle)

    def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        if self._is_active_cmd(cmd):
            _LOGGER.debug(f"     - sending a cmd: {cmd._hdr} (again 3)")
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
