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

from .exceptions import InvalidStateError, RetryLimitExceeded, SendTimeoutError

if TYPE_CHECKING:
    from .command import Command
    from .packet import Packet


_TransportT = TypeVar("_TransportT", bound=asyncio.BaseTransport)


_LOGGER = logging.getLogger(__name__)

_DEBUG_MAINTAIN_STATE_CHAIN = False  # HACK: use for debugging


DEFAULT_SEND_PRIORITY = 1

DEFAULT_WAIT_TIMEOUT = 3.0  # waiting in queue to send
DEFAULT_ECHO_TIMEOUT = 0.05  # waiting for echo pkt after cmd sent
DEFAULT_RPLY_TIMEOUT = 0.50  # waiting for reply pkt after echo pkt received

_DEFAULT_WAIT_TIMEOUT = td(seconds=DEFAULT_WAIT_TIMEOUT)
_DEFAULT_ECHO_TIMEOUT = td(seconds=DEFAULT_ECHO_TIMEOUT)
_DEFAULT_RPLY_TIMEOUT = td(seconds=DEFAULT_RPLY_TIMEOUT)

DEFAULT_MAX_RETRIES = 3

POLLING_INTERVAL = 0.0005


class ProtocolContext:  # asyncio.Protocol):  # mixin for tracking state
    """A mixin is to add state to a Protocol."""

    MAX_BUFFER_SIZE: int = 5

    _state: _StateT = None  # type: ignore[assignment]

    def __init__(self, protocol, *args, **kwargs) -> None:
        # super().__init__(*args, **kwargs)
        self._protocol = protocol

        self._loop = asyncio.get_running_loop()
        self._que = PriorityQueue(maxsize=self.MAX_BUFFER_SIZE)
        self._sem = BoundedSemaphore(value=1)

        self.set_state(IsInactive)  # set initial state

    def __repr__(self) -> str:
        state_name = self.state.__class__.__name__
        return f"Context({state_name}, len(queue)={self._que.unfinished_tasks})"

    def set_state(
        self, state: type[_StateT], cmd: None | Command = None, cmd_sends: int = 0
    ) -> None:
        """Set the State of the Protocol (context)."""

        assert not isinstance(self._state, state)  # check a transition has occurred
        _LOGGER.info(f" ... State was moved from {self._state!r} to {state.__name__}")

        if state == HasFailed:  # FailedRetryLimit?
            _LOGGER.warning(f"!!! failed: {self}")

        if _DEBUG_MAINTAIN_STATE_CHAIN:  # HACK for debugging
            prev_state = self._state

        if state is IsInIdle:
            self._state = state(self)
        else:
            self._state = state(self, cmd=cmd, cmd_sends=cmd_sends)

        if _DEBUG_MAINTAIN_STATE_CHAIN:  # HACK for debugging
            setattr(self._state, "_prev_state", prev_state)

        if self._ready_to_send:
            self._get_next_to_send()

    @property
    def state(self) -> _StateT:
        return self._state

    @property
    def _ready_to_send(self) -> bool:
        """Return True if the protocol is ready to send another command."""
        return isinstance(self.state, IsInIdle)

    def _is_active_cmd(self, cmd: Command) -> bool:
        """Return True if there is an active command and the supplied cmd is it."""
        return self.state.is_active_cmd(cmd)

    def connection_made(self, transport: _TransportT) -> None:
        _LOGGER.info(
            f"... Connection made when {self._state!r}: {transport.__class__.__name__}"
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
                *_, fut, _ = self._que.get_nowait()  # *priority, fut, expires
            except Empty:
                break
            fut.cancel()  # if not fut.done(): not required

        _LOGGER.info(f"... Connection lost when {self.state!r}, Exception: {exc}")
        self.state.lost_connection(exc)

    def pause_writing(self) -> None:  # not required?
        _LOGGER.info(f"... Writing paused, when {self.state!r}")
        self.state.writing_paused()

    def resume_writing(self) -> None:
        _LOGGER.info(f"... Writing resumed when {self.state!r}")
        self.state.writing_resumed()

    async def _wait_for_transition(self, old_state: _StateT, until: dt) -> _StateT:
        """Poll the state machine until it moves its context to another state.

        Raises a TimeoutError if the default timeout is exceeded.
        """

        _LOGGER.error(f"...  - WAITING to leave {old_state}...")
        while until > dt.now():
            if old_state._next_state:
                break
            await asyncio.sleep(POLLING_INTERVAL)
        else:
            _LOGGER.error(f"...  - FAILURE to leave {old_state} in time")
            raise SendTimeoutError(f"{self}: Failed to leave {old_state} in time")

        _LOGGER.error(
            f"...  - SUCCESS leaving  {old_state}, to {old_state._next_state.__name__}"
        )
        return old_state._next_state

    async def wait_for_rcvd_echo(
        self, cmd: Command, this_state: _StateT, timeout: float = _DEFAULT_ECHO_TIMEOUT
    ) -> None:
        """Wait until the state machine has received the expected echo pkt.

        Raises a SendTimeoutError if the timeout is exceeded before trasitioning.
        Raises a InvalidStateError if transitions to the incorrect state.
        """

        # assert isinstance(this_state, WantEcho) and this_state._is_active_cmd(cmd), (
        #     f"{self}: Not in the correct initial state: {WantEcho.__name__}"
        # )  # TODO: remove
        if isinstance(this_state, (WantRply if cmd.rx_header else IsInIdle)):
            return  # TODO: add is_active_cmd

        # may: SendTimeoutError (NB: may have already transitioned)
        next_state = await self._wait_for_transition(this_state, dt.now() + timeout)
        if next_state != (WantRply if cmd.rx_header else IsInIdle):
            raise InvalidStateError(
                f"{self}: Didn't transition to {next_state.__name__}"
            )

    async def wait_for_rcvd_rply(
        self, cmd: Command, this_state: _StateT, timeout: float = _DEFAULT_RPLY_TIMEOUT
    ) -> None:
        """Wait until the state machine has received the expected reply pkt.

        Raises a SendTimeoutError if the timeout is exceeded before trasitioning.
        Raises a InvalidStateError if transitiones to the incorrect state.
        """

        # assert isinstance(this_state, WantRply) and this_state._is_active_cmd(cmd), (
        #     f"{self}: Not in the correct initial state: {WantRply.__name__}"
        # )  # TODO: remove
        if isinstance(this_state, IsInIdle):
            return  # TODO: add is_active_cmd

        # may: SendTimeoutError (NB: may have already transitioned)
        next_state = await self._wait_for_transition(this_state, dt.now() + timeout)
        if next_state != IsInIdle:
            raise InvalidStateError(
                f"{self}: Didn't transition to {next_state.__name__}"
            )

    async def send_cmd(
        self,
        cmd: Command,
        timeout: float = DEFAULT_WAIT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        """When the state machine is Idle, transition to the WantEcho state.

        If the state machine is not Idle, teh command will join a priority queue.
        """

        _LOGGER.info(f"### Sending a cmd: {cmd}")

        if self._is_active_cmd(cmd):  # no need to queue...
            self.state.sent_cmd(cmd, max_retries)  # ?InvalidStateErr/RetryLimitExceeded
            return

        dt_sent = dt.now()
        fut = self._loop.create_future()
        self._que.put_nowait(
            (DEFAULT_SEND_PRIORITY, dt_sent, fut, dt_sent + td(seconds=timeout))
        )

        if self._ready_to_send:  # fut.set_result(None) for next cmd
            self._get_next_to_send()

        try:
            await asyncio.wait_for(fut, timeout)
        except TimeoutError:
            _LOGGER.warning("!!! wait_for(fut) has expired")
            fut.set_exception(SendTimeoutError("Timeout has expired (A2)"))

        fut.result()  # may raise exception
        self.state.sent_cmd(cmd, max_retries)  # ?InvalidStateErr/RetryLimitExceeded

    def pkt_received(self, pkt: Packet) -> None:
        _LOGGER.info(f"*** Receivd a pkt: {pkt}")
        self.state.rcvd_pkt(pkt)

    def _get_next_to_send(self) -> None:  # called by context
        """Recurse through the queue and notify the first 'ready' Future."""

        fut: asyncio.Future  # mypy

        try:
            *_, fut, expires = self._que.get_nowait()  # *priority, fut, expires
        except Empty:
            return

        if fut.done():
            self._get_next_to_send()
        elif expires <= dt.now():
            fut.set_exception(SendTimeoutError("Timeout has expired (A1)"))
        else:
            fut.set_result(None)


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

    def _set_context_state(self, state: _StateT, *args, **kwargs) -> None:
        self._next_state = state
        self._context.set_state(state, *args, **kwargs)  # pylint: disable=W0212

    def _retry_limit_exceeded(self):
        self._set_context_state(HasFailedRetries)

    def is_active_cmd(self, cmd: Command) -> bool:
        """Return True if there is an active command and the cmd is it."""
        return self.cmd and (
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

    def sent_cmd(self, cmd: Command, _: int) -> None:
        raise InvalidStateError(f"{self}: Not implemented")


class IsInactive(ProtocolStateBase):
    """Protocol has no active connection with a Transport."""

    def __repr__(self) -> str:
        assert self.cmd is None
        return f"{self.__class__.__name__}()"

    def rcvd_pkt(self, pkt: Packet) -> None:  # raise an exception
        raise InvalidStateError(f"{self}: Can't rcvd {pkt._hdr}: not connected")

    async def sent_cmd(self, cmd: Command, _: int) -> None:  # raise an exception
        raise InvalidStateError(f"{self}: Can't send {cmd._hdr}: not connected")


class IsPaused(ProtocolStateBase):
    """Protocol has active connection with a Transport, but should not send."""

    async def sent_cmd(self, cmd: Command, _: int) -> None:  # raise an exception
        raise InvalidStateError(f"{self}: Can't send {cmd._hdr}: paused")


class IsInIdle(ProtocolStateBase):
    """Protocol is available to send a Command (has no outstanding Commands)."""

    def sent_cmd(self, cmd: Command, max_retries: int) -> None:
        _LOGGER.debug(f"     - sending a cmd: {cmd._hdr}")
        self._set_context_state(WantEcho, cmd=cmd, cmd_sends=1)


class WantEcho(ProtocolStateBase):
    """Protocol is waiting for the local echo (has sent a Command)."""

    _fut: asyncio.Future
    _loop: asyncio.BaseEventLoop

    # TODO: consider enforcing retry limit in init

    def rcvd_pkt(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected echo."""

        if self.cmd.rx_header and pkt._hdr == self.cmd.rx_header:  # expected pkt
            raise InvalidStateError(f"{self}: Reply received before echo: {pkt._hdr}")

        if pkt._hdr != self.cmd.tx_header:
            _LOGGER.debug(f"     - received ????: {pkt._hdr} (unexpected, ignored)")

        elif self.cmd.rx_header:
            _LOGGER.debug(f"     - received echo: {pkt._hdr} (now expecting a reply)")
            self._set_context_state(WantRply, cmd=self.cmd, cmd_sends=self.cmd_sends)

        else:
            _LOGGER.debug(f"     - received echo: {pkt._hdr} (no reply expected)")
            self._set_context_state(IsInIdle)

    def sent_cmd(self, cmd: Command, max_retries: int) -> None:  # raise an exception
        """

        Raise InvalidStateError if sending command other than active command.
        Raise RetryLimitExceeded if sending command woudl exceed retry limit.
        """

        # if not self.is_active_cmd(cmd):  # handled by Context
        #     raise InvalidStateError(f"{self}: Can't send {cmd._hdr}: not active cmd")

        self.cmd_sends += 1
        if self.cmd_sends == max_retries:
            raise RetryLimitExceeded(f"{self}: Exceeded retry limit of {max_retries}")

        _LOGGER.debug(f"     - sending a cmd: {cmd._hdr} (again)")


class WantRply(WantEcho):
    """Protocol is now waiting for a response (has received the Command echo)."""

    def rcvd_pkt(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected response."""

        if pkt._hdr == self.cmd.tx_header:  # expected pkt
            _LOGGER.debug(f"     - received echo: {pkt._hdr} (again B2)")

        elif pkt._hdr != self.cmd.rx_header:
            _LOGGER.debug(f"     - received ????: {pkt._hdr} (unexpected, ignored)")

        elif pkt._hdr == self.cmd.rx_header:  # expected pkt
            _LOGGER.debug(f"     - received rply: {pkt._hdr} (as expected)")
            self._set_context_state(IsInIdle)


class HasFailed(ProtocolStateBase):
    """Protocol has rcvd the Command echo and is waiting for a response to be Rx'd."""

    def sent_cmd(self, cmd: Command, _: int) -> None:  # raise an exception
        raise InvalidStateError(f"{self}: Can't send {cmd._hdr}: in a failed state")


class HasFailedRetries(HasFailed):
    pass


_StateT = ProtocolStateBase  # TypeVar("_StateT", bound=ProtocolStateBase)


class ProtocolState:
    DEAD = IsInactive
    IDLE = IsInIdle
    ECHO = WantEcho
    RPLY = WantRply
