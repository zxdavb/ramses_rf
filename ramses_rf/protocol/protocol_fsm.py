#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible packet protocol finite state machine."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime as dt
from datetime import timedelta as td
from enum import IntEnum
from queue import Empty, Full, PriorityQueue
from threading import BoundedSemaphore
from typing import TYPE_CHECKING, Awaitable, TypeVar

# from .const import SZ_SIGNATURE
from .exceptions import ProtocolFsmError, ProtocolSendFailed

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
    from . import Command, Packet

_TransportT = TypeVar("_TransportT", bound=asyncio.BaseTransport)


_LOGGER = logging.getLogger(__name__)

# All debug flags should be False for end-users
_DEBUG_MAINTAIN_STATE_CHAIN = False  # maintain Context._prev_state


class SendPriority(IntEnum):
    _MAX = -9
    HIGH = -2
    DEFAULT = 0
    LOW = 2
    _MIN = 9


DEFAULT_PRIORITY = SendPriority.DEFAULT

DEFAULT_TIMEOUT = 3.0  # total waiting for successful send
DEFAULT_ECHO_TIMEOUT = 0.50  # waiting for echo pkt after cmd sent
DEFAULT_RPLY_TIMEOUT = 0.50  # waiting for reply pkt after echo pkt received

_DEFAULT_TIMEOUT = td(seconds=DEFAULT_TIMEOUT)
_DEFAULT_ECHO_TIMEOUT = td(seconds=DEFAULT_ECHO_TIMEOUT)
_DEFAULT_RPLY_TIMEOUT = td(seconds=DEFAULT_RPLY_TIMEOUT)

DEFAULT_MAX_RETRIES = 3

POLLING_INTERVAL = 0.0005


class _ProtocolWaitFailed(ProtocolSendFailed):
    """The Command timed out when waiting for its turn to send."""


class _ProtocolEchoFailed(ProtocolSendFailed):
    """The Command was sent OK, but failed to elicit its echo."""


class _ProtocolRplyFailed(ProtocolSendFailed):
    """The Command received an echo OK, but failed to elicit the expected reply."""


class ProtocolContext:
    """A mixin is to add state to a Protocol."""

    MAX_BUFFER_SIZE: int = 10

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
        self,
        state: type[_StateT],
        cmd: None | Command = None,
        cmd_sends: int = 0,
    ) -> None:
        """Set the State of the Protocol (context)."""

        # assert not isinstance(self._state, state)  # check a transition has occurred
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
            self._notify_next_queued_cmd()

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
                *_, fut = self._que.get_nowait()  # *priority, cmd, expires, fut
            except Empty:
                break
            fut.cancel()  # if not fut.done(): not required as can cancel if done

        _LOGGER.info(f"... Connection lost when {self.state!r}, Exception: {exc}")
        self.state.lost_connection(exc)

    def pause_writing(self) -> None:  # not required?
        _LOGGER.info(f"... Writing paused, when {self.state!r}")
        self.state.writing_paused()

    def resume_writing(self) -> None:
        _LOGGER.info(f"... Writing resumed when {self.state!r}")
        self.state.writing_resumed()

    async def send_cmd(
        self,
        send_fnc: Awaitable,
        cmd: Command,
        max_retries: int = DEFAULT_MAX_RETRIES,
        wait_for_reply: None | bool = None,
        wait_timeout: float = DEFAULT_TIMEOUT,
    ) -> Packet:
        """Wrapper to send a command with retries, until success or Exception."""

        # if cmd.code == Code._PUZZ:
        #     self._handle_puzzle_cmd(cmd)

        while True:  # if required, resend until RetryLimitExceeded
            try:  # _wait_for_can_send
                prev_state, next_state = await self._wait_for_can_send(
                    self.state, cmd, td(seconds=wait_timeout)
                )
                assert isinstance(self.state, _ProtocolState.IDLE)

                self.state.sent_cmd(cmd, max_retries)  # must be *before* actually sent
                assert isinstance(self.state, _ProtocolState.ECHO)

            except (AssertionError, ProtocolFsmError, ProtocolSendFailed) as exc:
                raise _ProtocolWaitFailed(
                    f"{self}: Failed ready to send command:  {exc}"
                )

            await send_fnc(cmd)  # the wrapped function

            try:  # _wait_for_rcvd_echo & prev_state._echo
                prev_state, next_state = await self._wait_for_rcvd_echo(
                    self.state, cmd, _DEFAULT_ECHO_TIMEOUT
                )
                assert isinstance(
                    self.state, (_ProtocolState.RPLY, _ProtocolState.IDLE)
                )
                assert prev_state._echo

                # if prev_state._echo.code == Code._PUZZ:
                #     self._handle_puzzle_pkt(prev_state._echo)
                #     # self.set_state(ProtocolState.IDLE)  # will happen next
                #     # assert isinstance(next_state, ProtocolState.IDLE)
                #     # return prev_state._echo

                if (
                    wait_for_reply is False
                    or (wait_for_reply is None and cmd.verb != RQ)
                    or cmd.code == Code._1FC9  # otherwise issues with binding FSM
                ):
                    # binding FSM is implemented at higher layer
                    self.set_state(_ProtocolState.IDLE)  # maybe was: ProtocolState.RPLY
                    assert isinstance(next_state, _ProtocolState.IDLE)
                    return prev_state._echo

                if not cmd.rx_header:  # no reply to wait for
                    # self.set_state(ProtocolState.IDLE)  # state will do this
                    assert isinstance(next_state, _ProtocolState.IDLE)
                    return prev_state._echo

                assert isinstance(next_state, _ProtocolState.RPLY)

            except (AssertionError, ProtocolFsmError, ProtocolSendFailed) as exc:
                # if cmd.code == Code._PUZZ and self._is_active_puzzle_cmd(cmd):
                #     continue
                raise _ProtocolEchoFailed(
                    f"{self}: Failed to receive echo packet: {exc}"
                )

            try:  # _wait_for_rcvd_rply & prev_state._rply
                prev_state, next_state = await self._wait_for_rcvd_rply(
                    next_state, cmd, _DEFAULT_RPLY_TIMEOUT
                )  # NOTE: is next_state, not self.state
                assert isinstance(next_state, _ProtocolState.IDLE)
                assert prev_state._rply

            except (AssertionError, ProtocolFsmError, ProtocolSendFailed) as exc:
                raise _ProtocolRplyFailed(
                    f"{self}: Failed to receive rply packet: {exc}"
                )

            break  # TODO: remove

        return prev_state._rply

    def _handle_puzzle_cmd(self, cmd: Command) -> None:
        """Ensure the puzzle packet is not filtered out by the transport."""

        # self._protocol._transport._extra[SZ_SIGNATURE] = cmd.payload
        self._puzzle_cmd = cmd
        self._puzzle_num_sent = 0

    def _handle_puzzle_pkt(self, pkt: Command) -> None:
        """Update the transport filters, according to the puzzle packet."""

        if pkt.payload[2:4] != "11":
            return
        self._puzzle_cmd = None

    def _is_active_puzzle_cmd(self, cmd: Command) -> bool:
        """Return True if there is an acive puzzle Command, and this is it."""

        result = self._puzzle_cmd and self._puzzle_cmd.payload == cmd.payload
        if not result:
            return False
        self._puzzle_num_sent += 1
        if self._puzzle_num_sent > 20:
            return False
        return True

    async def _wait_for_can_send(
        self, this_state: _StateT, cmd: Command, timeout: td
    ) -> tuple[_StateT, _StateT]:
        """Wait until state machine is such that this context can (re-)send.

        When required, wait until the FSM is/becomes Idle, then transition to the
        WantEcho state. If it is not Idle, the command will join a priority queue.

        Raises a ProtocolFsmError if transitions from/to an invalid state.
        Raises a ProtocolWaitFailed if the timeout is exceeded before transitioning.
        """

        _LOGGER.info(f"### Waiting to send a command for:  {cmd}")

        if self._is_active_cmd(cmd):  # no need to queue...
            return this_state, self.state

        dt_sent = dt.now()
        fut = self._loop.create_future()
        try:
            self._que.put_nowait(
                (DEFAULT_PRIORITY, dt_sent, cmd, dt_sent + timeout, fut)
            )
        except Full:
            _LOGGER.error(f"### Queue is full, discarded:       {cmd._hdr}")
            self._notify_next_queued_cmd()  # remove all the cancelled futs

        if self._ready_to_send:  # fut.set_result(None) for next cmd
            self._notify_next_queued_cmd()

        try:
            await asyncio.wait_for(fut, timeout.total_seconds())
        except asyncio.TimeoutError as exc:
            _LOGGER.warning(f"!!! wait_for(fut): {exc}")
            fut.set_exception(ProtocolSendFailed("wait_for_can_send() timeout expired"))
        except ProtocolSendFailed as exc:  # TODO: remove. not needed?
            _LOGGER.warning(f"!!! wait_for(fut): {exc}")

        if isinstance(self.state, WantEcho):
            raise ProtocolFsmError(f"Bad transition to {self.state}")

        fut.result()  # may: raise ProtocolSendFailed
        return this_state, self.state  # TODO: should have this_state._cmd_

    async def _wait_for_transition(self, old_state: _StateT, until: dt) -> _StateT:
        """Return the new state that the context transitioned to from the old state..

        Raises a TimeoutError if a transition doesn't occur before the timer expires.
        """

        _LOGGER.debug(f"...  - WAITING to leave {old_state}...")
        while until > dt.now():
            if old_state._next_state:
                break
            await asyncio.sleep(POLLING_INTERVAL)
        else:
            _LOGGER.debug(f"...  - FAILURE to leave {old_state} in time")
            raise ProtocolFsmError(f"Failed to leave {old_state} in time")

        _LOGGER.debug(
            f"...  - SUCCESS leaving  {old_state}, to {old_state._next_state}"
        )
        return old_state._next_state

    async def _wait_for_rcvd_echo(
        self, this_state: _StateT, cmd: Command, timeout: dt
    ) -> tuple[_StateT, _StateT]:
        """Wait until the state machine has received the expected echo pkt.

        Raises a InvalidStateError if transitions to the incorrect state.
        Raises a SendTimeoutError if the timeout is exceeded before transitioning.
        """

        _LOGGER.info(f"### Waiting to receive an echo for: {cmd}")

        if not isinstance(this_state, (WantEcho, WantRply)):
            raise ProtocolFsmError(f"Bad transition from {this_state}")

        # may: SendTimeoutError (NB: may have already transitioned)
        next_state = await self._wait_for_transition(this_state, dt.now() + timeout)

        if not isinstance(next_state, (WantRply if cmd.rx_header else IsInIdle)):
            raise ProtocolFsmError(f"Bad transition to {next_state}")

        return this_state, next_state  # for: this_state._echo

    async def _wait_for_rcvd_rply(
        self, this_state: _StateT, cmd: Command, timeout: dt
    ) -> tuple[_StateT, _StateT]:
        """Wait until the state machine has received the expected reply pkt.

        Raises a InvalidStateError if transitiones to the incorrect state.
        Raises a SendTimeoutError if the timeout is exceeded before transitioning.
        """

        _LOGGER.info(f"### Waiting to receive a reply for: {cmd}")

        if not isinstance(this_state, WantRply):
            raise ProtocolFsmError(f"Bad transition from {this_state}")

        # may: SendTimeoutError (NB: may have already transitioned)
        next_state = await self._wait_for_transition(this_state, dt.now() + timeout)

        if not isinstance(next_state, IsInIdle):
            raise ProtocolFsmError(f"Bad transition to {next_state}")

        return this_state, next_state  # for: this_state._rply

    def pkt_received(self, pkt: Packet) -> None:
        _LOGGER.info(f"*** Receivd a pkt: {pkt}")
        self.state.rcvd_pkt(pkt)

    def _notify_next_queued_cmd(self) -> None:
        """Recurse through the queue and notify the first 'ready' Future.

        The next Command is notified by setting it's fut.set_result(None)'
        Expired Commands have fut.set_exception().
        """

        fut: asyncio.Future  # mypy

        try:
            *_, expires, fut = self._que.get_nowait()  # *priority, cmd, expires, fut
        except Empty:
            return

        self._que.task_done()

        if fut.cancelled():  # incl. cancelled()
            _LOGGER.error(f"### Cancelled command:              {_}")
            self._notify_next_queued_cmd()  # NOTE: recursion
        elif fut.done():  # incl. cancelled()
            _LOGGER.error(f"### Completed command:              {_}")
            self._notify_next_queued_cmd()  # NOTE: recursion
        elif expires <= dt.now():
            _LOGGER.error(f"### Expired command:                {_}")
            fut.set_exception(ProtocolSendFailed("Timeout has expired (A1)"))
        else:
            _LOGGER.error(f"### Activated command:              {_}")
            fut.set_result(None)


class ProtocolStateBase:
    # state attrs
    cmd: None | Command
    cmd_sends: int

    _next_state: None | _StateT = None

    def __init__(
        self,
        context: ProtocolContext,
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
        self._context.set_state(state, *args, **kwargs)  # pylint: disable=W0212
        self._next_state = self._context.state

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

    def sent_cmd(self, cmd: Command, max_retries: int) -> None:  # raise an exception
        raise ProtocolFsmError(f"{self}: Not implemented")


class IsInactive(ProtocolStateBase):
    """Protocol has no active connection with a Transport."""

    def __repr__(self) -> str:
        assert self.cmd is None
        return f"{self.__class__.__name__}()"

    # method should be OK, but for a timing issue in _make_connection_after_signature()
    # means pkt received here *before* state changed by state.connection_made()
    # def rcvd_pkt(self, pkt: Packet) -> None:  # raise an exception
    #     raise ProtocolFsmError(f"{self}: Can't rcvd {pkt._hdr}: not connected")

    def sent_cmd(self, cmd: Command, max_retries: int) -> None:  # raise an exception
        raise ProtocolFsmError(f"{self}: Can't send {cmd._hdr}: not connected")


class IsPaused(ProtocolStateBase):
    """Protocol has active connection with a Transport, but should not send."""

    def sent_cmd(self, cmd: Command, max_retries: int) -> None:  # raise an exception
        raise ProtocolFsmError(f"{self}: Can't send {cmd._hdr}: paused")


class IsInIdle(ProtocolStateBase):
    """Protocol is available to send a Command (has no outstanding Commands)."""

    _cmd_: None | Command = None  # used only for debugging

    def sent_cmd(self, cmd: Command, max_retries: int) -> None:
        _LOGGER.debug(f"     - sending a cmd: {cmd._hdr}")
        self._cmd_ = cmd
        self._set_context_state(WantEcho, cmd=cmd, cmd_sends=1)


class WantEcho(ProtocolStateBase):
    """Protocol is waiting for the local echo (has sent a Command)."""

    _echo: None | Packet = None

    def rcvd_pkt(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected echo."""

        if self.cmd.rx_header and pkt._hdr == self.cmd.rx_header:  # expected pkt
            raise ProtocolFsmError(f"{self}: Reply received before echo: {pkt._hdr}")

        if pkt._hdr != self.cmd.tx_header:
            _LOGGER.debug(f"     - received pkt_: {pkt._hdr} (unexpected, ignored)")

        elif self.cmd.rx_header:
            _LOGGER.debug(f"     - received echo: {pkt._hdr} (now expecting a reply)")
            self._echo = pkt
            self._set_context_state(WantRply, cmd=self.cmd, cmd_sends=self.cmd_sends)

        else:
            _LOGGER.debug(f"     - received echo: {pkt._hdr} (no reply expected)")
            self._echo = pkt
            self._set_context_state(IsInIdle)

    def sent_cmd(self, cmd: Command, max_retries: int) -> None:  # raise an exception
        raise ProtocolSendFailed(f"{self}: Can't re-send {cmd._hdr}: not received echo")


class WantRply(ProtocolStateBase):
    """Protocol is now waiting for a response (has received the Command echo)."""

    _rply: None | Packet = None

    def rcvd_pkt(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected response."""

        if pkt._hdr == self.cmd.tx_header:  # expected pkt
            _LOGGER.debug(f"     - received echo: {pkt._hdr} (again B2)")

        elif pkt._hdr != self.cmd.rx_header:
            _LOGGER.debug(f"     - received pkt_: {pkt._hdr} (unexpected, ignored)")

        elif pkt._hdr == self.cmd.rx_header:  # expected pkt
            _LOGGER.debug(f"     - received rply: {pkt._hdr} (as expected)")
            self._rply = pkt
            self._set_context_state(IsInIdle)

    def sent_cmd(self, cmd: Command, max_retries: int) -> None:
        """The Transport has re-sent a Command.

        Raise InvalidStateError if sending command other than active command.
        Raise RetryLimitExceeded if sending command woudl exceed retry limit.
        """

        # if not self.is_active_cmd(cmd):  # handled by Context
        #     raise InvalidStateError(f"{self}: Can't send {cmd._hdr}: not active cmd")

        if self.cmd_sends > max_retries:
            raise ProtocolSendFailed(f"{self}: Exceeded retry limit of {max_retries}")
        self.cmd_sends += 1
        _LOGGER.debug(f"     - sending cmd..: {cmd._hdr} (again)")


class HasFailed(ProtocolStateBase):
    """Protocol has rcvd the Command echo and is waiting for a response to be Rx'd."""

    def sent_cmd(self, cmd: Command, max_retries: int) -> None:  # raise an exception
        raise ProtocolFsmError(f"{self}: Can't send {cmd._hdr}: in a failed state")


_StateT = ProtocolStateBase


class _ProtocolState:
    DEAD = IsInactive
    IDLE = IsInIdle
    ECHO = WantEcho
    RPLY = WantRply
