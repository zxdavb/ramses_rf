#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible packet protocol finite state machine."""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from typing import Callable

    from .command import Command
    from .packet import Packet


_TransportT = TypeVar("_TransportT", bound=asyncio.BaseTransport)


_LOGGER = logging.getLogger(__name__)


TIMEOUT_FOR_ECHO = 0.05
TIMEOUT_FOR_WAIT = 0.20  # incl. wait for echo
MAX_RETRIES_ECHO = 3
MAX_RETRIES_WAIT = 3  # incl. echo retries


class ProtocolContext:  # asyncio.Protocol):  # mixin for tracking state
    """A mixin is to add state to a Protocol."""

    _state: _StateT = None

    def __init__(self, protocol, *args, **kwargs) -> None:
        # super().__init__(*args, **kwargs)
        self._protocol = protocol

        self._set_state(IsInactive)  # set initial state

    def _set_state(self, state: type[_StateT]) -> None:
        """Set the State of the Protocol (context)."""
        if state == IsIdle:
            self._state = state(self)
        elif state != HasFailed:  # FailedRetryLimit
            self._state = state(self, old_state=self._state)
        else:
            # TODO: do something about the fail (see self._state)
            self._state = IsIdle(self)  # drop old_state, if any

    def connection_made(self, transport: _TransportT) -> None:
        self._state.made_connection(transport)

    def connection_lost(self, exc: None | Exception) -> None:
        self._state.lost_connection(exc)

    def pause_writing(self) -> None:  # not required?
        self._state.writing_paused()

    def resume_writing(self) -> None:
        self._state.writing_resumed()

    def send_cmd(self, cmd: Command) -> None:
        if not isinstance(self._state, IsIdle):
            raise RuntimeError
        self._state.sent_cmd(cmd)

    def pkt_received(self, pkt: Packet) -> None:
        self._state.rcvd_pkt(pkt)


_ContextT = ProtocolContext  # TypeVar("_ContextT", bound=ProtocolContext)


class ProtocolStateBase:
    # state attrs
    cmd: None | Command
    cmd_sends: int

    def __init__(self, context: _ContextT, old_state: None | _StateT = None) -> None:
        self._context = context  # a Protocol
        self._set_context_state: Callable = context._set_state  # pylint: disable=W0212

        self.cmd: None | Command = getattr(old_state, "cmd", None)
        self.cmd_sends: None | int = getattr(old_state, "cmd_sends", 0)

        _LOGGER.error(f"State changed to {self!r}")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"

    def __str__(self) -> str:
        return self.__class__.__name__

    def _retry_limit_exceeded(self):
        self._set_context_state(HasFailedRetries)

    def made_connection(self, transport: _TransportT) -> None:  # FIXME: may be paused
        self._set_context_state(IsIdle)  # initial state (assumes not paused)

    def lost_connection(self, exc: None | Exception) -> None:
        self._set_context_state(IsInactive)

    def writing_paused(self) -> None:
        self._set_context_state(IsInactive)

    def writing_resumed(self) -> None:
        self._set_context_state(IsIdle)

    def rcvd_pkt(self, pkt: Packet) -> None:
        pass

    def sent_cmd(self, cmd: Command) -> None:
        raise NotImplementedError


class IsInactive(ProtocolStateBase):
    """Protocol has no active connection with a Transport."""

    def rcvd_pkt(self, pkt: Packet) -> None:  # raise an exception
        raise RuntimeError("Protocol shouldn't rcvd whilst not connected")

    async def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError("Protocol shouldn't send whilst not connected")


class IsPaused(ProtocolStateBase):
    """Protocol has active connection with a Transport, but shoudl not send."""

    async def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError("Protocol shouldn't send whilst not connected")


class IsIdle(ProtocolStateBase):
    """Protocol is available to send a Command (has no outstanding Commands)."""

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(hdr={self.cmd})"

    def sent_cmd(self, cmd: Command) -> None:
        # these two are required, so to pass on to next state (via old_state)
        self.cmd = cmd
        self.cmd_sends += 1
        self._set_context_state(WantEcho)


class WantEcho(ProtocolStateBase):
    """Protocol is waiting for the local echo (has sent a Command)."""

    def __init__(self, context: _ContextT, old_state: None | _StateT = None) -> None:
        super().__init__(context, old_state=old_state)

        assert old_state and old_state.cmd  # for mypy

        if self.cmd_sends > self.cmd._qos.retry_limit:  # first send was not a retry
            self._retry_limit_exceeded()

    def __repr__(self) -> str:
        hdr = self.cmd.tx_header if self.cmd else None
        return f"{self.__class__.__name__}(hdr={hdr}, tx={self.cmd_sends})"

    def rcvd_pkt(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected echo."""

        if self.cmd.rx_header:  # if we're expecting a response
            self._set_context_state(WantResponse)
        elif pkt._hdr == self.cmd.tx_header:
            self._set_context_state(IsIdle)
        else:
            pass  # wait for timer to expire

    def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError("Protocol should not send whilst waiting for an echo")


class WantResponse(ProtocolStateBase):
    """Protocol is now waiting for a response (has received the Command echo)."""

    def __init__(self, context: _ContextT, old_state: None | _StateT = None) -> None:
        super().__init__(context, old_state=old_state)

        assert old_state and old_state.cmd  # for mypy

    def __repr__(self) -> str:
        hdr = self.cmd.rx_header if self.cmd else None
        return f"{self.__class__.__name__}(hdr={hdr}, tx={self.cmd_sends})"

    def rcvd_pkt(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected response."""
        assert self.cmd  # for mypy

        if pkt._hdr == self.cmd.tx_header:  # otherwise, wait for timer to expire
            raise RuntimeError("Duplicate echo packet")  # make logger.warning
        elif pkt._hdr == self.cmd.rx_header:  # otherwise, wait for timer to expire
            self._set_context_state(IsIdle)
        else:  # otherwise, wait for timer to expire
            pass

    def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError("Protocol should not send whilst waiting for a response")


class HasFailed(ProtocolStateBase):
    """Protocol has rcvd the Command echo and is waiting for a response to be Rx'd."""

    def __init__(self, context: _ContextT, old_state: None | _StateT = None) -> None:
        super().__init__(context, old_state=old_state)

        assert old_state and old_state.cmd  # for mypy

    def sent_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError("Protocol should not send whilst in a Failed state")


class HasFailedRetries(HasFailed):
    pass


_StateT = ProtocolStateBase  # TypeVar("_StateT", bound=ProtocolStateBase)


class ProtocolState:
    DEAD = IsInactive  # #      #
    IDLE = IsIdle  # ##
    ECHO = WantEcho  # #     #
    WAIT = WantResponse  # #
