#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - RAMSES-II compatible packet protocol finite state machine."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from typing import Callable

    from .command import Command
    from .packet import Packet


_TransportT = TypeVar("_TransportT", bound=asyncio.BaseTransport)


class ProtocolContext(asyncio.Protocol):  # mixin for tracking state
    """A mixin is to add state to a Protocol."""

    _state: _StateT

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._set_state(IsInactive)  # set initial state

    def _set_state(self, state: type[_StateT]) -> None:
        """Set the State of the Protocol (context)."""
        if not isinstance(state, HasFailed):  # FailedRetryLimit
            self._state = state(self, old_state=self._state)
        else:
            # TODO: do something about the fail (see self._state)
            self._state = IsWaitForCommand(self)  # drop old_state, if any

    def connection_made(self, transport: _TransportT) -> None:
        self._state.connection_made(transport)
        super().connection_made(transport)

    def connection_lost(self, exc: None | Exception) -> None:
        self._state.connection_lost(exc)
        super().connection_lost(exc)

    async def send_cmd(self, cmd: Command) -> None:
        await self._state.send_cmd(cmd)
        await super().send_cmd(cmd)  # type: ignore[misc]

    def data_received(self, pkt: Packet) -> None:  # type: ignore[override]
        self._state.data_received(pkt)
        super().data_received(pkt)  # type: ignore[arg-type]


_ContextT = ProtocolContext  # TypeVar("_ContextT", bound=ProtocolContext)


class ProtocolStateBase:
    def __init__(self, context: _ContextT, old_state: _StateT) -> None:
        self._context = context  # a Protocol
        self.cmd: None | Command = None
        self._num_sends: int = 0

        self._set_context_state: Callable = context._set_state  # pylint: disable=W0212

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} (tx={self._num_sends})"

    def __str__(self) -> str:
        return self.__class__.__name__

    def _retry_limit_exceeded(self):
        # self._error = "retry_limit_exceeded"
        self._set_context_state(HasFailedRetries)

    def connection_made(self, transport: _TransportT) -> None:
        self._set_context_state(IsWaitForCommand)  # initial state

    def connection_lost(self, exc: None | Exception) -> None:
        self._set_context_state(IsInactive)

    def data_received(self, pkt: Packet) -> None:
        pass

    async def send_cmd(self, cmd: Command) -> None:
        raise NotImplementedError


class IsInactive(ProtocolStateBase):
    """Protocol has no active connection with a Transport."""

    def data_received(self, pkt: Packet) -> None:  # raise an exception
        raise RuntimeError("Protocol shouldn't rcvd whilst not connected")

    async def send_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError("Protocol shouldn't send whilst not connected")


class IsWaitForCommand(ProtocolStateBase):
    """Protocol is available to send a Command (has no outstanding Commands)."""

    async def send_cmd(self, cmd: Command) -> None:
        # these two are required, so to pass on to next state (via old_state)
        self.cmd = cmd
        self._set_context_state(WantEchoPkt)


class WantEchoPkt(ProtocolStateBase):
    """Protocol is waiting for the local echo (has sent a Command)."""

    def __init__(self, context: _ContextT, old_state: _StateT) -> None:
        super().__init__(context, old_state)

        assert old_state and old_state.cmd  # for mypy

        self._num_sends = old_state._num_sends
        self.cmd = old_state.cmd

        if self._num_sends > self.cmd._qos.retry_limit:  # first send was not a retry
            self._retry_limit_exceeded()
        else:
            self._num_sends += 1

    def data_received(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected echo."""
        assert self.cmd  # for: mypy

        if pkt._hdr != self.cmd.tx_header:
            pass  # wait for timer to expire
        elif self.cmd._rx_header:  # if we're expecting a response
            self._set_context_state(IsWantResponsePkt)
        else:
            self._set_context_state(IsWaitForCommand)

    async def send_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError("Protocol should not send whilst waiting for an echo")


class IsWantResponsePkt(ProtocolStateBase):
    """Protocol is now waiting for a response (has received the Command echo)."""

    def __init__(self, context: _ContextT, old_state: _StateT) -> None:
        super().__init__(context, old_state)

        assert old_state and old_state.cmd  # for mypy

        self._num_sends = old_state._num_sends
        self.cmd = old_state.cmd

    def data_received(self, pkt: Packet) -> None:
        """The Transport has received a Packet, possibly the expected response."""
        assert self.cmd  # for mypy

        if pkt._hdr == self.cmd._rx_header:  # otherwise, wait for timer to expire
            self._set_context_state(IsWaitForCommand)

    async def send_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError("Protocol should not send whilst waiting for a response")


class HasFailed(ProtocolStateBase):
    """Protocol has rcvd the Command echo and is waiting for a response to be Rx'd."""

    def __init__(self, context: _ContextT, old_state: _StateT) -> None:
        super().__init__(context, old_state)

        assert old_state and old_state.cmd  # for mypy

        self._num_sends = old_state._num_sends
        self.cmd = old_state.cmd

    async def send_cmd(self, cmd: Command) -> None:  # raise an exception
        raise RuntimeError("Protocol should not send whilst in a Failed state")


class HasFailedRetries(HasFailed):
    pass


_StateT = ProtocolStateBase  # TypeVar("_StateT", bound=ProtocolStateBase)
