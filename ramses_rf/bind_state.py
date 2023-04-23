#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Base for all devices.
"""
from __future__ import annotations

import asyncio
import logging
from abc import ABC
from typing import TYPE_CHECKING, TypeVar

from .const import __dev_mode__

if TYPE_CHECKING:
    from typing import Callable

    from .device import Device


DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


TIMEOUT_SECS = 3
RETRY_LIMIT = 3


class BindError(Exception):
    """Base class for exceptions in this module."""

    pass


class BindFlowError(BindError):
    """An error in transition from one state to another."""

    pass


class BindRetryError(BindError):
    """Retry count exceeded."""

    pass


class BindTimeoutError(BindError):
    """An error in state."""

    pass


class Context:
    """The context is the Device class. It should be initiated with a default state."""

    _is_respondent: bool  # otherwise, is supplicant
    _state: State  # FIXME: should be: _State, but mypy says is unbound!!

    def __init__(self, device: Device, initial_state: type[_State]) -> None:
        self._dev = device

        if initial_state not in (Listening, Offering):
            raise BindFlowError(f"{self}: inital state must be Listening or Offering")
        self._is_respondent == initial_state is Listening
        self._set_context_state(initial_state)

    def __repr__(self) -> str:
        return f"{self._dev}: {self.role}: {self.state!r}"

    def __str__(self) -> str:
        return f"{self._dev.id}: {self.state}"

    def _set_context_state(self, state: type[_State]) -> None:
        """Change the State of the Context."""
        self._state = state(self)

    @property
    def role(self) -> str:
        return "respondent" if self._is_respondent else "supplicant"

    @property
    def state(self) -> str:
        return repr(self)

    def proc_offer(self, src: Device, _: Device) -> None:
        """Context has received an Offer pkt.

        It may be from the supplicant (self._dev is msg._src), or was cast to all
        listening devices.
        """
        # if self._is_respondent and src is self._dev:
        #     pass  # raise BindFlowError(f"{self}: unexpected Offer from itself")
        # elif not self._is_respondent and src is not self._dev:
        #     pass  # TODO: issue warning & return
        self._state.received_offer(src is self._dev)  # not self._is_respondent)

    def proc_accept(self, src: Device, _: Device) -> None:
        """Context has received an Accept pkt.

        It may be from the respondent (self._dev is msg._dst), or to the supplicant.
        """
        # if self._is_respondent and dst is not self._dev:
        #     pass  # TODO: issue warning & return
        # elif not self._is_respondent and src is self._dev:
        #     raise BindFlowError(f"{self}: unexpected Accept from itself")
        self._state.received_accept(src is self._dev)  # self._is_respondent)

    def proc_confirm(self, src: Device, _: Device) -> None:
        """Context has received a Confirm pkt.

        It may be from the supplicant (self._dev is msg._dst), or to the respondent.
        """
        # if self._is_respondent and src is self._dev:
        #     raise BindFlowError(f"{self}: unexpected Confirm from itself")
        # elif not self._is_respondent and src is not self._dev:
        #     pass  # TODO: issue warning & return
        self._state.received_confirm(src is self._dev)  # not self._is_respondent)

    def sent_offer(self) -> None:
        """Context has sent an Offer."""
        self._state.sent_offer()  # raises BindRetryError if RETRY_LIMIT exceeded

    def sent_accept(self) -> None:
        """Context has sent an Accept."""
        self._state.sent_accept()  # raises BindRetryError if RETRY_LIMIT exceeded

    def sent_confirm(self) -> None:
        """Context has sent an Confirm."""
        self._state.sent_confirm()  # raises BindRetryError if RETRY_LIMIT exceeded


def _no_offer_received(context):
    raise BindTimeoutError(f"{context}: no Offer received and timer expired")


def _no_accept_received(context):
    raise BindTimeoutError(f"{context}: no Accept received and timer expired")


def _no_confirm_received(context):
    raise BindTimeoutError(f"{context}: no Confirm received and timer expired")


class State(ABC):
    """The common state interface for all the states."""

    _proc_timeout: Callable | None = None
    _timer_handle: asyncio.TimerHandle
    _transmit_counter: int = 0

    def __init__(self, context: Context) -> None:
        self._context = context
        self._set_context_state: Callable = context._set_context_state  # HACK

        if self._proc_timeout:
            self._timer_handle = asyncio.get_running_loop().call_later(
                TIMEOUT_SECS, self._proc_timeout, self._context
            )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} (transmits={self._transmit_counter})"

    def __str__(self) -> str:
        return f"{self.__class__.__name__}"

    @property
    def context(self) -> Context:
        return self._context

    def received_offer(self, from_self: bool) -> None:  # treat as unexpected
        """Treat an Offer as unexpected (by default) and raise a BindFlowError."""
        raise BindFlowError(
            f"{self.context}: unexpected Offer from {'itself' if from_self else 'another'}"
        )

    def received_accept(self, from_self: bool) -> None:  # treat as unexpected
        """Treat an Accept as unexpected (by default) and raise a BindFlowError."""
        raise BindFlowError(
            f"{self.context}: unexpected Accept from {'itself' if from_self else 'another'}"
        )

    def received_confirm(self, from_self: bool) -> None:  # treat as unexpected
        """Treat a Confirm as unexpected (by default) and raise a BindFlowError."""
        raise BindFlowError(
            f"{self.context}: unexpected Confirm from {'itself' if from_self else 'another'}"
        )

    def sent_offer(self) -> None:  # treat as unexpected
        """Raise BindRetryError if the RETRY_LIMIT is exceeded."""
        raise BindFlowError(f"{self.context}: not expected to send an Offer")

    def sent_accept(self) -> None:  # treat as unexpected
        """Raise BindRetryError if the RETRY_LIMIT is exceeded."""
        raise BindFlowError(f"{self.context}: not expected to send an Accept")

    def sent_confirm(self) -> None:  # treat as unexpected
        """Raise BindRetryError if the RETRY_LIMIT is exceeded."""
        raise BindFlowError(f"{self.context}: not expected to send a Confirm")


class Listening(State):
    """Respondent has started listening, and is waiting for an Offer.

    It will continue to wait for an Offer, unless it times out.
    """

    # waiting for an Offer (until timeout expires)...
    _proc_timeout: Callable = _no_offer_received

    def received_offer(self, from_self: bool) -> None:
        if from_self:  # Respondents (listeners) shouldn't send Offers
            super().received_offer(from_self)  # TODO: log & ignore?
        self._timer_handle.cancel()
        self._set_context_state(Accepting)


class Offering(State):
    """Supplicant can send a Offer cmd."""

    # can send an Offer...
    def sent_offer(self) -> None:
        self._set_context_state(Offered)


class Offered(Offering):
    """Supplicant has sent an Offer, and is waiting for an Accept.

    It will continue to send Offers until it gets an Accept, or times out.
    """

    # has sent an Offer...
    _transmit_counter: int = 1  # already sent one

    def received_offer(self, from_self: bool) -> None:
        if not from_self:
            super().received_offer(from_self)  # TODO: log & ignore?

    def sent_offer(self) -> None:
        self._transmit_counter += 1
        if self._transmit_counter > RETRY_LIMIT:
            raise BindRetryError(f"{self._context}: sent excessive Offers)")

    # waiting for an Accept...
    _proc_timeout: Callable = _no_accept_received

    def received_accept(self, from_self: bool) -> None:
        if from_self:  # Supplicants shouldn't send Accepts
            super().received_accept(from_self)  # TODO: log & ignore?
        self._timer_handle.cancel()
        self._set_context_state(Confirming)


class Accepting(State):
    """Respondent has received an Offer, and can send an Accept cmd."""

    # no longer waiting for an Offer (handle retransmits from Supplicant)...
    def received_offer(self, from_self: bool) -> None:  # handle retransmits
        if from_self:  # Respondents (listeners) shouldn't send Offers
            super().received_offer(from_self)  # TODO: log & ignore?

    # can send an Accept...
    def sent_accept(self) -> None:
        self._set_context_state(Accepted)


class Accepted(Accepting):
    """Respondent has sent an Accept, and is waiting for a Confirm.

    It will continue to send Accepts, three times total, unless it times out.
    """

    # has sent an Accept...
    _transmit_counter: int = 1  # already sent one

    def received_accept(self, from_self: bool) -> None:
        if not from_self:
            super().received_accept(from_self)  # TODO: log & ignore?

    def sent_accept(self) -> None:
        self._transmit_counter += 1
        if self._transmit_counter > RETRY_LIMIT:
            raise BindRetryError(f"{self._context}: sent excessive Accepts)")

    # waiting for a Confirm...
    _proc_timeout: Callable = _no_confirm_received

    def received_confirm(self, from_self: bool) -> None:
        if from_self:  # Respondents (listeners) shouldn't send Confirms
            super().received_confirm(from_self)  # TODO: log & ignore?
        self._timer_handle.cancel()
        self._set_context_state(Bound)


class Confirming(State):
    """Supplicant has received an Accept, and can send a Confirm cmd.

    It will continue to send Confirms until it gets any pkt, or times out.
    """

    # no longer waiting for an Accept (handle retransmits from Respondent)...
    def received_accept(self, from_self: bool) -> None:  # handle retransmits
        if from_self:  # Supplicants shouldn't send Accepts
            super().received_accept(from_self)  # TODO: log & ignore?

    # can send a Confirm...
    def sent_confirm(self) -> None:
        self._set_context_state(Confirmed)


class Confirmed(Confirming):
    """Supplicant has sent a Confirm pkt.

    It will continue to send Confirms 3x.
    """

    # has sent a Confirm...
    _transmit_counter: int = 1  # already sent one

    def received_confirm(self, from_self: bool) -> None:
        if not from_self:
            super().received_confirm(from_self)  # TODO: log & ignore?

    def sent_confirm(self) -> None:
        self._transmit_counter += 1
        if self._transmit_counter == RETRY_LIMIT:
            self._set_context_state(Bound)


class Bound(State):
    """Context is Bound."""

    pass


class BoundAccepted(Accepting, Bound):  # FIXME: handle retransmits from supplicant
    """Respondent is Bound."""

    # waiting for a Confirm (until timeout expires)...
    _proc_timeout: Callable = lambda self: self.context.set_device_state(
        Bound(self.context)
    )

    # no longer waiting for a Confirm (handle retransmits from Supplicant)...
    def received_confirm(self, from_self: bool) -> None:
        if from_self:  # Respondents (listeners) shouldn't send Confirms
            super().received_confirm(from_self)  # TODO: log & ignore?


_State = TypeVar("_State", bound=State)
