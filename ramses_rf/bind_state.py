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

if TYPE_CHECKING:
    from typing import Callable

    from .device import Address, Command, Message
    from .device.base import Fakeable

# skipcq: PY-W2000
from .device import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

from . import __dev_mode__

DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


TIMEOUT_SECS = 3
RETRY_LIMIT = 3


__all__ = ["Exceptions", "Context", "BindState"]


class BindError(Exception):
    """Base class for exceptions in this module."""

    pass


class BindFlowError(BindError):
    """An error in transition from one state to another."""

    pass


class BindRetryError(BindError):
    """Retry count exceeded."""

    pass


class BindStateError(BindError):
    """An error in the (initial) state of the Device."""

    pass


class BindTimeoutError(BindError):
    """An error in state."""

    pass


class Exceptions:  # HACK  ???
    BindError = BindError
    BindFlowError = BindFlowError
    BindRetryError = BindRetryError
    BindStateError = BindStateError
    BindTimeoutError = BindTimeoutError


class Context:
    """The context is the Device class. It should be initiated with a default state."""

    _is_respondent: bool  # otherwise, must be supplicant
    _state: _State = None  # type: ignore[assignment]

    def __init__(self, dev: _Device, initial_state: type[_State]) -> None:
        self._dev = dev

        if initial_state not in (Listening, Offering):
            raise BindStateError(f"{self}: Incompatible inital state: {initial_state}")

        self._is_respondent = initial_state is Listening
        self._set_context_state(initial_state)

    def __repr__(self) -> str:
        return f"{self._dev}: {self.role}: {self.state!r}"

    def __str__(self) -> str:
        return f"{self._dev.id}: {self.state}"

    def _set_context_state(self, state: type[_State]) -> None:
        """Change the State of the Context."""
        self._state = state(self)

    @classmethod
    def respondent(cls, dev: _Device) -> Context:  # HACK: using _context is regrettable
        """Create a new Context only if the Device is coming from a suitable state."""
        if dev._context is not None and type(dev._context.state) in _BAD_PREV_STATES:
            raise BindStateError(
                f"{dev}: incompatible current State for Device: {dev._context}"
            )
        return cls(dev, BindState.LISTENING)

    @classmethod
    def supplicant(cls, dev: _Device) -> Context:  # HACK: using _context is regrettable
        """Create a new Context only if the Device is coming from a suitable state."""
        if dev._context is not None and type(dev._context.state) in _BAD_PREV_STATES:
            raise BindStateError(
                f"{dev}: incompatible current State for Device: {dev._context}"
            )
        return cls(dev, BindState.OFFERING)

    @property
    def role(self) -> str:
        return "respondent" if self._is_respondent else "supplicant"

    @property
    def state(self) -> _State:
        return self._state

    def rcvd_msg(self, msg: Message) -> None:
        # Can assume the packet payloads have past validation
        if msg.verb == I_ and msg.src is msg.dst:  # msg["phase"] == "offer":
            self._rcvd_offer(msg.src)
        elif msg.verb == W_:  # msg["phase"] == "accept":
            self._rcvd_accept(msg.src)
        elif msg.verb == I_:  # msg["phase"] == "confirm":
            self._rcvd_confirm(msg.src)

    def _rcvd_offer(self, src: Address) -> None:
        """Context has received an Offer pkt.

        It may be from the supplicant (self._dev is msg._src), or was cast to all
        listening devices.
        """
        # if self._is_respondent and src is self._dev:
        #     pass  # raise BindFlowError(f"{self}: unexpected Offer from itself")
        # elif not self._is_respondent and src is not self._dev:
        #     pass  # TODO: issue warning & return
        self._state.received_offer(src is self._dev)  # not self._is_respondent)

    def _rcvd_accept(self, src: Address) -> None:
        """Context has received an Accept pkt.

        It may be from the respondent (self._dev is msg._dst), or to the supplicant.
        """
        # if self._is_respondent and dst is not self._dev:
        #     pass  # TODO: issue warning & return
        # elif not self._is_respondent and src is self._dev:
        #     raise BindFlowError(f"{self}: unexpected Accept from itself")
        self._state.received_accept(src is self._dev)  # self._is_respondent)

    def _rcvd_confirm(self, src: Address) -> None:
        """Context has received a Confirm pkt.

        It may be from the supplicant (self._dev is msg._dst), or to the respondent.
        """
        # if self._is_respondent and src is self._dev:
        #     raise BindFlowError(f"{self}: unexpected Confirm from itself")
        # elif not self._is_respondent and src is not self._dev:
        #     pass  # TODO: issue warning & return
        self._state.received_confirm(src is self._dev)  # not self._is_respondent)

    def sent_cmd(self, cmd: Command) -> None:
        # Assume the packet meta-data is valid
        if cmd.verb == I_ and cmd.src is cmd.dst:
            self._sent_offer()
        elif cmd.verb == W_:  # and cmd.src is self:
            self._sent_accept()
        elif cmd.verb == I_:  # and cmd.src is self:
            self._sent_confirm()
        else:
            raise RuntimeError  # TODO: better error message

    def _sent_offer(self) -> None:
        """Context has sent an Offer."""
        self._state.sent_offer()  # raises BindRetryError if RETRY_LIMIT exceeded

    def _sent_accept(self) -> None:
        """Context has sent an Accept."""
        self._state.sent_accept()  # raises BindRetryError if RETRY_LIMIT exceeded

    def _sent_confirm(self) -> None:
        """Context has sent an Confirm."""
        self._state.sent_confirm()  # raises BindRetryError if RETRY_LIMIT exceeded


class State(ABC):
    """The common state interface for all the states."""

    _has_expiry_timer: bool = False
    _timer_handle: asyncio.TimerHandle

    _cmds_sent: int = 0  # num of bind cmds sent
    _pkts_rcvd: int = 0  # num of bind pkts rcvd (could be an echo of sender's cmd)

    def __init__(self, context: Context) -> None:
        self._context = context
        self._set_context_state: Callable = context._set_context_state  # HACK
        self._prev_state: _State | None = self._context.state

        _LOGGER.debug(f"{self}: Changing state from: {self._context.state} to: {self}")

        if self._has_expiry_timer:
            self._timer_handle = asyncio.get_running_loop().call_later(
                TIMEOUT_SECS, self._wait_timer_expired
            )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} (rx={self._pkts_rcvd}, tx={self._cmds_sent})"

    def __str__(self) -> str:
        return self.__class__.__name__

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

    def _retries_execeeded(self) -> None:
        """Process an overrun of the RETRY_LIMIT when sending a Command.

        The Tx retry limit has been exceeded, with nothing heard from the other device.
        """

        self._set_context_state(Unknown)
        _LOGGER.warning(
            f"{self._context}: {RETRY_LIMIT} commands sent, but no response received" ""
        )  # was: BindRetryError

    def _wait_timer_expired(self) -> None:
        """Process an overrun of the TIMEOUT_SECS when waiting for a Packet.

        The Rx wait time has been exceeded, with nothing heard from the other device.
        """
        self._set_context_state(Unknown)
        _LOGGER.warning(
            f"{self._context}: {TIMEOUT_SECS} secs passed, but no response received"
        )  # was: BindTimeoutError


class Unknown(State):
    _warning_sent: bool = False

    def _send_warning_if_not_already_sent(self) -> None:
        if self._warning_sent:
            return

        self._warning_sent = True
        raise BindStateError(f"{self}: Current state is Unknown")

    def received_offer(self, from_self: bool) -> None:
        self._send_warning_if_not_already_sent()

    def received_accept(self, from_self: bool) -> None:
        self._send_warning_if_not_already_sent()

    def received_confirm(self, from_self: bool) -> None:
        self._send_warning_if_not_already_sent()

    def sent_offer(self) -> None:
        self._send_warning_if_not_already_sent()

    def sent_accept(self) -> None:
        self._send_warning_if_not_already_sent()

    def sent_confirm(self) -> None:
        self._send_warning_if_not_already_sent()


class Listening(State):
    """Respondent has started listening, and is waiting for an Offer.

    It will continue to wait for an Offer, unless it times out.
    """

    # waiting for an Offer (until timeout expires)...
    _has_expiry_timer: bool = True

    def received_offer(self, from_self: bool) -> None:
        if from_self:  # Respondents (listeners) shouldn't send Offers
            super().received_offer(from_self)  # TODO: log & ignore?
        self._timer_handle.cancel()
        self._set_context_state(Accepting)


class Offering(State):
    """Supplicant can send a Offer cmd."""

    # can send an Offer (anytime now)...
    def sent_offer(self) -> None:
        self._set_context_state(Offered)


class Offered(Offering):
    """Supplicant has sent an Offer, and is waiting for an Accept.

    It will continue to send Offers until it gets an Accept, or times out.
    """

    # has sent an Offer...
    _cmds_sent: int = 1  # already sent one

    def received_offer(self, from_self: bool) -> None:
        if not from_self:
            pass  # TODO: log & ignore?
        _LOGGER.warning(f"{self.context}: Offer received before sent")

    def sent_offer(self) -> None:
        self._cmds_sent += 1
        if self._cmds_sent > RETRY_LIMIT:
            self._retries_execeeded()

    # waiting for an Accept...
    _has_expiry_timer: bool = True

    def received_accept(self, from_self: bool) -> None:
        if from_self:  # Supplicants shouldn't send Accepts
            super().received_accept(from_self)  # TODO: log & ignore?
        self._timer_handle.cancel()
        self._set_context_state(Confirming)


class Accepting(State):  # aka Listened
    """Respondent has received an Offer, and can send an Accept cmd."""

    # no longer waiting for an Offer (handle retransmits from Supplicant)...
    def received_offer(self, from_self: bool) -> None:  # handle retransmits
        if from_self:  # Respondents (listeners) shouldn't send Offers
            super().received_offer(from_self)  # TODO: log & ignore?

    # can send an Accept anytime now...
    def sent_accept(self) -> None:
        self._set_context_state(Accepted)


class Accepted(Accepting):
    """Respondent has sent an Accept, and is waiting for a Confirm.

    It will continue to send Accepts, three times total, unless it times out.
    """

    # has sent an Accept...
    _cmds_sent: int = 1  # already sent one

    def received_accept(self, from_self: bool) -> None:  # TODO: warn out of order
        if not from_self:
            super().received_accept(from_self)  # TODO: log & ignore?
        _LOGGER.warning(f"{self.context}: Accept received before sent")

    def sent_accept(self) -> None:
        self._cmds_sent += 1
        if self._cmds_sent > RETRY_LIMIT:
            self._retries_execeeded()

    # waiting for a Confirm...
    _has_expiry_timer: bool = True

    def received_confirm(self, from_self: bool) -> None:
        if from_self:  # Respondents (listeners) shouldn't send Confirms
            super().received_confirm(from_self)  # TODO: log & ignore?
        self._timer_handle.cancel()
        self._set_context_state(BoundAccepted)


class Confirming(State):
    """Supplicant has received an Accept, and can send a Confirm cmd.

    It will continue to send Confirms until it gets any pkt, or times out.
    """

    # no longer waiting for an Accept (handle retransmits from Respondent)...
    def received_accept(self, from_self: bool) -> None:  # handle retransmits
        if from_self:  # Supplicants shouldn't send Accepts
            super().received_accept(from_self)  # TODO: log & ignore?

    # can send a Confirm anytime now...
    def sent_confirm(self) -> None:
        self._set_context_state(Confirmed)


class Confirmed(Confirming):
    """Supplicant has sent a Confirm pkt.

    It will continue to send Confirms 3x.
    """

    _has_expiry_timer: bool = True

    # sending Confirms (until timeout expires)...
    def _wait_timer_expired(self) -> None:
        self._set_context_state(Bound)

    # has sent a Confirm...
    _cmds_sent: int = 1  # already sent one
    _warning_sent: bool = False

    def received_confirm(self, from_self: bool) -> None:  # TODO: warn out of order
        if not from_self:
            super().received_confirm(from_self)  # TODO: log & ignore?
        self._pkts_rcvd += 1
        if self._pkts_rcvd > self._cmds_sent and not self._warning_sent:
            _LOGGER.warning(f"{self.context}: Confirmed received before sent")
            self._warning_sent = True

    def sent_confirm(self) -> None:
        self._cmds_sent += 1
        if self._cmds_sent == RETRY_LIMIT:
            self._set_context_state(Bound)


class Bound(State):
    """Context is Bound."""

    def received_confirm(self, from_self: bool) -> None:  # TODO: warn out of order
        self._pkts_rcvd += 1
        if not from_self:
            pass


class BoundAccepted(Accepting, Bound):
    """Respondent is Bound, but should handle retransmits from the supplicant."""

    _has_expiry_timer: bool = True

    # waiting for a Confirm (until timeout expires)...  # TODO: should be error if no confirm
    def _wait_timer_expired(self) -> None:
        self._set_context_state(Bound)

    # no longer waiting for a Confirm (handle retransmits from Supplicant)...
    _pkts_rcvd: int = 1  # already rcvd one

    def received_confirm(self, from_self: bool) -> None:
        if from_self:  # Respondents (listeners) shouldn't send Confirms
            super().received_confirm(from_self)  # TODO: log & ignore?
        self._pkts_rcvd += 1


if TYPE_CHECKING:
    _Device = TypeVar("_Device", bound=Fakeable)
    _State = State  # TypeVar("_State", bound=State)  # FIXME: mypy says is unbound!!


# Invalid states from which to move to a new an initial state (Listening, Offering)
_BAD_PREV_STATES = (Listening, Offering, Offered, Accepting, Accepted, Confirming)


class BindState:
    UNKNOWN = Unknown
    LISTENING = Listening  # #                              waiting for offers
    OFFERING = Offering  # #   sent offer,                  waiting for echo
    OFFERED = Offered  # #     sent offer (seen echo?),     waiting for accept
    ACCEPTING = Accepting  # # rcvd offer  -> sent accept,  waiting for confirm
    ACCEPTED = Accepted  # #   rcvd offer  -> sent accept,  waiting for confirm
    CONFIRMING = Confirming  # rcvd accept -> sent confirm, bound
    CONFIRMED = Confirmed  # #
    BOUND = Bound  # #         rcvd confirm,                bound
    BOUND_ACCEPTED = BoundAccepted

    # SUPPLICANT/REQUEST -> RESPONDENT/WAITING
    #       DHW/THM, TRV -> CTL     (temp, valve_position), or:
    #                CTL -> BDR/OTB (heat_demand)
    #
    #            unbound -- idle/unbound
    #            unbound -- listening
    #   offering/offered -> listening               #  offered when sees own offer pkt
    #           offering <- accepting/accepted      # accepted when sees own accept pkt
    #   confirming/bound -> accepted (optional?)    #    bound when sees own confirm pkt
    #              bound -- bound_accepted
    #
