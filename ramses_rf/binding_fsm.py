#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Base for all devices.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from .protocol.address import NUL_DEVICE_ID
from .protocol.const import SZ_ACCEPT, SZ_CONFIRM, SZ_OFFER, SZ_PHASE

if TYPE_CHECKING:
    from typing import Callable, Iterable, TypeVar

    from .device import Command, Message
    from .device.base import Fakeable

# skipcq: PY-W2000
from .device import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
    Verb,
)


_LOGGER = logging.getLogger(__name__)

# All debug flags should be False for end-users
_DEBUG_MAINTAIN_STATE_CHAIN = False  # maintain Context._prev_state


SZ_RESPONDENT = "respondent"
SZ_SUPPLICANT = "supplicant"
SZ_IS_DORMANT = "is_dormant"


CONFIRM_RETRY_LIMIT = 3  # automatically Bound, from Confirming > this # of sends
SENDING_RETRY_LIMIT = 3  # fail Offering/Accepting if no reponse > this # of sends

CONFIRM_TIMEOUT_SECS = 3  # automatically Bound, from BoundAccepted > this # of seconds
WAITING_TIMEOUT_SECS = 3  # fail Listen/Offer/Accept if no pkt rcvd > this # of seconds

# raise a BindTimeoutError if expected Pkt is not received before this number of seconds
_TENDER_WAIT_TIME = WAITING_TIMEOUT_SECS  # resp. listening for Offer
_ACCEPT_WAIT_TIME = WAITING_TIMEOUT_SECS  # TODO: supp. sent Offer, expecting Accept
_AFFIRM_WAIT_TIME = CONFIRM_TIMEOUT_SECS  # TODO: resp. sent Accept, expecting Confirm
_RATIFY_WAIT_TIME = CONFIRM_TIMEOUT_SECS  # TODO: resp. rcvd Confirm, expecting 10E0


__all__ = ["Exceptions", "BindContext", "BindState"]


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


class BindContext:
    """The context is the Device class. It should be initiated with a default state."""

    _is_respondent: bool  # otherwise, must be supplicant
    _state: _StateT = None  # type: ignore[assignment]

    def __init__(
        self, dev: _FakedT, initial_state: None | type[_StateT] = None
    ) -> None:
        self._dev = dev
        self._loop = asyncio.get_running_loop()
        self._fut: None | asyncio.Future = None

        if initial_state not in (None, Listening, Offering):
            raise BindStateError(f"{self}: Incompatible inital state: {initial_state}")

        self._set_state(initial_state or IsIdle)

    def __repr__(self) -> str:
        return f"{self._dev}: {self.role}: {self.state!r}"

    def __str__(self) -> str:
        return f"{self._dev.id}: {self.state}"

    def _set_state(self, state: type[_StateT]) -> None:
        """Change the State of the Context (used only by the Context)."""

        if _DEBUG_MAINTAIN_STATE_CHAIN:  # HACK for debugging
            prev_state = self._state

        self._state = state(self)

        # self._is_respondent is used in role property
        if state == BindState.LISTENING:
            self._is_respondent = True
        elif state == BindState.OFFERING:
            self._is_respondent = False
        elif state not in _IS_BINDING_STATES:
            self._is_respondent = None

        if _DEBUG_MAINTAIN_STATE_CHAIN:  # HACK for debugging
            setattr(self._state, "_prev_state", prev_state)

    @property
    def state(self) -> _StateT:
        return self._state

    @property
    def role(self) -> str:
        if self._is_respondent is True:
            return SZ_RESPONDENT
        if self._is_respondent is False:
            return SZ_SUPPLICANT
        return SZ_IS_DORMANT

    @property
    def is_binding(self) -> bool:
        """Return True if is currently participating in a binding process."""
        return isinstance(self._state, _IS_BINDING_STATES)

    def rcvd_msg(self, msg: Message) -> None:
        """Process any relevant Message that was received."""

        # TODO: need to handle 10E0, and any others
        if msg.code == Code._10E0:
            return
        if msg.code != Code._1FC9:
            return

        if msg.payload.get(SZ_PHASE) == SZ_OFFER:
            if msg.src is self._dev:
                self._state.received_offer(msg)  # Supplicant(Offered)
            else:
                self._state.received_offer(msg)  # Respondent(Listening), or other
        elif msg.payload.get(SZ_PHASE) == SZ_ACCEPT:
            if msg.src is self._dev:
                self._state.received_accept(msg)
            elif msg.dst is self._dev:
                self._state.received_accept(msg)
            else:
                self._state.received_accept(msg)
        elif msg.payload.get(SZ_PHASE) == SZ_CONFIRM:
            if msg.src is self._dev:
                self._state.received_confirm(msg)
            elif msg.dst is self._dev:
                self._state.received_confirm(msg)
            else:
                self._state.received_confirm(msg)

    def sent_cmd(self, cmd: Command) -> None:
        """Process any relevant Command that was sent."""

        # TODO: need to handle 10E0, and any others
        if cmd.code == Code._10E0:
            return
        if cmd.code != Code._1FC9:
            return

        # these sends raise BindRetryError if RETRY_LIMIT exceeded
        if cmd.verb == I_ and cmd.dst.id in (cmd.src.id, NUL_DEVICE_ID):
            self._state.sent_offer(cmd)  # Supplicant(Offering)
        elif cmd.verb == W_:  # and cmd.src is self:
            self._state.sent_accept(cmd)  # Respondent(Accepting)
        elif cmd.verb == I_:  # and cmd.src is self:
            self._state.sent_confirm(cmd)  # Supplicant(Confirming)

    async def wait_for_binding_request(
        self,
        codes: Iterable[Code],
        idx: str = "00",
    ) -> Message:
        """Listen for a binding and return the Supplicant's Offer."""

        if self.is_binding:
            raise BindStateError(f"{self._dev}: bad start State for a bind: {self}")
        self._set_state(BindState.LISTENING)

        assert self._fut is None or self._fut.done()
        self._fut = self._loop.create_future()

        timeout = _TENDER_WAIT_TIME
        try:
            await asyncio.wait_for(self._fut, timeout)
        except asyncio.TimeoutError:
            _LOGGER.warning("!!! wait_for_binding_request() has asyncio.TimeoutError")
            self._fut.set_exception(
                BindTimeoutError(f"WaitforOffer timer expired ({timeout}s)")
            )

        return self._fut.result()  # may raise BindTimeoutError

    async def initiate_binding_process(
        self,
        codes: Iterable[Code],
        oem_code: None | str = None,
    ) -> Message:
        """Start a binding (cast an Offer) and return the Respondent's Accept."""

        if self.is_binding:
            raise BindStateError(f"{self._dev}: bad start State for a bind: {self}")
        self._set_state(BindState.OFFERING)  # TODO: pre-offering


_ContextT = BindContext  # TypeVar("_ContextT", bound=Context)


class BindStateBase:
    """The common state interface for all the states."""

    _cmds_sent: int = 0  # num of bind cmds sent
    _pkts_rcvd: int = 0  # num of bind pkts rcvd (icl. any echos of sender's own cmd)

    _has_wait_timer: bool = False
    _retry_limit: int = SENDING_RETRY_LIMIT
    _timer_handle: asyncio.TimerHandle

    def __init__(self, context: BindContext) -> None:
        self._context = context
        self._loop = context._loop
        self._set_context_state: Callable = context._set_state

        _LOGGER.debug(f"{self}: Changing state from: {self._context.state} to: {self}")

        if self._has_wait_timer:
            self._timer_handle = self._loop.call_later(
                WAITING_TIMEOUT_SECS, self._wait_timer_expired
            )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} (rx={self._pkts_rcvd}, tx={self._cmds_sent})"

    def __str__(self) -> str:
        return self.__class__.__name__

    @property
    def context(self) -> BindContext:
        return self._context

    def received_offer(self, msg: Message) -> None:  # treat as unexpected
        """Treat an Offer as unexpected (by default) and raise a BindFlowError."""
        hint = "itself" if msg.src is self.context._dev else str(msg.src)
        raise BindFlowError(f"{self.context}: unexpected Offer from {hint}")

    def received_accept(self, msg: Message) -> None:  # treat as unexpected
        """Treat an Accept as unexpected (by default) and raise a BindFlowError."""
        hint = "itself" if msg.src is self.context._dev else str(msg.src)
        raise BindFlowError(f"{self.context}: unexpected Accept from {hint}")

    def received_confirm(self, msg: Message) -> None:  # treat as unexpected
        """Treat a Confirm as unexpected (by default) and raise a BindFlowError."""
        hint = "itself" if msg.src is self.context._dev else str(msg.src)
        raise BindFlowError(f"{self.context}: unexpected Confirm from {hint}")

    def sent_offer(self, cmd: Command) -> None:  # treat as unexpected
        """Raise BindRetryError if the RETRY_LIMIT is exceeded."""
        raise BindFlowError(f"{self.context}: not expected to send an Offer")

    def sent_accept(self, cmd: Command) -> None:  # treat as unexpected
        """Raise BindRetryError if the RETRY_LIMIT is exceeded."""
        raise BindFlowError(f"{self.context}: not expected to send an Accept")

    def sent_confirm(self, cmd: Command) -> None:  # treat as unexpected
        """Raise BindRetryError if the RETRY_LIMIT is exceeded."""
        raise BindFlowError(f"{self.context}: not expected to send a Confirm")

    def _retries_exceeded(self) -> None:
        """Process an overrun of the RETRY_LIMIT when sending a Command."""

        self._set_context_state(Unknown)
        _LOGGER.warning(
            f"{self._context}: {self._retry_limit} commands sent, but packet not received"
            ""
        )  # was: BindRetryError

    def _wait_timer_expired(self) -> None:
        """Process an overrun of the wait timer when waiting for a Packet."""
        self._set_context_state(Unknown)
        _LOGGER.warning(
            f"{self._context}: {WAITING_TIMEOUT_SECS} secs passed, but packet not received"
        )  # was: BindTimeoutError


class IsIdle(BindStateBase):
    pass


class Unknown(BindStateBase):
    """Failed binding, see previous State for more info."""

    _warning_sent: bool = False

    def _send_warning_if_not_already_sent(self) -> None:
        if self._warning_sent:
            return

        self._warning_sent = True
        raise BindStateError(f"{self}: Current state is Unknown")

    def received_offer(self, msg: Message) -> None:
        self._send_warning_if_not_already_sent()

    def received_accept(self, msg: Message) -> None:
        self._send_warning_if_not_already_sent()

    def received_confirm(self, msg: Message) -> None:
        self._send_warning_if_not_already_sent()

    def sent_offer(self, cmd: Command) -> None:
        self._send_warning_if_not_already_sent()

    def sent_accept(self, cmd: Command) -> None:
        self._send_warning_if_not_already_sent()

    def sent_confirm(self, cmd: Command) -> None:
        self._send_warning_if_not_already_sent()


class Listening(BindStateBase):
    """Respondent has started listening, and is waiting for an Offer.

    It will continue to wait for an Offer, unless it times out.
    """

    _has_wait_timer: bool = True

    # waiting for an Offer until timer expires...
    def received_offer(self, msg: Message) -> None:
        if msg.src is self.context._dev:  # Listeners shouldn't send Offers
            super().received_offer(msg)  # TODO: log & ignore?

        if not self.context._fut.done():
            self.context._fut.set_result(msg)

        self._timer_handle.cancel()
        self._set_context_state(Accepting)


class Offering(BindStateBase):
    """Supplicant can send a Offer cmd."""

    # def received_offer(self, msg: Message) -> None:  # OK if is echo from itself
    #     """Ignore any Offer echo'd to a Device from itself."""
    #     if msg.src is not self._context._dev:
    #         super().received_offer(msg)

    # can send an Offer anytime now...
    def sent_offer(self, cmd: Command) -> None:
        if self._context.role != SZ_SUPPLICANT:
            super().sent_offer(cmd)
        self._set_context_state(Offered)


class Offered(Offering):
    """Supplicant has sent an Offer, and is waiting for an Accept.

    It will continue to send Offers until it gets an Accept, or times out.
    """

    _cmds_sent: int = 1  # already sent one

    _has_wait_timer: bool = True

    # has sent one Offer so far...
    def received_offer(self, msg: Message) -> None:
        if msg.src is not self.context._dev:  # TODO: check me
            super().received_offer(msg)

    def sent_offer(self, cmd: Command) -> None:
        self._cmds_sent += 1
        if self._retry_limit and self._cmds_sent > self._retry_limit:
            self._retries_exceeded()

    # waiting for an Accept until timer expires...
    def received_accept(self, msg: Message) -> None:
        if msg.src is self.context._dev:  # Supplicants shouldn't send Accepts
            super().received_accept(msg)  # TODO: log & ignore?

        self._timer_handle.cancel()
        self._set_context_state(Confirming)


class Accepting(BindStateBase):  # aka Listened
    """Respondent has received an Offer, and can send an Accept cmd."""

    # no longer waiting for an Offer...
    def received_offer(self, msg: Message) -> None:  # handle retransmits
        if msg.src is self.context._dev:  # Respondents shouldn't send Offers
            super().received_offer(msg)  # TODO: log & ignore?

    def received_accept(self, msg: Message) -> None:  # OK if is echo from itself
        """Ignore any Accept echo'd to a Device from itself."""
        if msg.src is not self._context._dev:
            super().received_accept(msg)

    # can send an Accept anytime now...
    def sent_accept(self, cmd: Command) -> None:
        self._set_context_state(Accepted)


class Accepted(Accepting):
    """Respondent has sent an Accept, and is waiting for a Confirm.

    It will continue to send Accepts, three times total, unless it times out.
    """

    _cmds_sent: int = 1  # already sent one

    _has_wait_timer: bool = True

    # has sent one Accept so far...
    def received_accept(self, msg: Message) -> None:  # TODO: warn out of order
        if msg.src is not self.context._dev:
            super().received_accept(msg)  # TODO: log & ignore?

    def sent_accept(self, cmd: Command) -> None:
        self._cmds_sent += 1
        if self._retry_limit and self._cmds_sent > self._retry_limit:
            self._retries_exceeded()

    # waiting for a Confirm until timer expires...
    def received_confirm(self, msg: Message) -> None:
        if msg.src is self.context._dev:  # Respondents shouldn't send Confirms
            super().received_confirm(msg)  # TODO: log & ignore?

        self._timer_handle.cancel()
        self._set_context_state(BoundAccepted)


class Confirming(BindStateBase):
    """Supplicant has received an Accept, and can send a Confirm cmd.

    It will continue to send Confirms until it gets any pkt, or times out.
    """

    # no longer waiting for an Accept...
    def received_accept(self, msg: Message) -> None:  # handle retransmits
        if msg.src is self.context._dev:  # Supplicants shouldn't send Accepts
            super().received_accept(msg)  # TODO: log & ignore?

    # can send a Confirm anytime now...
    def sent_confirm(self, cmd: Command) -> None:
        self._set_context_state(Confirmed)


class Confirmed(Confirming):
    """Supplicant has sent a Confirm pkt.

    It will continue to send Confirms, total 3x.
    """

    _cmds_sent: int = 1  # already sent one

    _has_wait_timer: bool = True
    _warning_sent: bool = False

    # sending Confirms until timeout expires...
    def _wait_timer_expired(self) -> None:
        self._set_context_state(Bound)

    # has sent one Confirm so far...
    def received_confirm(self, msg: Message) -> None:  # TODO: warn out of order
        if msg.src is not self.context._dev:  # Respondents shouldn't send Confirms
            super().received_confirm(msg)

        self._pkts_rcvd += 1
        if self._pkts_rcvd > self._cmds_sent and not self._warning_sent:
            _LOGGER.warning(f"{self.context}: Confirmed received before sent")
            self._warning_sent = True

    def sent_confirm(self, cmd: Command) -> None:
        self._cmds_sent += 1
        if self._cmds_sent == CONFIRM_RETRY_LIMIT:
            self._set_context_state(Bound)


class Bound(BindStateBase):
    """Context is Bound."""

    _pkts_rcvd: int = 0  # TODO: check these counters

    def received_confirm(self, msg: Message) -> None:  # TODO: warn out of order
        # self._pkts_rcvd += 1
        if msg.src is not self.context._dev:  # TODO: what?
            pass


class BoundAccepted(Accepting, Bound):
    """Respondent is Bound, but should handle retransmits from the supplicant."""

    _pkts_rcvd: int = 1  # already sent 1, TODO: check these counters

    def __init__(self, context: BindContext) -> None:
        super().__init__(context)

        self._timer_handle = self._loop.call_later(
            CONFIRM_TIMEOUT_SECS, self._xxxx_timer_expired
        )

    # automatically transition to a quiesced bound mode after x seconds
    def _xxxx_timer_expired(self) -> None:
        self._set_context_state(Bound)

    # no longer waiting for a Confirm (handle retransmits from Supplicant)...
    def received_confirm(self, msg: Message) -> None:
        if msg.src is self.context._dev:  # Respondents shouldn't send Confirms
            super().received_confirm(msg)  # TODO: log & ignore?

        self._pkts_rcvd += 1
        if self._pkts_rcvd == CONFIRM_RETRY_LIMIT:
            self._timer_handle.cancel()
            self._set_context_state(Bound)


class BoundFinal(Accepting, Bound):
    """Device is fully Bound,no more transmits or receives."""

    pass


if TYPE_CHECKING:
    _FakedT = TypeVar("_FakedT", bound=Fakeable)
    _StateT = BindStateBase


# Invalid states from which to move to a new an initial state (Listening, Offering)
_IS_BINDING_STATES = (Listening, Offering, Offered, Accepting, Accepted, Confirming)


class BindState:
    UNKNOWN = Unknown
    IDLE = IsIdle
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
