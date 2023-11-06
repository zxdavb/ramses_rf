#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Base for all devices.
"""
from __future__ import annotations

import asyncio
import logging
from enum import StrEnum
from typing import TYPE_CHECKING

from ramses_tx import NUL_DEV_ADDR, NUL_DEVICE_ID, Command

from .exceptions import BindingError, BindingFlowFailed, BindingFsmError

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
    from collections.abc import Iterable

    from .device import Message
    from .device.base import Fakeable


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
_ACCEPT_WAIT_TIME = WAITING_TIMEOUT_SECS  # supp. sent Offer, expecting Accept
_AFFIRM_WAIT_TIME = CONFIRM_TIMEOUT_SECS  # resp. sent Accept, expecting Confirm
_RATIFY_WAIT_TIME = CONFIRM_TIMEOUT_SECS  # resp. rcvd Confirm, expecting Ratify (10E0)


#


class Vendor(StrEnum):
    ITHO = "itho"
    NUAIRE = "nuaire"
    ORCON = "orcon"
    DEFAULT = "default"


class BindPhase(StrEnum):
    TENDER = "offer"
    ACCEPT = "accept"
    AFFIRM = "confirm"
    RATIFY = "addenda"  # Code._10E0


class BindRole(StrEnum):
    RESPONDENT = "respondent"
    SUPPLICANT = "supplicant"
    IS_DORMANT = "is_dormant"
    IS_UNKNOWN = "is_unknown"


SCHEME_LOOKUP = {
    Vendor.ITHO: {"oem_code": "01"},
    Vendor.NUAIRE: {"oem_code": "6C"},
    Vendor.ORCON: {"oem_code": "67", "offer_to": NUL_DEVICE_ID},
    Vendor.DEFAULT: {"oem_code": None},
}


#


class BindContextBase:
    """The context is the Device class. It should be initiated with a default state."""

    _attr_role = BindRole.IS_UNKNOWN

    _is_respondent: None | bool  # if binding, is either: respondent or supplicant
    _state: BindStateBase = None  # type: ignore[assignment]

    def __init__(self, dev: Fakeable) -> None:
        self._dev = dev
        self._loop = asyncio.get_running_loop()
        self._fut: None | asyncio.Future = None

        self.set_state(DevIsNotBinding)

    def __repr__(self) -> str:
        return f"{self._dev.id} ({self.role}): {self.state!r}"

    def __str__(self) -> str:
        return f"{self._dev.id}: {self.state}"

    def set_state(
        self, state: type[BindStateBase], result: None | asyncio.Future = None
    ) -> None:
        """Transition the State of the Context, and process the result, if any."""

        if False and result:
            try:
                self._fut.set_result(result.result())
            except BindingError as exc:
                self._fut.set_result(exc)

        if _DEBUG_MAINTAIN_STATE_CHAIN:  # HACK for debugging
            # if prev_state in (None, )
            prev_state = self._state

        self._state = state(self)
        if not self.is_binding:
            self._is_respondent = None
        elif state is RespIsWaitingForOffer:
            self._is_respondent = True
        elif state is SuppSendOfferWaitForAccept:
            self._is_respondent = False

        if _DEBUG_MAINTAIN_STATE_CHAIN:  # HACK for debugging
            setattr(self._state, "_prev_state", prev_state)  # noqa: B010

    @property
    def state(self) -> BindStateBase:
        """Return the State (phase) of the Context."""
        return self._state

    @property
    def role(self) -> BindRole:
        if self._is_respondent is True:
            return BindRole.RESPONDENT
        if self._is_respondent is False:
            return BindRole.SUPPLICANT
        return BindRole.IS_DORMANT

    # TODO: Should remain is_binding until after 10E0 rcvd (if one expected)?
    @property
    def is_binding(self) -> bool:
        """Return True if is currently participating in a binding process."""
        return not isinstance(self.state, _IS_NOT_BINDING_STATES)

    def rcvd_msg(self, msg: Message) -> None:
        """Pass relevant Messages through to the state processor."""
        if msg.code in (Code._1FC9, Code._10E0):
            self.state.rcvd_msg(msg)

    def sent_cmd(self, cmd: Command) -> None:
        """Pass relevant Commands through to the state processor."""
        if cmd.code in (Code._1FC9, Code._10E0):
            self.state.send_cmd(cmd)


class BindContextRespondent(BindContextBase):
    """The binding Context for a Respondent."""

    _attr_role = BindRole.RESPONDENT

    async def wait_for_binding_request(
        self,
        codes: Code | list[Code],
        idx: None | Index = None,
    ) -> tuple[Message, Message, Message, Message]:
        """Device starts binding as a Respondent, by listening for an Offer.

        Returns the Supplicant's Offer or raise an exception if the binding is
        unsuccesful (BindError).
        """

        if self.is_binding:
            raise BindingFsmError(f"{self}: bad State for bindings as a Respondent")
        self.set_state(RespIsWaitingForOffer)  # self._is_respondent = True

        # Step R1: Respondent expects an Offer
        tender = await self._wait_for_offer()

        # Step R2: Respondent expects a Confirm after sending an Accept (accepts Offer)
        accept = await self._accept_offer(tender, codes, idx=idx)
        affirm = await self._wait_for_confirm(accept)

        # Step R3: Respondent expects an Addenda (optional)
        try:
            ratify = await self._wait_for_addenda(accept)
        except BindingFlowFailed:
            ratify = None

        # self._set_as_bound(tender, accept, affirm, ratify)
        return tender, accept, affirm, ratify

    async def _wait_for_offer(self, timeout: float = _TENDER_WAIT_TIME) -> Message:
        """Resp waits timeout seconds for an Offer to arrive & returns it."""
        return await self.state.wait_for_offer(timeout)

    async def _accept_offer(
        self, tender: Message, codes: Iterable[Code], idx: Index = "00"
    ) -> Message:
        """Resp sends an Accept on the basis of a rcvd Offer & returns the Confirm."""
        cmd = Command.put_bind(W_, self._dev.id, codes, dst_id=tender.src.id, idx=idx)
        pkt = await self._dev._async_send_cmd(cmd)
        self.state.accept_offer()
        return pkt

    async def _wait_for_confirm(
        self, accept: Message, timeout: float = _AFFIRM_WAIT_TIME
    ) -> Message:
        """Resp waits timeout seconds for a Confirm to arrive & returns it."""
        return await self.state.wait_for_confirm(timeout)

    async def _wait_for_addenda(
        self, accept: Message, timeout: float = _RATIFY_WAIT_TIME
    ) -> Message:
        """Resp waits timeout seconds for an Addenda to arrive & returns it."""
        return await self.state.wait_for_addenda(timeout)


class BindContextSupplicant(BindContextBase):
    """The binding Context for a Supplicant."""

    _attr_role = BindRole.SUPPLICANT

    async def initiate_binding_process(
        self,
        codes: Code | list[Code],
        scheme: None | Vendor = None,
        oem_code: None | str = "FF",
    ) -> tuple[Message, Message, Message, Message]:
        """Device starts binding as a Supplicant, by sending an Offer.

        Returns the Respondent's Accept, or raise an exception if the binding is
        unsuccesful (BindError).
        """

        if self.is_binding:
            raise BindingFsmError(f"{self}: bad State for binding as a Supplicant")
        self.set_state(SuppSendOfferWaitForAccept)  # self._is_respondent = False

        # Step S1: Supplicant sends an Offer (makes Offer) and expects an Accept
        tender = await self._make_offer(codes, scheme=scheme, oem_code=oem_code)
        accept = await self._wait_for_accept(tender)

        # Step S2: Supplicant sends a Confirm (confirms Accept)
        affirm = await self._confirm_accept(accept)

        # Step S3: Supplicant sends an Addenda (optional)
        if oem_code:
            ratify = await self._cast_addenda(accept, oem_code=oem_code)
        else:
            ratify = None

        # self._set_as_bound(tender, accept, affirm, ratify)
        return tender, accept, affirm, ratify

    async def _make_offer(
        self,
        codes: Iterable[Code],
        scheme: None | Vendor = None,
        oem_code: None | str = None,
    ) -> Message:
        """Supp sends an Offer & returns the corresponding Packet."""

        scheme = scheme or Vendor.DEFAULT

        oem_code = SCHEME_LOOKUP[scheme].get("oem_code")
        dst_id = SCHEME_LOOKUP[scheme].get("offer_to", self._dev.id)

        # state = self.state
        cmd = Command.put_bind(
            I_, self._dev.id, codes, dst_id=dst_id, oem_code=oem_code
        )
        pkt = await self._dev._async_send_cmd(cmd)  # , timeout=30)

        # await state._fut
        self.state.make_offer()
        return pkt

    async def _wait_for_accept(
        self, tender: Message, timeout: float = _ACCEPT_WAIT_TIME
    ) -> Message:
        """Supp waits timeout seconds for an Accept to arrive & returns it."""
        return await self.state.wait_for_accept(timeout)

    async def _confirm_accept(
        self, accept: Message, codes: None | Iterable[Code] = None, idx: Index = "00"
    ) -> Message:
        """Supp casts a Confirm on the basis of a rcvd Accept & returns the Confirm."""
        cmd = Command.put_bind(I_, self._dev.id, codes, dst_id=accept.src.id, idx=idx)
        pkt = await self._dev._async_send_cmd(cmd)
        await self.state.confirm_accept()
        return pkt

    async def _cast_addenda(self, accept: Message, oem_code: None | str) -> Message:
        """Supp casts an Addenda (the final 10E0 command)."""
        msg = self._dev._get_msg_by_hdr(f"{Code._10E0}|{I_}|{self._dev.id}")
        pkt = await self._dev._async_send_cmd(Command(msg._pkt._frame))
        await self.state.cast_addenda()
        return pkt


class BindContext(BindContextRespondent, BindContextSupplicant):
    _attr_role = BindRole.IS_UNKNOWN


#


class BindStateBase:
    _attr_role = BindRole.IS_UNKNOWN

    _cmds_sent: int = 0  # num of bind cmds sent
    _pkts_rcvd: int = 0  # num of bind pkts rcvd (incl. any echos of sender's own cmd)

    _has_wait_timer: bool = False
    _retry_limit: int = SENDING_RETRY_LIMIT
    _timer_handle: asyncio.TimerHandle

    _next_ctx_state: type[BindStateBase]  # next state, if successful transition

    def __init__(self, context: BindContextBase) -> None:
        self._context = context
        self._loop = context._loop

        self._fut = self._loop.create_future()
        _LOGGER.debug(f"{self}: Changing state from: {self._context.state} to: {self}")

        if self._has_wait_timer:
            self._timer_handle = self._loop.call_later(
                WAITING_TIMEOUT_SECS,
                self._handle_wait_timer_expired,
                WAITING_TIMEOUT_SECS,
            )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} (tx={self._cmds_sent})"

    def __str__(self) -> str:
        return self.__class__.__name__

    @property
    def context(self) -> BindContextBase:
        return self._context

    async def _wait_for_fut_result(self, timeout: float) -> Message:
        """Wait timeout seconds for an expected event to occur.

        The expected event is defined by the State's sent_cmd, rcvd_msg methods.
        """
        try:
            await asyncio.wait_for(self._fut, timeout)
        except asyncio.TimeoutError:
            self._handle_wait_timer_expired(timeout)
        else:
            self._set_context_state(self._next_ctx_state)
        return self._fut.result()

    def _handle_wait_timer_expired(self, timeout: float) -> None:
        """Process an overrun of the wait timer when waiting for a Message."""

        msg = (
            f"{self._context}: Failed to transition to {self._next_ctx_state}: "
            f"expected message not received after {timeout} secs"
        )

        _LOGGER.warning(msg)
        self._fut.set_exception(BindingFlowFailed(msg))
        self._set_context_state(DevHasFailedBinding)

    def _set_context_state(self, next_state: type[BindStateBase]) -> None:
        if not self._fut.done():  # if not BindRetryError, BindTimeoutError, msg
            raise BindingFsmError  # or: self._fut.set_exception()
        self._context.set_state(next_state, result=self._fut)

    def send_cmd(self, cmd: Command) -> None:
        raise NotImplementedError

    def rcvd_msg(self, msg: Message) -> None:
        raise NotImplementedError

    @staticmethod
    def is_phase(cmd: Command, phase: BindPhase) -> bool:
        if phase == BindPhase.RATIFY:
            return cmd.verb == I_ and cmd.code == Code._10E0
        if cmd.code != Code._1FC9:
            return False
        if phase == BindPhase.TENDER:
            return cmd.verb == I_ and cmd.dst in (cmd.src, NUL_DEV_ADDR)
        if phase == BindPhase.ACCEPT:
            return cmd.verb == W_ and cmd.dst is not cmd.src
        if phase == BindPhase.AFFIRM:
            return cmd.verb == I_ and cmd.dst not in (cmd.src, NUL_DEV_ADDR)
        return False

    # Respondent State APIs...
    async def wait_for_offer(self, *args, **kwargs) -> Message:
        raise BindingFsmError(
            f"{self._context!r}: shouldn't wait_for_offer() from this State"
        )

    def accept_offer(self, *args, **kwargs) -> Message:
        raise BindingFsmError(
            f"{self._context!r}: shouldn't accept_offer() from this State"
        )

    async def wait_for_confirm(self, *args, **kwargs) -> Message:
        raise BindingFsmError(
            f"{self._context!r}: shouldn't wait_for_confirm() from this State"
        )

    async def wait_for_addenda(self, *args, **kwargs) -> Message:
        raise BindingFsmError(
            f"{self._context!r}: shouldn't wait_for_addenda() from this State"
        )

    # Supplicant State APIs...
    def make_offer(self, *args, **kwargs) -> Message:
        raise BindingFsmError(
            f"{self._context!r}: shouldn't make_offer() from this State"
        )

    async def wait_for_accept(self, *args, **kwargs) -> Message:
        raise BindingFsmError(
            f"{self._context!r}: shouldn't wait_for_accept() from this State"
        )

    async def confirm_accept(self, *args, **kwargs) -> Message:
        raise BindingFsmError(
            f"{self._context!r}: shouldn't confirm_accept() from this State"
        )

    async def cast_addenda(self, *args, **kwargs) -> Message:
        raise BindingFsmError(
            f"{self._context!r}: shouldn't cast_addenda() from this State"
        )


class _DevIsWaitingForMsg(BindStateBase):
    """Device waits until it receives the anticipated Packet (Offer or Addenda).

    Failure occurs when the timer expires (timeout) before receiving the Packet.
    """

    _expected_pkt_phase: BindPhase

    _wait_timer_limit: float = 3.0

    def __init__(self, context: BindContextBase) -> None:
        super().__init__(context)

        self._timer_handle = self._loop.call_later(
            self._wait_timer_limit,
            self._handle_wait_timer_expired,
            self._wait_timer_limit,
        )

    def _set_context_state(self, next_state: type[BindStateBase]) -> None:
        if self._timer_handle:
            self._timer_handle.cancel()
        super()._set_context_state(next_state)

    def rcvd_msg(self, msg: Message) -> None:
        """If the msg is the expected pkt, transition to the next state."""
        if self.is_phase(msg._pkt, self._expected_pkt_phase):
            self._fut.set_result(msg)


class _DevIsReadyToSendCmd(BindStateBase):
    """Device sends a Command (Confirm, Addenda) that wouldn't result in a reply Packet.

    Failure occurs when the retry limit is exceeded before receiving a Command echo.
    """

    _expected_cmd_phase: BindPhase

    _send_retry_limit: int = 0  # retries dont include the first send
    _send_retry_timer: float = 0.8  # retry if no echo received before timeout

    def __init__(self, context: BindContextBase) -> None:
        super().__init__(context)

        self._cmd: None | Command = None
        self._cmds_sent: int = 0

    def _retries_exceeded(self) -> None:
        """Process an overrun of the retry limit when sending a Command."""

        msg = (
            f"{self._context}: Failed to transition to {self._next_ctx_state}: "
            f"{self._expected_cmd_phase} command echo not received after "
            f"{self._retry_limit} retries"
        )

        _LOGGER.warning(msg)
        self._fut.set_exception(BindingFlowFailed(msg))
        self._set_context_state(DevHasFailedBinding)

    def send_cmd(self, cmd: Command) -> None:
        """If sending a cmd, expect the corresponding echo."""

        if not self.is_phase(cmd, self._expected_cmd_phase):
            return

        if self._cmds_sent > self._send_retry_limit:
            self._retries_exceeded()
        self._cmds_sent += 1
        self._cmd = self._cmd or cmd

    def rcvd_msg(self, msg: Message) -> None:
        """If the msg is the expected echo, transition to the next state."""
        if self._cmd and msg._pkt == self._cmd:
            self._fut.set_result(msg)


class _DevSendCmdUntilReply(_DevIsWaitingForMsg, _DevIsReadyToSendCmd):
    """Device sends a Command (Offer, Accept), until it gets the expected reply Packet.

    Failure occurs when the the timer expires (timeout) or the retry limit is exceeded
    before receiving a reply Packet.
    """

    def rcvd_msg(self, msg: Message) -> None:
        """If the msg is the expected reply, transition to the next state."""
        # if self._cmd and msg._pkt == self._cmd:  # the echo
        #     self._set_context_state(self._next_ctx_state)
        if self.is_phase(msg._pkt, self._expected_pkt_phase):
            self._fut.set_result(msg)


class DevHasFailedBinding(BindStateBase):
    """Device has failed binding."""

    _attr_role = BindRole.IS_UNKNOWN


class DevIsNotBinding(BindStateBase):
    """Device is not binding."""

    _attr_role = BindRole.IS_DORMANT


#


class RespHasBoundAsRespondent(BindStateBase):
    """Respondent has received an Offer (+/- an Addenda) & has nothing more to do."""

    _attr_role = BindRole.IS_DORMANT


class RespIsWaitingForAddenda(_DevIsWaitingForMsg, BindStateBase):
    """Respondent has received a Confirm & is waiting for an Addenda."""

    _attr_role = BindRole.RESPONDENT

    _expected_pkt_phase: BindPhase = BindPhase.RATIFY
    _next_ctx_state: type[BindStateBase] = RespHasBoundAsRespondent

    async def wait_for_addenda(self, timeout: None | float = None) -> Message:
        return await self._wait_for_fut_result(timeout or _RATIFY_WAIT_TIME)


class RespSendAcceptWaitForConfirm(_DevSendCmdUntilReply, BindStateBase):
    """Respondent is ready to send an Accept & will expect a Confirm."""

    _attr_role = BindRole.RESPONDENT

    _expected_cmd_phase: BindPhase = BindPhase.ACCEPT
    _expected_pkt_phase: BindPhase = BindPhase.AFFIRM
    _next_ctx_state: type[
        BindStateBase
    ] = RespHasBoundAsRespondent  # or: RespIsWaitingForAddenda

    def accept_offer(self) -> Message:
        pass

    async def wait_for_confirm(self, timeout: None | float = None) -> Message:
        return await self._wait_for_fut_result(timeout or _AFFIRM_WAIT_TIME)


class RespIsWaitingForOffer(_DevIsWaitingForMsg, BindStateBase):
    """Respondent is waiting for an Offer."""

    _attr_role = BindRole.RESPONDENT

    _expected_pkt_phase: BindPhase = BindPhase.TENDER
    _next_ctx_state: type[BindStateBase] = RespSendAcceptWaitForConfirm

    async def wait_for_offer(self, timeout: None | float = None) -> Message:
        return await self._wait_for_fut_result(timeout or _TENDER_WAIT_TIME)


#


class SuppHasBoundAsSupplicant(BindStateBase):
    """Supplicant has sent a Confirm (+/- an Addenda) & has nothing more to do."""

    _attr_role = BindRole.IS_DORMANT


class SuppIsReadyToSendAddenda(
    _DevIsReadyToSendCmd, BindStateBase
):  # send until echo, max_retry=1
    """Supplicant has sent a Confirm & is ready to send an Addenda."""

    _attr_role = BindRole.SUPPLICANT

    _expected_cmd_phase: BindPhase = BindPhase.RATIFY
    _next_ctx_state: type[BindStateBase] = SuppHasBoundAsSupplicant

    async def cast_addenda(self, timeout: None | float = None) -> Message:
        return await self._wait_for_fut_result(timeout or _ACCEPT_WAIT_TIME)


class SuppIsReadyToSendConfirm(
    _DevIsReadyToSendCmd, BindStateBase
):  # send until echo, max_retry=1
    """Supplicant has received an Accept & is ready to send a Confirm."""

    _attr_role = BindRole.SUPPLICANT

    _expected_cmd_phase: BindPhase = BindPhase.AFFIRM
    _next_ctx_state: type[
        BindStateBase
    ] = SuppHasBoundAsSupplicant  # or: SuppIsReadyToSendAddenda

    async def confirm_accept(self, timeout: None | float = None) -> Message:
        return await self._wait_for_fut_result(timeout or _ACCEPT_WAIT_TIME)


class SuppSendOfferWaitForAccept(_DevSendCmdUntilReply, BindStateBase):
    """Supplicant is ready to send an Offer & will expect an Accept."""

    _attr_role = BindRole.SUPPLICANT

    _expected_cmd_phase: BindPhase = BindPhase.TENDER
    _expected_pkt_phase: BindPhase = BindPhase.ACCEPT
    _next_ctx_state: type[BindStateBase] = SuppIsReadyToSendConfirm

    def make_offer(self) -> Message:
        pass

    async def wait_for_accept(self, timeout: None | float = None) -> Message:
        return await self._wait_for_fut_result(timeout or _ACCEPT_WAIT_TIME)


#


class _BindStates:  # used for test suite
    IS_IDLE_DEVICE = DevIsNotBinding  # may send Offer
    NEEDING_TENDER = RespIsWaitingForOffer  # receives Offer, sends Accept
    NEEDING_ACCEPT = SuppSendOfferWaitForAccept  # receives Accept, sends
    NEEDING_AFFIRM = RespSendAcceptWaitForConfirm
    TO_SEND_AFFIRM = SuppIsReadyToSendConfirm
    NEEDING_RATIFY = RespIsWaitingForAddenda  # Optional: has sent Confirm
    TO_SEND_RATIFY = SuppIsReadyToSendAddenda  # Optional
    HAS_BOUND_RESP = RespHasBoundAsRespondent
    HAS_BOUND_SUPP = SuppHasBoundAsSupplicant
    IS_FAILED_RESP = DevHasFailedBinding
    IS_FAILED_SUPP = DevHasFailedBinding


_IS_NOT_BINDING_STATES = (
    DevHasFailedBinding,
    DevIsNotBinding,
    RespHasBoundAsRespondent,
    SuppHasBoundAsSupplicant,
)
