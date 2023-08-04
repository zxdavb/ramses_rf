#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF - **using binding FSM**.

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
import functools
from inspect import isclass
from typing import TypeVar
from unittest.mock import patch

import pytest

from ramses_rf.bind_state import BindState, BindStateBase, Context, Exceptions
from ramses_rf.device.base import Fakeable
from tests_rf.virtual_rf import _rf_net_cleanup, _rf_net_create, ensure_fakeable

_DeviceStateT = TypeVar("_DeviceStateT", bound=BindStateBase)
_FakedDeviceT = TypeVar("_FakedDeviceT", bound=Fakeable)


CONFIRM_TIMEOUT_SECS = 0.001  # # patch ramses_rf.bind_state
MAINTAIN_STATE_CHAIN = True  # #  patch ramses_rf.bind_state (was False)
WAITING_TIMEOUT_SECS = 0  # #     patch ramses_rf.bind_state

ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 1


TEST_DATA = (
    (("40:111111", "CO2"), ("41:888888", "FAN"), ("1298",)),
)  # supplicant, respondent, codes


async def assert_context_state(
    ctx: Context, expected_state: type[_DeviceStateT], max_sleep: int = 0
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if ctx.state.__class__ is expected_state:
            break
    assert ctx.state.__class__ is expected_state


def binding_test_decorator(fnc):
    supp, resp, codes = TEST_DATA[0]  # tuple, tuple, tuple

    @functools.wraps(fnc)
    async def binding_test_wrapper():
        rf, gwy_0, gwy_1 = _rf_net_create(
            {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
            {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        )

        await gwy_0.start()
        await gwy_1.start()

        supplicant = gwy_0.device_by_id[supp[0]]
        respondent = gwy_1.device_by_id[resp[0]]

        ensure_fakeable(respondent)

        await fnc(supplicant, respondent, codes)

        await _rf_net_cleanup(rf, gwy_0, gwy_1)

    return binding_test_wrapper


async def _phase_0(supplicant: _FakedDeviceT, respondent: _FakedDeviceT) -> None:
    """Set the initial Context for each Device.

    Asserts the initial state and the result.
    """

    assert respondent._context is None  # TODO
    assert supplicant._context is None

    respondent._context = Context.respondent(respondent)
    supplicant._context = Context.supplicant(supplicant)

    assert respondent._context is not None
    assert supplicant._context is not None

    await assert_context_state(supplicant._context, BindState.OFFERING)
    await assert_context_state(respondent._context, BindState.LISTENING)


async def _phase_1(supplicant: _FakedDeviceT, respondent: _FakedDeviceT) -> None:
    """The supplicant sends an Offer, which is received by both.

    Asserts the initial state and the result.
    """

    assert isinstance(respondent._context, Context)  # also needed for mypy
    assert isinstance(supplicant._context, Context)  # also needed for mypy

    supplicant._context._sent_offer()
    await assert_context_state(supplicant._context, BindState.OFFERED)

    supplicant._context._rcvd_offer(src=supplicant)
    await assert_context_state(supplicant._context, BindState.OFFERED)

    respondent._context._rcvd_offer(src=supplicant)
    await assert_context_state(respondent._context, BindState.ACCEPTING)


async def _phase_2(supplicant: _FakedDeviceT, respondent: _FakedDeviceT) -> None:
    """The respondent sends an Accept, which is received by both.

    Asserts the initial state and the result.
    """

    assert isinstance(respondent._context, Context)  # also needed for mypy
    assert isinstance(supplicant._context, Context)  # also needed for mypy

    respondent._context._sent_accept()
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    respondent._context._rcvd_accept(src=respondent)
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    supplicant._context._rcvd_accept(src=respondent)
    await assert_context_state(supplicant._context, BindState.CONFIRMING)


async def _phase_3(supplicant: _FakedDeviceT, respondent: _FakedDeviceT) -> None:
    """The supplicant sends a Confirm, which is received by both.

    Asserts the initial state and the result.
    """

    assert isinstance(respondent._context, Context)  # also needed for mypy
    assert isinstance(supplicant._context, Context)  # also needed for mypy

    supplicant._context._sent_confirm()
    await assert_context_state(supplicant._context, BindState.CONFIRMED)

    supplicant._context._rcvd_confirm(src=supplicant)
    await assert_context_state(supplicant._context, BindState.CONFIRMED)

    respondent._context._rcvd_confirm(src=supplicant)
    await assert_context_state(respondent._context, BindState.BOUND_ACCEPTED)

    await assert_context_state(respondent._context, BindState.BOUND, max_sleep=1)


async def _phase_4(supplicant: _FakedDeviceT, respondent: _FakedDeviceT) -> None:
    """The supplicant sends remaining Confirms, and transitions to Bound.

    Asserts the initial state and the result.
    """

    assert isinstance(respondent._context, Context)  # also needed for mypy
    assert isinstance(supplicant._context, Context)  # also needed for mypy

    await assert_context_state(respondent._context, BindState.BOUND)
    await assert_context_state(supplicant._context, BindState.CONFIRMED)

    supplicant._context._sent_confirm()
    supplicant._context._rcvd_confirm(src=supplicant)
    respondent._context._rcvd_confirm(src=supplicant)

    supplicant._context._sent_confirm()
    supplicant._context._rcvd_confirm(src=supplicant)
    respondent._context._rcvd_confirm(src=supplicant)

    await assert_context_state(respondent._context, BindState.BOUND)
    await assert_context_state(supplicant._context, BindState.BOUND)  # after tx x3


@patch("ramses_rf.bind_state._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN)
@patch("ramses_rf.bind_state.CONFIRM_TIMEOUT_SECS", CONFIRM_TIMEOUT_SECS)
@binding_test_decorator
async def _test_binding_flow_0(supplicant: _FakedDeviceT, respondent: _FakedDeviceT, _):
    """Check the change of state during a faultless binding."""

    await _phase_0(supplicant, respondent)  # For each Device, create a Context
    await _phase_1(supplicant, respondent)  # The supplicant Offers x1, both receive
    await _phase_2(supplicant, respondent)  # The respondent Accepts x1, both receive
    await _phase_3(supplicant, respondent)  # The supplicant Confirms x1, both receive
    await _phase_4(supplicant, respondent)  # The supplicant Confirms x2, both receive

    assert isinstance(respondent._context, Context)  # also needed for mypy
    assert isinstance(supplicant._context, Context)  # also needed for mypy

    await assert_context_state(supplicant._context, BindState.BOUND)  # after tx x3
    await assert_context_state(respondent._context, BindState.BOUND)  # after rx x1


@patch("ramses_rf.bind_state._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN)
@binding_test_decorator
async def _test_binding_flow_1(supplicant: _FakedDeviceT, respondent: _FakedDeviceT, _):
    """Check for inappropriate change of state (BindFlowError)."""

    await _phase_0(supplicant, respondent)  # For each Device, create a Context

    assert isinstance(respondent._context, Context)  # needed for mypy
    assert isinstance(supplicant._context, Context)  # needed for mypy

    for sent_cmd in (  # BAD: The supplicant (Offering) doesn't send an Offer
        supplicant._context._sent_accept,
        supplicant._context._sent_confirm,
    ):
        try:
            sent_cmd()
        except Exceptions.BindFlowError:
            continue
        else:
            assert False

    for sent_cmd in (  # BAD: The respondent (Listening) sends before receiving anything
        respondent._context._sent_offer,
        respondent._context._sent_accept,
        respondent._context._sent_confirm,
    ):
        try:
            sent_cmd()
        except Exceptions.BindFlowError:
            continue
        else:
            assert False

    await _phase_1(supplicant, respondent)  # The supplicant Offers, both receive it


@patch("ramses_rf.bind_state._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN)
@patch("ramses_rf.bind_state.WAITING_TIMEOUT_SECS", WAITING_TIMEOUT_SECS)
@binding_test_decorator
async def _test_binding_flow_2(supplicant: _FakedDeviceT, respondent: _FakedDeviceT, _):
    """Check for inappropriate change of state (BindFlowError)."""

    await _phase_0(supplicant, respondent)  # For each Device, create a Context

    assert isinstance(respondent._context, Context)  # needed for mypy
    assert isinstance(supplicant._context, Context)  # needed for mypy

    supplicant._context._sent_offer()
    supplicant._context._sent_offer()
    supplicant._context._sent_offer()

    try:  # BAD: The supplicant (Offering) sends a 4th Offer
        supplicant._context._sent_offer()
    except Exceptions.BindFlowError:
        pass

    await assert_context_state(supplicant._context, BindState.UNKNOWN)
    assert supplicant._context.state._prev_state.__class__ is BindState.OFFERED

    try:  # BAD: The supplicant (now Unknown) sends an Offer
        supplicant._context._sent_offer()
    except Exceptions.BindStateError:
        pass

    await assert_context_state(supplicant._context, BindState.UNKNOWN)
    assert supplicant._context.state._prev_state.__class__ is BindState.OFFERED

    # BAD: The respondant never got the Offer
    await assert_context_state(respondent._context, BindState.UNKNOWN, max_sleep=1)
    assert respondent._context.state._prev_state.__class__ is BindState.LISTENING


@patch("ramses_rf.bind_state._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN)
@binding_test_decorator
async def _test_binding_init_1(supplicant: _FakedDeviceT, respondent: _FakedDeviceT, _):
    """Create both Contexts via init (first try bad initial States)."""

    assert respondent._context is None
    assert supplicant._context is None

    # BAD: Create a Context with an initial State other than Listening, Offering
    for state in [s for s in BindState.__dict__.values() if isclass(s)]:
        if state in (BindState.LISTENING, BindState.OFFERING):
            continue
        try:
            supplicant._context = Context(supplicant, state)
        except Exceptions.BindStateError:
            continue
        else:
            assert False

    respondent._context = Context(respondent, BindState.LISTENING)
    supplicant._context = Context(supplicant, BindState.OFFERING)

    await assert_context_state(respondent._context, BindState.LISTENING)
    await assert_context_state(supplicant._context, BindState.OFFERING)


@patch("ramses_rf.bind_state._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN)
@binding_test_decorator
async def _test_binding_init_2(supplicant: _FakedDeviceT, respondent: _FakedDeviceT, _):
    """Create both Contexts via constructors (then try bad previous States)."""

    assert respondent._context is None
    assert supplicant._context is None

    # Create the respondent, supplicant Contexts using the constructor
    respondent._context = Context.respondent(respondent)
    supplicant._context = Context.supplicant(supplicant)

    # BAD: Create a Context with a unacceptible previous State
    try:
        respondent._context = Context.respondent(respondent)
    except Exceptions.BindStateError:
        pass
    else:
        assert False

    try:
        supplicant._context = Context.supplicant(supplicant)
    except Exceptions.BindStateError:
        pass
    else:
        assert False

    await assert_context_state(respondent._context, BindState.LISTENING)
    await assert_context_state(supplicant._context, BindState.OFFERING)


@pytest.mark.xdist_group(name="serial")
async def test_flow_0():
    await _test_binding_flow_0()


@pytest.mark.xdist_group(name="serial")
async def test_flow_1():
    await _test_binding_flow_1()


@pytest.mark.xdist_group(name="serial")
async def test_flow_2():
    await _test_binding_flow_2()


@pytest.mark.xdist_group(name="serial")
async def test_init_1():
    await _test_binding_init_1()


@pytest.mark.xdist_group(name="serial")
async def test_init_2():
    await _test_binding_init_2()
