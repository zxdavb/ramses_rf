#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF - **using binding FSM**.

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
from inspect import isclass
from unittest.mock import patch

import pytest

from ramses_rf.bind_state import BindState, Context, Exceptions
from tests_rf.helpers import _binding_test_wrapper, _Device

ASSERT_CYCLE_TIME = 0.001  # to be 1/10th of protocols min, 0.001?
MAX_SLEEP = 1  # max_cycles_per_assert = MAX_SLEEP / ASSERT_CYCLE_TIME

XXXX_TIMEOUT_SECS = 0.001  # to patch ramses_rf.bind_state

TEST_DATA: tuple[dict[str, str], dict[str, str], tuple[str]] = (
    (("40:111111", "CO2"), ("41:888888", "FAN"), ("1298",)),
)  # supplicant, respondent, codes


async def assert_context_state(  # NOTE: not a duplicate function (cf: max_sleep)
    ctx: Context, expected_state: BindState, max_sleep: int = 0
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if ctx._state.__class__ is expected_state:
            break
    assert ctx._state.__class__ is expected_state


def binding_test_decorator(fnc):
    async def test_binding_wrapper(test_data=TEST_DATA[0]):
        supp, resp, codes = test_data

        await _binding_test_wrapper(
            fnc,
            {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
            {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
            codes,
        )

    return test_binding_wrapper


async def _phase_0(supplicant: _Device, respondent: _Device) -> None:
    """Create the Context for each Device, initialised their initial State."""

    respondent._context = Context.respondent(respondent)
    supplicant._context = Context.supplicant(supplicant)

    await assert_context_state(supplicant._context, BindState.OFFERING)
    await assert_context_state(respondent._context, BindState.LISTENING)


async def _phase_1(supplicant: _Device, respondent: _Device) -> None:
    """The supplicant sends an Offer, which is received by both."""

    supplicant._context._sent_offer()
    await assert_context_state(supplicant._context, BindState.OFFERED)

    supplicant._context._rcvd_offer(src=supplicant)
    await assert_context_state(supplicant._context, BindState.OFFERED)

    respondent._context._rcvd_offer(src=supplicant)
    await assert_context_state(respondent._context, BindState.ACCEPTING)


async def _phase_2(supplicant: _Device, respondent: _Device) -> None:
    """The respondent sends an Accept, which is received by both."""

    respondent._context._sent_accept()
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    respondent._context._rcvd_accept(src=respondent)
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    supplicant._context._rcvd_accept(src=respondent)
    await assert_context_state(supplicant._context, BindState.CONFIRMING)


async def _phase_3(supplicant: _Device, respondent: _Device) -> None:
    """The supplicant sends a Confirm, which is received by both."""

    supplicant._context._sent_confirm()
    await assert_context_state(supplicant._context, BindState.CONFIRMED)

    supplicant._context._rcvd_confirm(src=supplicant)
    await assert_context_state(supplicant._context, BindState.CONFIRMED)

    respondent._context._rcvd_confirm(src=supplicant)
    await assert_context_state(respondent._context, BindState.BOUND_ACCEPTED)


@pytest.mark.xdist_group(name="serial")
@patch("ramses_rf.bind_state.XXXX_TIMEOUT_SECS", XXXX_TIMEOUT_SECS)
@binding_test_decorator
async def test_binding_flow_1(supplicant: _Device, respondent: _Device, _):
    """Check the change of state during a faultless binding."""

    await _phase_0(supplicant, respondent)  # For each Device, create a Context
    await _phase_1(supplicant, respondent)  # The supplicant Offers, both receive it
    await _phase_2(supplicant, respondent)  # The respondent Accepts, both receive it
    await _phase_3(supplicant, respondent)  # The supplicant Confirms, both receive it


@pytest.mark.xdist_group(name="serial")
@patch("ramses_rf.bind_state.XXXX_TIMEOUT_SECS", XXXX_TIMEOUT_SECS)
@binding_test_decorator
async def test_binding_flow_2(supplicant: _Device, respondent: _Device, _):
    """Check for inappropriate change of state (BindFlowError)."""

    await _phase_0(supplicant, respondent)  # For each Device, create a Context

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


@pytest.mark.xdist_group(name="serial")
@patch("ramses_rf.bind_state.XXXX_TIMEOUT_SECS", XXXX_TIMEOUT_SECS)
@binding_test_decorator
async def test_binding_init_1(supplicant: _Device, respondent: _Device, _):
    """Check the Context init of the respondent & supplicant (BindStateError)."""

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


@pytest.mark.xdist_group(name="serial")
@patch("ramses_rf.bind_state.XXXX_TIMEOUT_SECS", XXXX_TIMEOUT_SECS)
@binding_test_decorator
async def test_binding_init_2(supplicant: _Device, respondent: _Device, _):
    """Check the Context init of the respondent & supplicant (BindStateError)."""

    # Create the respondent, supplicant Contexts using the constructor
    respondent._context = Context.respondent(respondent)
    supplicant._context = Context.supplicant(supplicant)

    await assert_context_state(respondent._context, BindState.LISTENING)
    await assert_context_state(supplicant._context, BindState.OFFERING)

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
