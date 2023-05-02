#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF - **using binding FSM**.

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
from abc import ABCMeta

import pytest

from ramses_rf.bind_state import BindState, Context, Exceptions
from tests_rf.helpers import _Device, _test_binding_wrapper

# import tracemalloc
# tracemalloc.start()


ASSERT_CYCLE_TIME = 0.001  # to be 1/10th of protocols min, 0.001?
MAX_SLEEP = 1  # max_cycles_per_assert = MAX_SLEEP / ASSERT_CYCLE_TIME


TEST_DATA: tuple[dict[str, str], dict[str, str], tuple[str]] = (
    (("40:111111", "CO2"), ("41:888888", "FAN"), ("1298",)),
)  # supplicant, respondent, codes


# NOTE: not exactly a duplicate function (cf: max_sleep)
async def assert_context_state(
    ctx: Context, expected_state: BindState, max_sleep: int = 0
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if ctx._state.__class__ is expected_state:
            break
    assert ctx._state.__class__ is expected_state


async def _test_binding_fsm_1(supplicant: _Device, respondent: _Device, _):
    """Check currently binding Devices don't get bad initial Context (BindFlowError)."""

    # PHASE 0: Initialise the respondent, supplicant
    respondent._context = Context.respondent(respondent)
    supplicant._context = Context.supplicant(supplicant)

    # BAD: The respondent sends an Offer
    try:
        respondent._context._sent_offer()
    except Exceptions.BindFlowError:
        pass
    else:
        assert False

    # PHASE 1: The supplicant sends an Offer
    await assert_context_state(supplicant._context, BindState.OFFERING)
    supplicant._context._sent_offer()
    await assert_context_state(supplicant._context, BindState.OFFERED)

    # BAD: The supplicant sends a 4th Offer (*before* receving the Offer it sent)
    supplicant._context._sent_offer()
    supplicant._context._sent_offer()
    try:
        supplicant._context._sent_offer()
    except Exceptions.BindRetryError:
        pass
    else:
        assert False
    await assert_context_state(supplicant._context, BindState.UNKNOWN)


async def _test_binding_fsm_2(supplicant: _Device, respondent: _Device, _):
    """Check the change of state during a faultless binding."""

    # PHASE 0: Initialise the respondent, supplicant
    respondent._context = Context.respondent(respondent)
    supplicant._context = Context.supplicant(supplicant)

    # PHASE 1: The supplicant sends an Offer
    await assert_context_state(supplicant._context, BindState.OFFERING)
    supplicant._context._sent_offer()
    await assert_context_state(supplicant._context, BindState.OFFERED)

    supplicant._context._rcvd_offer(src=supplicant)
    await assert_context_state(supplicant._context, BindState.OFFERED)

    supplicant._context._rcvd_offer(src=supplicant)  # supplicant retransmits
    await assert_context_state(supplicant._context, BindState.OFFERED)

    # PHASE 2: The respondent receives the Offer... and Accepts
    await assert_context_state(respondent._context, BindState.LISTENING)
    respondent._context._rcvd_offer(src=supplicant)
    await assert_context_state(respondent._context, BindState.ACCEPTING)

    respondent._context._rcvd_offer(src=supplicant)  # supplicant retransmits
    await assert_context_state(respondent._context, BindState.ACCEPTING)

    respondent._context._sent_accept()
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    # PHASE 3: The supplicant receives the Accept... and Confirms (after 3x is Bound)
    await assert_context_state(supplicant._context, BindState.OFFERED)
    supplicant._context._rcvd_accept(src=respondent)
    await assert_context_state(supplicant._context, BindState.CONFIRMING)

    supplicant._context._sent_confirm()
    await assert_context_state(supplicant._context, BindState.CONFIRMED)

    supplicant._context._rcvd_confirm(src=supplicant)
    await assert_context_state(supplicant._context, BindState.CONFIRMED)

    # PHASE 4: The respondent receives the Confirm
    await assert_context_state(respondent._context, BindState.ACCEPTED)
    respondent._context._rcvd_confirm(src=supplicant)
    await assert_context_state(respondent._context, BindState.BOUND_ACCEPTED)

    # TODO: GOOD: The respondent receives a 2nd/3rd Confirm
    respondent._context._rcvd_confirm(src=supplicant)
    respondent._context._rcvd_confirm(src=supplicant)
    await assert_context_state(respondent._context, BindState.BOUND_ACCEPTED)

    # TODO: GOOD: The respondent receives (ignores) a 4th Confirm
    respondent._context._rcvd_confirm(src=supplicant)


async def _test_binding_fsm_3(supplicant: _Device, respondent: _Device, _):
    """Check for BindRetryError when expected (TBA: BindTimeoutError)."""

    # PHASE 0: Initialise the respondent, supplicant
    respondent._context = Context.respondent(respondent)
    supplicant._context = Context.supplicant(supplicant)

    # BAD: The supplicant sends a 4th Offer (*before* receving the Offer it sent)
    supplicant._context._sent_offer()
    supplicant._context._sent_offer()
    supplicant._context._sent_offer()
    try:
        supplicant._context._sent_offer()
    except Exceptions.BindRetryError:
        pass
    else:
        raise
    await assert_context_state(supplicant._context, BindState.UNKNOWN)


async def _test_binding_init_1(supplicant: _Device, respondent: _Device, _):
    """Check the Context init of the respondent & supplicant (BindStateError)."""

    # PHASE 0: Initialise the respondent, supplicant
    # BAD: Initialise device with a state other than Listening, Offering
    for state in [s for s in BindState.__dict__.values() if type(s) is ABCMeta]:
        if state in (BindState.LISTENING, BindState.OFFERING):
            continue
        try:
            respondent._context = Context(respondent, state)
        except Exceptions.BindStateError:
            continue
        else:
            assert False

    # Initialise the respondent, supplicant using the constructor
    respondent._context = Context.respondent(respondent)
    supplicant._context = Context.supplicant(supplicant)

    await assert_context_state(respondent._context, BindState.LISTENING)
    await assert_context_state(supplicant._context, BindState.OFFERING)

    # Check that State constructors detect contexts that are currently binding
    try:
        # using nt._context = Context(dev, new_state) isn't a useful test
        respondent._context = Context.respondent(respondent)
        respondent._context = Context.respondent(supplicant)
        supplicant._context = Context.supplicant(supplicant)
        supplicant._context = Context.supplicant(respondent)
    except Exceptions.BindStateError:
        pass
    else:
        assert False

    await assert_context_state(respondent._context, BindState.LISTENING)
    await assert_context_state(supplicant._context, BindState.OFFERING)


async def _test_binding_init_2(supplicant: _Device, respondent: _Device, _):
    """Check the Context init of the respondent & supplicant (BindStateError)."""

    # PHASE 0: Initialise the respondent, supplicant
    # BAD: Initialise device with a state other than Listening, Offering
    for state in [s for s in BindState.__dict__.values() if isinstance(s, ABCMeta)]:
        if state in (BindState.LISTENING, BindState.OFFERING):
            continue
        try:
            supplicant._context = Context(supplicant, state)
        except Exceptions.BindStateError:
            continue
        else:
            assert False

    # Initialise the respondent, supplicant (using the constructor)
    respondent._context = Context(respondent, BindState.LISTENING)
    supplicant._context = Context(supplicant, BindState.OFFERING)

    await assert_context_state(respondent._context, BindState.LISTENING)
    await assert_context_state(supplicant._context, BindState.OFFERING)


@pytest.mark.xdist_group(name="serial")
async def test_binding_state_flow_1(test_data=TEST_DATA[0]):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_fsm_1,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )


@pytest.mark.xdist_group(name="serial")
async def test_binding_state_flow_2(test_data=TEST_DATA[0]):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_fsm_2,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )


@pytest.mark.xdist_group(name="serial")
async def test_binding_state_flow_3(test_data=TEST_DATA[0]):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_fsm_3,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )


@pytest.mark.xdist_group(name="serial")
async def test_binding_state_init_1(test_data=TEST_DATA[0]):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_init_1,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )


@pytest.mark.xdist_group(name="serial")
async def test_binding_state_init_2(test_data=TEST_DATA[0]):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_init_2,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )
