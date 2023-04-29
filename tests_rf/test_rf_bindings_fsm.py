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


# NOTE: duplicate function
def pytest_generate_tests(metafunc):
    def id_fnc(param):
        return f"{param[0][1]} to {param[1][1]}"

    metafunc.parametrize("test_data", TEST_DATA, ids=id_fnc)


# NOTE: not exactly a duplicate function (cf: max_sleep)
async def assert_context_state(
    ctx: Context, expected_state: BindState, max_sleep: int = 0
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if ctx._state.__class__ is expected_state:
            break
    assert ctx._state.__class__ is expected_state


async def _test_binding_fsm(supplicant: _Device, respondent: _Device, _):
    """Check the change of state during a binding (BindFlowError)."""

    # PHASE 0: Initialise the respondent, supplicant
    # Initialise the respondent, supplicant
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
    await assert_context_state(supplicant._context, BindState.OFFERED)

    supplicant._context._rcvd_offer(src=supplicant)
    await assert_context_state(supplicant._context, BindState.OFFERED)

    supplicant._context._rcvd_offer(src=supplicant)  # supplicant retransmits
    await assert_context_state(supplicant._context, BindState.OFFERED)

    # BAD: The supplicant receives an Offer, but not from itself
    try:
        supplicant._context._rcvd_offer(src=respondent)  # TODO: use 3rd dev
    except Exceptions.BindFlowError:
        pass
    else:
        assert False

    # PHASE 2: The respondent receives the Offer... and Accepts
    await assert_context_state(respondent._context, BindState.LISTENING)
    respondent._context._rcvd_offer(src=supplicant)
    await assert_context_state(respondent._context, BindState.ACCEPTING)

    respondent._context._rcvd_offer(src=supplicant)  # supplicant retransmits
    await assert_context_state(respondent._context, BindState.ACCEPTING)

    respondent._context._sent_accept()
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    # BAD: The respondent sends a 4th Accept (*after* receiving the Offer it sent)
    respondent._context._sent_accept()
    respondent._context._sent_accept()
    try:
        respondent._context._sent_accept()
    except Exceptions.BindRetryError:
        pass
    else:
        assert False
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    respondent._context._rcvd_accept(src=respondent)
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    # PHASE 3: The supplicant receives the Accept... and Confirms (after 3x is Bound)
    await assert_context_state(supplicant._context, BindState.OFFERED)
    supplicant._context._rcvd_accept(src=respondent)
    await assert_context_state(supplicant._context, BindState.CONFIRMING)

    supplicant._context._sent_confirm()
    await assert_context_state(supplicant._context, BindState.CONFIRMED)

    supplicant._context._rcvd_confirm(src=supplicant)
    await assert_context_state(supplicant._context, BindState.CONFIRMED)

    # BAD: The supplicant sends a 4th Confirm (*after* receiving the Confirm it sent)
    supplicant._context._sent_confirm()
    supplicant._context._sent_confirm()
    await assert_context_state(supplicant._context, BindState.BOUND)

    try:
        supplicant._context._sent_confirm()
    except Exceptions.BindFlowError:  # not: BindRetryError, as Confirming -> Bound
        pass
    else:
        assert False
    await assert_context_state(supplicant._context, BindState.BOUND)

    # PHASE 4: The respondent receives the Confirm
    # BAD: The respondent receives a Confirm, but not from the supplicant
    try:
        respondent._context._rcvd_confirm(src=respondent)  # TODO: use 3rd dev
    except Exceptions.BindFlowError:
        pass
    else:
        assert False

    # The respondent receives the Confirm
    await assert_context_state(respondent._context, BindState.ACCEPTED)
    respondent._context._rcvd_confirm(src=supplicant)
    await assert_context_state(respondent._context, BindState.BOUND_ACCEPTED)

    # TODO: GOOD: The respondent receives a 2nd/3rd Confirm
    respondent._context._rcvd_confirm(src=supplicant)
    respondent._context._rcvd_confirm(src=supplicant)
    await assert_context_state(respondent._context, BindState.BOUND_ACCEPTED)

    # TODO: GOOD: The respondent receives (ignores) a 4th Confirm
    respondent._context._rcvd_confirm(src=supplicant)


async def _test_binding_init_1(supplicant: _Device, respondent: _Device, _):
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

    # BAD: Initialise device that is already binding
    for dev in (respondent, supplicant):
        try:
            dev._context = Context.respondent(dev)
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
            supplicant._context = Context(respondent, state)
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
async def test_binding_state_machine(test_data):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_fsm,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )


@pytest.mark.xdist_group(name="serial")
async def test_binding_state_starts(test_data):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_init_1,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )

    await _test_binding_wrapper(
        _test_binding_init_2,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )
