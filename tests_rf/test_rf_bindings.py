#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF.

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
from typing import TypeVar
from unittest.mock import patch

import pytest

from ramses_rf import Gateway, Packet
from ramses_rf.bind_state import BindState, Context, State
from tests_rf.helpers import _binding_test_wrapper, _Faked

_State = TypeVar("_State", bound=State)


CONFIRM_TIMEOUT_SECS = 0.001  # to patch ramses_rf.bind_state

ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 1


TEST_DATA = (
    (("40:111111", "CO2"), ("41:888888", "FAN"), ("1298",)),
    (("07:111111", "DHW"), ("01:888888", "CTL"), ("1260",)),
    (("40:111111", "HUM"), ("41:888888", "FAN"), ("12A0",)),
    (("40:111111", "REM"), ("41:888888", "FAN"), ("22F1",)),
    (("22:111111", "THM"), ("01:888888", "CTL"), ("30C9",)),
    # (("40:111111", "DHW"), ("41:888888", "FAN"), ("30C9",)),  # TODO: should fail!!
    # (("40:111111", "HUM"), ("01:888888", "FAN"), ("30C9",)),  # TODO: should fail!!
)  # supplicant, respondent, codes


def pytest_generate_tests(metafunc):
    def id_fnc(param):
        return f"{param[0][1]} to {param[1][1]}"

    metafunc.parametrize("test_data", TEST_DATA, ids=id_fnc)


async def assert_this_pkt_hdr(
    gwy: Gateway, expected_hdr: str, max_sleep: int = DEFAULT_MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if gwy._this_msg and gwy._this_msg._pkt._hdr == expected_hdr:
            break
    assert gwy._this_msg is not None  # mypy
    assert gwy._this_msg._pkt and gwy._this_msg._pkt._hdr == expected_hdr


async def assert_this_pkt_hdr_wrapper(
    gwy: Gateway, expected_hdr: str, max_sleep: int = DEFAULT_MAX_SLEEP
) -> Packet:
    await assert_this_pkt_hdr(gwy, expected_hdr, max_sleep)

    assert gwy._this_msg is not None  # mypy
    return gwy._this_msg._pkt.dtm, gwy, gwy._this_msg._pkt._hdr


async def assert_context_state(
    ctx: Context | None,
    expected_state: type[_State],
    max_sleep: int = DEFAULT_MAX_SLEEP,
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if ctx and ctx._state.__class__ is expected_state:
            break
    assert ctx is not None  # mypy
    assert ctx._state.__class__ is expected_state


async def _test_binding_flow(supplicant: _Faked, respondent: _Faked, codes):
    """Check the flow of packets during a binding."""

    hdr_flow = [
        "1FC9| I|63:262142",
        f"1FC9| W|{supplicant.id}",
        f"1FC9| I|{respondent.id}",
    ]

    respondent._make_fake()  # TODO: waiting=Code._22F1)
    respondent._bind_waiting(codes)

    assert supplicant._gwy._this_msg is None
    assert respondent._gwy._this_msg is None

    supplicant._make_fake(bind=True)  # rem._bind()

    # using tasks, since a sequence of awaits gives unreliable results
    tasks = [
        asyncio.create_task(assert_this_pkt_hdr_wrapper(role._gwy, hdr))
        for role in (supplicant, respondent)
        for hdr in hdr_flow
    ]

    # TEST 1: that pkts were sent/arrived
    await asyncio.gather(*tasks)

    # TEST 2: that pkts were sent/arrived in the correct order
    results = [(p[1], p[2]) for p in sorted([t.result() for t in tasks])]
    expected = [(x._gwy, h) for h in hdr_flow for x in (supplicant, respondent)]

    assert results == expected


async def _test_binding_state(supplicant: _Faked, respondent: _Faked, codes):
    """Check the change of state during a binding."""

    respondent._make_fake()  # TODO: waiting=Code._22F1)
    assert supplicant._context is None
    assert respondent._context is None

    respondent._bind_waiting(codes)
    # assert supplicant._context is None
    await assert_context_state(respondent._context, BindState.LISTENING, max_sleep=0)

    try:
        supplicant._bind()  # can't bind before make_fake
    except RuntimeError:
        pass
    else:
        assert False
    # assert supplicant._context is None
    await assert_context_state(respondent._context, BindState.LISTENING, max_sleep=0)

    # can (rarely?) get unreliable results for respondent as awaits are asynchronous
    supplicant._make_fake(bind=True)  # rem._bind()
    await assert_context_state(supplicant._context, BindState.OFFERED, max_sleep=0)
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    await assert_context_state(supplicant._context, BindState.CONFIRMED)  # after tx x1
    await assert_context_state(respondent._context, BindState.BOUND_ACCEPTED)
    # ait assert_context_state(respondent._context, BindState.BOUND, max_sleep=1)

    assert supplicant._context is not None
    supplicant._context._sent_confirm()  # HACK: virtually send two more Confirms,
    supplicant._context._sent_confirm()  # so Context can transition to Bound
    await assert_context_state(supplicant._context, BindState.BOUND)  # after tx x3
    await assert_context_state(respondent._context, BindState.BOUND)  # after rx x3


@pytest.mark.xdist_group(name="serial")
async def test_binding_flows(test_data):
    supp, resp, codes = test_data

    await _binding_test_wrapper(
        _test_binding_flow,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )


@pytest.mark.xdist_group(name="serial")
@patch("ramses_rf.bind_state.CONFIRM_TIMEOUT_SECS", CONFIRM_TIMEOUT_SECS)
async def test_binding_state(test_data):
    supp, resp, codes = test_data

    await _binding_test_wrapper(
        _test_binding_state,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )
