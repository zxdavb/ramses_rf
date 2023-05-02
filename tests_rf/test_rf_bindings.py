#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF.

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
from unittest.mock import patch

import pytest

from ramses_rf import Gateway, Packet
from ramses_rf.bind_state import BindState, Context
from tests_rf.helpers import _Device, _test_binding_wrapper

ASSERT_CYCLE_TIME = 0.001  # to be 1/10th of protocols min, 0.001?
MAX_SLEEP = 3  # max_cycles_per_assert = MAX_SLEEP / ASSERT_CYCLE_TIME

XXXX_TIMEOUT_SECS = 0.001  # to patch ramses_rf.bind_state

TEST_DATA: tuple[dict[str, str], dict[str, str], tuple[str]] = (
    (("40:111111", "CO2"), ("41:888888", "FAN"), ("1298",)),
    (("07:111111", "DHW"), ("01:888888", "CTL"), ("1260",)),
    (("40:111111", "HUM"), ("41:888888", "FAN"), ("12A0",)),
    (("40:111111", "REM"), ("41:888888", "FAN"), ("22F1",)),
    (("22:111111", "THM"), ("01:888888", "CTL"), ("30C9",)),
    # (("40:111111", "DHW"), ("41:888888", "FAN"), ("30C9",)),  # TODO: should fail!!
    # (("40:111111", "HUM"), ("01:888888", "FAN"), ("30C9",)),  # TODO: should fail!!
)  # supplicant, respondent, codes


# NOTE: duplicate function
def pytest_generate_tests(metafunc):
    def id_fnc(param):
        return f"{param[0][1]} to {param[1][1]}"

    metafunc.parametrize("test_data", TEST_DATA, ids=id_fnc)


async def assert_this_pkt_hdr(
    gwy: Gateway, expected_hdr: str, max_sleep: int = MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if gwy._this_msg and gwy._this_msg._pkt._hdr == expected_hdr:
            break
    assert gwy._this_msg._pkt and gwy._this_msg._pkt._hdr == expected_hdr


async def assert_this_pkt_hdr_wrapper(
    gwy: Gateway, expected_hdr: str, max_sleep: int = MAX_SLEEP
) -> Packet:
    await assert_this_pkt_hdr(gwy, expected_hdr, max_sleep)

    return gwy._this_msg._pkt


async def _test_binding_flow(supplicant: _Device, respondent: _Device, codes):
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

    # TEST 1: pkts arrived as expected
    await asyncio.gather(*tasks)

    # TEST 2: pkts arrived in the correct order
    pkts = [t.result() for t in tasks]
    pkts.sort(key=lambda x: x.dtm)
    results = [(p._hdr, p._gwy) for p in pkts]

    expected = [(h, x._gwy) for h in hdr_flow for x in (supplicant, respondent)]

    assert results == expected


@pytest.mark.xdist_group(name="serial")
async def test_binding_flows(test_data):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_flow,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )


# NOTE: not exactly a duplicate function (cf: max_sleep)
async def assert_context_state(
    ctx: Context, expected_state: BindState, max_sleep: int = MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if ctx._state.__class__ is expected_state:
            break
    assert ctx._state.__class__ is expected_state


async def _test_binding_state(supplicant: _Device, respondent: _Device, codes):
    """Check the change of state during a binding."""

    respondent._make_fake()  # TODO: waiting=Code._22F1)
    assert supplicant._context is None
    assert respondent._context is None

    respondent._bind_waiting(codes)
    assert supplicant._context is None
    await assert_context_state(respondent._context, BindState.LISTENING, max_sleep=0)

    try:
        supplicant._bind()  # can't bind before make_fake
    except RuntimeError:
        pass
    else:
        assert False
    assert supplicant._context is None
    await assert_context_state(respondent._context, BindState.LISTENING, max_sleep=0)

    # can (rarely?) get unreliable results for respondent as awaits are asynchronous
    supplicant._make_fake(bind=True)  # rem._bind()
    await assert_context_state(supplicant._context, BindState.OFFERED, max_sleep=0)
    await assert_context_state(respondent._context, BindState.ACCEPTED)

    await assert_context_state(supplicant._context, BindState.CONFIRMED)  # after tx x 1
    await assert_context_state(respondent._context, BindState.BOUND_ACCEPTED)

    # TODO:
    # await assert_context_state(supplicant._context, BindState.BOUND)  # after tx x3
    await assert_context_state(respondent._context, BindState.BOUND, max_sleep=1)


@pytest.mark.xdist_group(name="serial")
@patch("ramses_rf.bind_state.XXXX_TIMEOUT_SECS", XXXX_TIMEOUT_SECS)
async def test_binding_state(test_data):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_state,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )
