#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF - **using binding FSM**.

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
from typing import Callable
from unittest.mock import patch

from ramses_rf import Gateway
from ramses_rf.device.base import BindState, Fakeable
from ramses_rf.protocol.command import Command
from tests_rf.virtual_rf import VirtualRF

# import tracemalloc
# tracemalloc.start()


MAX_SLEEP = 1

ASSERT_CYCLE_TIME = 0.001  # to be 1/10th of protocols min, 0.001?


CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}


TEST_DATA: tuple[dict[str, str], dict[str, str], tuple[str]] = (
    (("40:111111", "CO2"), ("41:888888", "FAN"), ("1298",)),
    # (("07:111111", "DHW"), ("01:888888", "CTL"), ("1260",)),
    # (("40:111111", "HUM"), ("41:888888", "FAN"), ("12A0",)),
    # (("40:111111", "REM"), ("41:888888", "FAN"), ("22F1",)),
    # (("22:111111", "THM"), ("01:888888", "CTL"), ("30C9",)),
    # (("40:111111", "DHW"), ("41:888888", "FAN"), ("30C9",)),  # TODO: should fail!!
    # (("40:111111", "HUM"), ("01:888888", "FAN"), ("30C9",)),  # TODO: should fail!!
)  # supplicant, respondent, codes


def pytest_generate_tests(metafunc):
    def id_fnc(param):
        return f"{param[0][1]} to {param[1][1]}"

    metafunc.parametrize("test_data", TEST_DATA, ids=id_fnc)


async def _stifle_impersonation_alerts(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


async def assert_bind_state(
    dev: Fakeable, expected_state: BindState, max_sleep: int = MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if dev._bind_state._state.__class__ == expected_state:
            break
    assert dev._bind_state._state.__class__ == expected_state


@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    _stifle_impersonation_alerts,
)
async def _test_binding_wrapper(
    fnc: Callable, supp_schema: dict, resp_schema: dict, codes: tuple
):
    rf = VirtualRF(2)
    await rf.start()

    gwy_0 = Gateway(rf.ports[0], **CONFIG, **supp_schema)
    gwy_1 = Gateway(rf.ports[1], **CONFIG, **resp_schema)

    await gwy_0.start()
    await gwy_1.start()

    supplicant = gwy_0.device_by_id[supp_schema["orphans_hvac"][0]]
    respondent = gwy_1.device_by_id[resp_schema["orphans_hvac"][0]]

    # it is likely the respondent is not fakeable...
    if not isinstance(respondent, Fakeable):

        class NowFakeable(respondent.__class__, Fakeable):
            pass

        respondent.__class__ = NowFakeable
        setattr(respondent, "_faked", None)
        setattr(respondent, "_1fc9_state", {"state": BindState.UNKNOWN})

    await fnc(supplicant, respondent, codes)

    await gwy_0.stop()
    await gwy_1.stop()
    await rf.stop()


async def _test_binding_fsm(supplicant: Fakeable, respondent: Fakeable, codes):
    """Check the change of state during a binding."""

    setattr(supplicant, "_bind_state", None)
    setattr(respondent, "_bind_state", None)

    from ramses_rf.bind_state import BindState, Context, Exceptions

    # PHASE 0: Initialise the respondent, supplicant
    # BAD: Initialise device with a state other than Listening, Offering
    try:
        respondent._bind_state = Context(respondent, BindState.CONFIRMED)
    except Exceptions.BindFlowError:
        pass
    else:
        assert False

    # Initialise the respondent, supplicant
    respondent._bind_state = Context(respondent, BindState.LISTENING)
    await assert_bind_state(respondent, BindState.LISTENING, max_sleep=0)

    supplicant._bind_state = Context(supplicant, BindState.OFFERING)
    await assert_bind_state(supplicant, BindState.OFFERING, max_sleep=0)

    # BAD: The respondent sends an Offer
    try:
        respondent._bind_state.sent_offer()
    except Exceptions.BindFlowError:
        pass
    else:
        assert False

    # PHASE 1: The supplicant sends an Offer
    await assert_bind_state(supplicant, BindState.OFFERING, max_sleep=0)
    supplicant._bind_state.sent_offer()
    await assert_bind_state(supplicant, BindState.OFFERED, max_sleep=0)

    # BAD: The supplicant sends a 4th Offer (*before* receving the Offer it sent)
    supplicant._bind_state.sent_offer()
    supplicant._bind_state.sent_offer()
    try:
        supplicant._bind_state.sent_offer()
    except Exceptions.BindRetryError:
        pass
    else:
        assert False
    await assert_bind_state(supplicant, BindState.OFFERED, max_sleep=0)

    supplicant._bind_state.proc_offer(src=supplicant, _=None)
    await assert_bind_state(supplicant, BindState.OFFERED, max_sleep=0)

    supplicant._bind_state.proc_offer(src=supplicant, _=None)  # supplicant retransmits
    await assert_bind_state(supplicant, BindState.OFFERED, max_sleep=0)

    # BAD: The supplicant receives an Offer, but not from itself
    try:
        supplicant._bind_state.proc_offer(src=respondent, _=None)  # TODO: use 3rd dev
    except Exceptions.BindFlowError:
        pass
    else:
        assert False

    # PHASE 2: The respondent receives the Offer... and Accepts
    await assert_bind_state(respondent, BindState.LISTENING, max_sleep=0)
    respondent._bind_state.proc_offer(src=supplicant, _=None)
    await assert_bind_state(respondent, BindState.ACCEPTING, max_sleep=0)

    respondent._bind_state.proc_offer(src=supplicant, _=None)  # supplicant retransmits
    await assert_bind_state(respondent, BindState.ACCEPTING, max_sleep=0)

    respondent._bind_state.sent_accept()
    await assert_bind_state(respondent, BindState.ACCEPTED, max_sleep=0)

    # BAD: The respondent sends a 4th Accept (*after* receiving the Offer it sent)
    respondent._bind_state.sent_accept()
    respondent._bind_state.sent_accept()
    try:
        respondent._bind_state.sent_accept()
    except Exceptions.BindRetryError:
        pass
    else:
        assert False
    await assert_bind_state(respondent, BindState.ACCEPTED, max_sleep=0)

    respondent._bind_state.proc_accept(src=respondent, _=supplicant)
    await assert_bind_state(respondent, BindState.ACCEPTED, max_sleep=0)

    # PHASE 3: The supplicant receives the Accept... and Confirms (after 3x is Bound)
    await assert_bind_state(supplicant, BindState.OFFERED, max_sleep=0)
    supplicant._bind_state.proc_accept(src=respondent, _=supplicant)
    await assert_bind_state(supplicant, BindState.CONFIRMING, max_sleep=0)

    supplicant._bind_state.sent_confirm()
    await assert_bind_state(supplicant, BindState.CONFIRMED, max_sleep=0)

    supplicant._bind_state.proc_confirm(src=supplicant, _=respondent)
    await assert_bind_state(supplicant, BindState.CONFIRMED, max_sleep=0)

    # BAD: The supplicant sends a 4th Confirm (*after* receiving the Confirm it sent)
    supplicant._bind_state.sent_confirm()
    supplicant._bind_state.sent_confirm()
    await assert_bind_state(supplicant, BindState.BOUND, max_sleep=0)

    try:
        supplicant._bind_state.sent_confirm()
    except Exceptions.BindFlowError:  # not: BindRetryError, as Confirming -> Bound
        pass
    else:
        assert False
    await assert_bind_state(supplicant, BindState.BOUND, max_sleep=0)

    # PHASE 4: The respondent receives the Confirm
    # BAD: The respondent receives a Confirm, but not from the supplicant
    try:
        respondent._bind_state.proc_confirm(src=respondent, _=None)  # TODO: use 3rd dev
    except Exceptions.BindFlowError:
        pass
    else:
        assert False

    # The respondent receives the Confirm
    await assert_bind_state(respondent, BindState.ACCEPTED, max_sleep=0)
    respondent._bind_state.proc_confirm(src=supplicant, _=respondent)
    await assert_bind_state(respondent, BindState.BOUND_ACCEPTED, max_sleep=0)

    # TODO: GOOD: The respondent receives a 2nd/3rd Confirm
    respondent._bind_state.proc_confirm(src=supplicant, _=respondent)
    respondent._bind_state.proc_confirm(src=supplicant, _=respondent)
    await assert_bind_state(respondent, BindState.BOUND_ACCEPTED, max_sleep=0)

    # TODO: GOOD: The respondent receives a 4th Confirm
    respondent._bind_state.proc_confirm(src=supplicant, _=respondent)


async def test_binding_state_machine(test_data):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_fsm,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )
