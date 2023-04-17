#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol."""

import asyncio
from unittest.mock import patch

from ramses_rf import Gateway
from ramses_rf.device.base import BindState, Fakeable
from ramses_rf.protocol.command import Command
from tests.virtual_rf import VirtualRF

MAX_SLEEP = 5


def pytest_generate_tests(metafunc):
    def id_fnc(param):
        return f"{param[0][1]} to {param[1][1]}"

    metafunc.parametrize("test_data", TEST_DATA, ids=id_fnc)


CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}


async def _stifle_impersonation_alerts(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


async def assert_bind_state(dev, state, max_sleep: int = MAX_SLEEP):
    for _ in range(int(max_sleep / 0.001)):
        await asyncio.sleep(0.001)
        if dev._1fc9_state["state"] == state:
            break
    assert dev._1fc9_state["state"] == state


async def assert_this_pkt_hdr(pkt_protocol, hdr: str, max_sleep: int = MAX_SLEEP):
    for _ in range(int(max_sleep / 0.001)):
        await asyncio.sleep(0.001)
        if pkt_protocol._this_pkt and pkt_protocol._this_pkt._hdr == hdr:
            break
    assert pkt_protocol._this_pkt and pkt_protocol._this_pkt._hdr == hdr


TEST_DATA: tuple[dict[str, str], dict[str, str], tuple[str]] = (
    (("40:111111", "REM"), ("41:888888", "FAN"), ("22F1",)),
    (("22:111111", "THM"), ("01:888888", "CTL"), ("30C9",)),
)  # supplicant, respondent, codes


@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    _stifle_impersonation_alerts,
)
async def _test_binding_wrapper(
    fnc, supp_schema: dict, resp_schema: dict, codes: tuple
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


async def _test_binding_flow(supplicant, respondent, codes):
    """Check the flow of packets during a binding."""

    respondent._make_fake()  # TODO: waiting=Code._22F1)
    respondent._bind_waiting(codes)

    assert supplicant._gwy.pkt_protocol._this_pkt is None
    assert respondent._gwy.pkt_protocol._this_pkt is None

    supplicant._make_fake(bind=True)  # rem._bind()

    await assert_this_pkt_hdr(supplicant._gwy.pkt_protocol, "1FC9| I|63:262142")
    await assert_this_pkt_hdr(respondent._gwy.pkt_protocol, "1FC9| I|63:262142")

    await assert_this_pkt_hdr(respondent._gwy.pkt_protocol, f"1FC9| W|{supplicant.id}")
    await assert_this_pkt_hdr(supplicant._gwy.pkt_protocol, f"1FC9| W|{supplicant.id}")

    await assert_this_pkt_hdr(supplicant._gwy.pkt_protocol, f"1FC9| I|{respondent.id}")
    await assert_this_pkt_hdr(respondent._gwy.pkt_protocol, f"1FC9| I|{respondent.id}")


async def _test_binding_state(supplicant, respondent, codes):
    """Check the change of state during a binding."""

    await assert_bind_state(supplicant, BindState.UNKNOWN, max_sleep=0)
    await assert_bind_state(respondent, BindState.UNKNOWN, max_sleep=0)

    respondent._make_fake()  # TODO: waiting=Code._22F1)
    respondent._bind_waiting(codes)
    await assert_bind_state(supplicant, BindState.UNKNOWN, max_sleep=0)
    await assert_bind_state(respondent, BindState.LISTENING, max_sleep=0)

    try:
        supplicant._bind()
    except RuntimeError:
        pass
    else:
        assert False

    await assert_bind_state(supplicant, BindState.UNKNOWN, max_sleep=0)
    await assert_bind_state(respondent, BindState.LISTENING, max_sleep=0)

    supplicant._make_fake(bind=True)  # rem._bind()
    await assert_bind_state(supplicant, BindState.OFFERING, max_sleep=0)
    await assert_bind_state(respondent, BindState.ACCEPTING)

    await assert_bind_state(supplicant, BindState.BOUND)
    await assert_bind_state(respondent, BindState.BOUND)


async def test_binding_flow(test_data):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_flow,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )


async def test_binding_state(test_data):
    supp, resp, codes = test_data

    await _test_binding_wrapper(
        _test_binding_state,
        {"orphans_hvac": [supp[0]], "known_list": {supp[0]: {"class": supp[1]}}},
        {"orphans_hvac": [resp[0]], "known_list": {resp[0]: {"class": resp[1]}}},
        codes,
    )
