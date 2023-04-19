#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF.

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
from typing import Callable
from unittest.mock import patch

from ramses_rf import Gateway
from ramses_rf.device.base import BindState, Fakeable
from ramses_rf.protocol.command import Command
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.transport import PacketProtocolQos as PacketProtocol
from tests.virtual_rf import VirtualRF

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


async def _stifle_impersonation_alerts(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


async def assert_bind_state(
    dev: Fakeable, expected_state: BindState, max_sleep: int = MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if dev._1fc9_state["state"] == expected_state:
            break
    assert dev._1fc9_state["state"] == expected_state


async def assert_this_pkt_hdr(
    pkt_protocol: PacketProtocol, expected_hdr: str, max_sleep: int = MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if pkt_protocol._this_pkt and pkt_protocol._this_pkt._hdr == expected_hdr:
            break
    assert pkt_protocol._this_pkt and pkt_protocol._this_pkt._hdr == expected_hdr


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


async def _test_bind_state(
    dev: Fakeable, expected_state: BindState, max_sleep: int = MAX_SLEEP
):
    await assert_bind_state(dev, expected_state, max_sleep)

    return dev._gwy.pkt_protocol._this_pkt


async def _test_pkt_hdr(
    pkt_protocol: PacketProtocol, expected_hdr: str, max_sleep: int = MAX_SLEEP
):
    await assert_this_pkt_hdr(pkt_protocol, expected_hdr, max_sleep)

    return pkt_protocol._this_pkt


async def _test_binding_flow(supplicant: Fakeable, respondent: Fakeable, codes):
    """Check the flow of packets during a binding."""

    hdr_flow = [
        "1FC9| I|63:262142",
        f"1FC9| W|{supplicant.id}",
        f"1FC9| I|{respondent.id}",
    ]

    respondent._make_fake()  # TODO: waiting=Code._22F1)
    respondent._bind_waiting(codes)

    assert supplicant._gwy.pkt_protocol._this_pkt is None
    assert respondent._gwy.pkt_protocol._this_pkt is None

    supplicant._make_fake(bind=True)  # rem._bind()

    # using tasks, since a sequence of awaits gives unreliable results
    tasks = [
        asyncio.create_task(_test_pkt_hdr(role._gwy.pkt_protocol, hdr))
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


async def _test_binding_state(supplicant: Fakeable, respondent: Fakeable, codes):
    """Check the change of state during a binding."""

    packets = {}

    def track_packet_flow(msg: Message, prev_msg: Message | None = None) -> None:
        if (msg._pkt._hdr, msg._gwy.hgi.id) not in packets:  # ignore retransmits
            packets[msg._pkt._hdr, msg._gwy.hgi.id] = msg._pkt

    # supplicant._gwy.create_client(track_packet_flow)
    # respondent._gwy.create_client(track_packet_flow)

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

    # can (rarely?) get unreliable results for respondent as awaits are asynchronous
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
