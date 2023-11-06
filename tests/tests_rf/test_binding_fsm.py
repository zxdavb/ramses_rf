#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

# TODO: test addenda phase of binding handshake
# TODO: get test working with (and without) disabled QoS

"""Test the binding protocol with a virtual RF

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
from datetime import datetime as dt
from unittest.mock import patch

import pytest

from ramses_rf import Code, Device, Gateway, Message, Packet
from ramses_rf.binding_fsm import (
    SZ_RESPONDENT,
    SZ_SUPPLICANT,
    BindContext,
    BindStateBase,
    _BindStates,
)
from ramses_rf.device import Fakeable

from .virtual_rf import rf_factory

# patched constants
_DEBUG_DISABLE_IMPERSONATION_ALERTS = True  # # ramses_tx.protocol
_DEBUG_DISABLE_QOS = False  # #                 ramses_tx.protocol
DEFAULT_MAX_RETRIES = 0  # #                    ramses_tx.protocol
DEFAULT_TIMEOUT = 0.005  # #                    ramses_tx.protocol_fsm
MAINTAIN_STATE_CHAIN = False  # #               ramses_tx.protocol_fsm
MIN_GAP_BETWEEN_WRITES = 0  # #                 ramses_tx.protocol

# other constants
ASSERT_CYCLE_TIME = 0.0005  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 0.1

PKT_FLOW = "packets"


DEFAULT_GATEWAY_CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": True,
    }
}

ITHO__ = "itho"
NUAIRE = "nuaire"
ORCON_ = "orcon"

TEST_SUITE_300 = [
    {
        SZ_RESPONDENT: {
            "30:098165": {"class": "FAN", " scheme": "nuaire", "_notes": "ECO-HEAT-HC"},
        },
        SZ_SUPPLICANT: {
            "32:208628": {"class": "REM", "scheme": "nuaire", "_notes": "4-way switch"}
        },
        f"{SZ_RESPONDENT}_attr": {"codes": [Code._31DA], "idx": "21"},
        PKT_FLOW: (
            " I --- 32:208628 --:------ 32:208628 1FC9 018 00-22F1-832EF4 6C-10E0-832EF4 00-1FC9-832EF4",
            " W --- 30:098165 32:208628 --:------ 1FC9 006 21-31DA-797F75",
            " I --- 32:208628 30:098165 --:------ 1FC9 001 21",
            " I --- 32:208628 63:262142 --:------ 10E0 030 00-0001C85A0101-6C-FFFFFFFFFFFF010607E0564D4E2D32334C4D48323300",
            # I --- 32:208628 --:------ 32:208628 1060 003 00-FF01",  # sends x3
        ),
    },
    {
        SZ_RESPONDENT: {
            "18:126620": {"class": "FAN", "scheme": "itho", "_notes": "Spider HRU"},
        },
        SZ_SUPPLICANT: {
            "37:154011": {"class": "CO2", "scheme": "itho", "_notes": "Spider CO2"}
        },
        f"{SZ_RESPONDENT}_attr": {"codes": [Code._31D9, Code._31DA]},
        PKT_FLOW: (
            " I --- 37:154011 --:------ 37:154011 1FC9 030 00-31E0-96599B 00-1298-96599B 00-2E10-96599B 01-10E0-96599B 00-1FC9-96599B",
            " W --- 18:126620 37:154011 --:------ 1FC9 012 00-31D9-49EE9C 00-31DA-49EE9C",
            " I --- 37:154011 18:126620 --:------ 1FC9 001 00",
            " I --- 37:154011 63:262142 --:------ 10E0 038 00-000100280901-01-FEFFFFFFFFFF140107E5564D532D31324333390000000000000000000000",
        ),
    },
    {  # FIXME: offer sent to 63:262142, so send_cmd() wont return corresponding accept
        SZ_RESPONDENT: {
            "32:155617": {"class": "FAN", "scheme": "orcon", "_notes": "HRC-350"},
        },
        SZ_SUPPLICANT: {
            "29:158183": {"class": "REM", "scheme": "orcon", "_notes": "VMN-15LF01"}
        },
        f"{SZ_RESPONDENT}_attr": {"codes": [Code._31D9, Code._31DA]},
        PKT_FLOW: (
            " I --- 29:158183 63:262142 --:------ 1FC9 024 00-22F1-7669E7 00-22F3-7669E7 67-10E0-7669E7 00-1FC9-7669E7",
            " W --- 32:155617 29:158183 --:------ 1FC9 012 00-31D9-825FE1 00-31DA-825FE1",
            " I --- 29:158183 32:155617 --:------ 1FC9 001 00",
            " I --- 29:158183 63:262142 --:------ 10E0 038 00-0001C8270901-67-FFFFFFFFFFFF0D0207E3564D4E2D31354C46303100000000000000000000",
            # I --- 29:158183 --:------ 29:158183 1060 003 00-FF01",
        ),
    },
    {  # FIXME: supplicant used oem_code and 10E0
        SZ_RESPONDENT: {"32:155617": {"class": "FAN", "scheme": "orcon"}},
        SZ_SUPPLICANT: {"37:171871": {"class": "DIS", "scheme": "orcon"}},
        f"{SZ_RESPONDENT}_attr": {"codes": [Code._31D9, Code._31DA]},
        PKT_FLOW: (
            " I --- 37:171871 --:------ 37:171871 1FC9 024 00-22F1-969F5F 00-22F3-969F5F 67-10E0-969F5F 00-1FC9-969F5F",
            " W --- 32:155617 37:171871 --:------ 1FC9 012 00-31D9-825FE1 00-31DA-825FE1",
            " I --- 37:171871 32:155617 --:------ 1FC9 001 00",
            " I --- 37:171871 63:262142 --:------ 10E0 038 00-0001C8940301-67-FFFFFFFFFFFF1B0807E4564D492D313557534A3533000000000000000000",
        ),
    },
    {  # FIXME: confirm is:  I --- 07:045960 01:145038 --:------ 1FC9 006 0012601CB388
        SZ_RESPONDENT: {"01:145038": {"class": "CTL"}},
        SZ_SUPPLICANT: {"07:045960": {"class": "DHW"}},
        f"{SZ_RESPONDENT}_attr": {"codes": [Code._10A0]},
        PKT_FLOW: (
            " I --- 07:045960 --:------ 07:045960 1FC9 012 00-1260-1CB388 00-1FC9-1CB388",
            " W --- 01:145038 07:045960 --:------ 1FC9 006 00-10A0-06368E",
            " I --- 07:045960 01:145038 --:------ 1FC9 006 00-1260-1CB388",
        ),  # TODO: need epilogue packets, if any (1060?)
    },
    {  # FIXME: confirm is not:  I --- 22:057520 01:085545 --:------ 1FC9 006 07
        SZ_RESPONDENT: {"01:085545": {"class": "CTL"}},
        SZ_SUPPLICANT: {"22:057520": {"class": "THM"}},  # is THM, not STA
        f"{SZ_RESPONDENT}_attr": {"codes": [Code._2309], "idx": "07"},
        PKT_FLOW: (
            " I --- 22:057520 --:------ 22:057520 1FC9 024 00-2309-58E0B0 00-30C9-58E0B0 00-0008-58E0B0 00-1FC9-58E0B0",
            " W --- 01:085545 22:057520 --:------ 1FC9 006 07-2309-054E29",
            " I --- 22:057520 01:085545 --:------ 1FC9 006 00-2309-58E0B0",
        ),
    },
    {  # FIXME: needs initiate_binding_process(), and above
        SZ_RESPONDENT: {"01:145038": {"class": "CTL"}},
        SZ_SUPPLICANT: {"34:092243": {"class": "RND"}},
        PKT_FLOW: (
            " I --- 34:259472 --:------ 34:259472 1FC9 024 00-2309-8BF590 00-30C9-8BF590 00-0008-8BF590 00-1FC9-8BF590",
            " W --- 01:220768 34:259472 --:------ 1FC9 006 01-2309-075E60",
            " I --- 34:259472 01:220768 --:------ 1FC9 006 01-2309-8BF590",
            " I --- 34:259472 63:262142 --:------ 10E0 038 00-0001C8380F01-00-F1FF070B07E6030507E15438375246323032350000000000000000000000",
            # I --- 34:259472 --:------ 34:259472 1060 003 00-FF01",
            # I --- 34:259472 --:------ 34:259472 0005 012 000A0000000F000000100000",
            # I --- 34:259472 --:------ 34:259472 000C 018 000A7FFFFFFF000F7FFFFFFF00107FFFFFFF",
        ),
    },
]

RESPONDENT_ATTRS_BY_SUPPLICANT = {
    f"{list(d[SZ_SUPPLICANT].keys())[0]} to {list(d[SZ_RESPONDENT].keys())[0]}": d.get(
        f"{SZ_RESPONDENT}_attr", {}
    )  # can't use .pop in a comprehension
    for d in TEST_SUITE_300
}

TEST_SUITE_300 = [
    {k: d[k] for k in (SZ_SUPPLICANT, SZ_RESPONDENT, PKT_FLOW)} for d in TEST_SUITE_300
]


# ### FIXTURES #########################################################################


@pytest.fixture(autouse=True)
def patches_for_tests(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "ramses_tx.protocol._DEBUG_DISABLE_IMPERSONATION_ALERTS",
        _DEBUG_DISABLE_IMPERSONATION_ALERTS,
    )
    monkeypatch.setattr(
        "ramses_tx.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES
    )


def pytest_generate_tests(metafunc: pytest.Metafunc):
    def id_fnc(test_set):
        r_class = list(test_set[SZ_RESPONDENT].values())[0]["class"]
        s_class = list(test_set[SZ_SUPPLICANT].values())[0]["class"]
        return s_class + " binding to " + r_class

    metafunc.parametrize("test_set", TEST_SUITE_300, ids=id_fnc)


# ######################################################################################


def ensure_fakeable(dev: Device) -> None:
    """If a Device is not Fakeable (i.e. Fakeable, not _faked), make it so."""

    class _Fakeable(dev.__class__, Fakeable):
        pass

    if isinstance(dev, Fakeable):
        # if hasattr(dev, "_make_fake"):  # no need for callable(getattr(...))
        return

    dev.__class__ = _Fakeable
    setattr(dev, "_faked", None)
    setattr(dev, "_context", BindContext(dev))
    setattr(dev, "_1fc9_state", {})


async def assert_context_state(
    device: Fakeable, state: type[BindStateBase], max_sleep: int = DEFAULT_MAX_SLEEP
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if isinstance(device._context.state, state):
            break
    assert isinstance(device._context.state, state)


# ### TESTS ############################################################################


# TODO: test addenda phase of binding handshake
async def _test_flow_10x(
    gwy_r: Gateway, gwy_s: Gateway, pkt_flow_expected: list[str]
) -> None:
    """Check the change of state during a binding at device layer."""

    # STEP 0: Setup...
    loop = asyncio.get_running_loop()

    respondent: Fakeable = gwy_r.devices[0]
    supplicant: Fakeable = gwy_s.devices[0]
    ensure_fakeable(respondent)

    await assert_context_state(respondent, _BindStates.IS_IDLE_DEVICE)
    await assert_context_state(supplicant, _BindStates.IS_IDLE_DEVICE)

    assert not respondent._context.is_binding
    assert not supplicant._context.is_binding

    #
    # Step R0: Respondent initial state
    respondent._context.set_state(_BindStates.NEEDING_TENDER)
    await assert_context_state(respondent, _BindStates.NEEDING_TENDER)
    assert respondent._context.is_binding

    #
    # Step S0: Supplicant initial state
    supplicant._context.set_state(_BindStates.NEEDING_ACCEPT)
    await assert_context_state(supplicant, _BindStates.NEEDING_ACCEPT)
    assert supplicant._context.is_binding

    #
    # Step R1: Respondent expects an Offer
    resp_task = loop.create_task(respondent._context._wait_for_offer())

    #
    # Step S1: Supplicant sends an Offer (makes Offer) and expects an Accept
    msg = Message(Packet(dt.now(), "000 " + pkt_flow_expected[0]))
    codes = [b[1] for b in msg.payload["bindings"] if b[1] != Code._1FC9]

    pkt = await supplicant._context._make_offer(codes)
    await assert_context_state(supplicant, _BindStates.NEEDING_ACCEPT)

    await resp_task
    await assert_context_state(respondent, _BindStates.NEEDING_AFFIRM)

    tender = resp_task.result()
    assert tender._pkt == pkt, "Resp's Msg doesn't match Supp's Offer cmd"

    supp_task = loop.create_task(supplicant._context._wait_for_accept(tender))

    #
    # Step R2: Respondent expects a Confirm after sending an Accept (accepts Offer)
    msg = Message(Packet(dt.now(), "000 " + pkt_flow_expected[1]))
    codes = [b[1] for b in msg.payload["bindings"]]

    pkt = await respondent._context._accept_offer(tender, codes)
    await assert_context_state(respondent, _BindStates.NEEDING_AFFIRM)

    await supp_task
    await assert_context_state(supplicant, _BindStates.TO_SEND_AFFIRM)

    accept = supp_task.result()
    assert accept._pkt == pkt, "Supp's Msg doesn't match Resp's Accept cmd"

    resp_task = loop.create_task(respondent._context._wait_for_confirm(accept))

    #
    # Step S2: Supplicant sends a Confirm (confirms Accept)
    msg = Message(Packet(dt.now(), "000 " + pkt_flow_expected[2]))
    codes = [b[1] for b in msg.payload["bindings"] if len(b) > 1]

    pkt = await supplicant._context._confirm_accept(accept, codes=codes)
    if True or len(pkt_flow_expected) == 3:  # FIXME
        await assert_context_state(supplicant, _BindStates.HAS_BOUND_SUPP)
    else:
        await assert_context_state(supplicant, _BindStates.TO_SEND_RATIFY)

    await resp_task
    if True or len(pkt_flow_expected) == 3:  # FIXME
        await assert_context_state(respondent, _BindStates.HAS_BOUND_RESP)
    else:
        await assert_context_state(respondent, _BindStates.NEEDING_RATIFY)

    affirm = resp_task.result()
    assert affirm._pkt == pkt, "Resp's Msg doesn't match Supp's Confirm cmd"

    #
    # Some bindings don't include an Addenda...
    if True or len(pkt_flow_expected) == 3:  # i.e. no addenda  FIXME
        return

    await assert_context_state(respondent, _BindStates.NEEDING_RATIFY)
    await assert_context_state(supplicant, _BindStates.TO_SEND_RATIFY)

    # Step R3: Respondent expects an Addenda (optional)
    resp_task = loop.create_task(
        respondent._context._wait_for_addenda(accept, timeout=0.05)
    )

    # Step S3: Supplicant sends an Addenda (optional)
    msg = Message(Packet(dt.now(), "000 " + pkt_flow_expected[3]))
    supplicant._msgz[msg.code] = {msg.verb: {msg._pkt._ctx: msg}}

    pkt = await supplicant._context._cast_addenda()
    await assert_context_state(supplicant, _BindStates.HAS_BOUND_SUPP)

    await assert_context_state(respondent, _BindStates.HAS_BOUND_RESP)
    await resp_task

    ratify = resp_task.result()
    assert ratify._pkt == pkt, "Resp's Msg doesn't match Supp's Addenda cmd"

    assert False


# TODO: get test working without QoS
@pytest.mark.xdist_group(name="virt_serial")
@patch("ramses_tx.protocol._DEBUG_DISABLE_QOS", _DEBUG_DISABLE_QOS)
async def test_flow_100(test_set: dict[str:dict]) -> None:
    """Check packet flow / state change of a binding at device layer."""

    config = {}
    for role in (SZ_RESPONDENT, SZ_SUPPLICANT):
        devices = [d for d in test_set.values() if isinstance(d, dict)]
        config[role] = DEFAULT_GATEWAY_CONFIG | {
            "known_list": {k: v for d in devices for k, v in d.items()},
            "orphans_hvac": list(test_set[role]),  # TODO: used by Heat domain too!
        }

    pkt_flow = [
        x[:46] + x[46:].replace(" ", "").replace("-", "")
        for x in test_set.get(PKT_FLOW, [])
    ]

    # cant use fixture for this, as new schema required for every test
    rf, gwys = await rf_factory([config[SZ_RESPONDENT], config[SZ_SUPPLICANT]])

    try:
        await _test_flow_10x(gwys[0], gwys[1], pkt_flow)
    finally:
        for gwy in gwys:
            await gwy.stop()
        await rf.stop()
