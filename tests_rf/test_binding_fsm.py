#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
import functools
from unittest.mock import patch

import pytest

from ramses_rf import Code, Device, Gateway
from ramses_rf.binding_fsm import (
    SZ_RESPONDENT,
    SZ_SUPPLICANT,
    BindContext,
    BindState,
    BindStateBase,
)
from ramses_rf.device import Fakeable
from ramses_rf.protocol.protocol import QosProtocol, _BaseProtocol, _ProtQosTimers

from .virtual_rf import VirtualRf

_ACCEPT_WAIT_TIME = 0.95  # #  patch ramses_rf.binding_fsm
_TENDER_WAIT_TIME = 3.95  # #  patch ramses_rf.binding_fsm
DEFAULT_MAX_RETRIES = 0  # #       patch ramses_rf.protocol.protocol
DEFAULT_WAIT_TIMEOUT = 0.05  # #   patch ramses_rf.protocol.protocol_fsm
MAINTAIN_STATE_CHAIN = False  # #  patch ramses_rf.protocol.protocol_fsm
MAX_DUTY_CYCLE = 1.0  # #          patch ramses_rf.protocol.protocol
MIN_GAP_BETWEEN_WRITES = 0  # #    patch ramses_rf.protocol.protocol


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

SCHEME_LOOKUP = {
    ITHO__: {"oem_code": "01", "idx": "00", "offer_to": None},
    NUAIRE: {"oem_code": "6C", "idx": "21", "offer_to": None},
    ORCON_: {"oem_code": "67", "idx": "00", "offer_to": "63:262142"},
}
TEST_SUITE_300 = [
    {
        SZ_RESPONDENT: {
            "30:098165": {"class": "FAN", "scheme": "nuaire", "_notes": "ECO-HEAT-HC"}
        },
        SZ_SUPPLICANT: {
            "32:208628": {"class": "REM", "scheme": "nuaire", "_notes": "4-way switch"}
        },
        # PKT_FLOW: (
        #     " I --- 32:208628 --:------ 32:208628 1FC9 018 00-22F1-832EF4 6C-10E0-832EF4 00-1FC9-832EF4",
        #     " W --- 30:098165 32:208628 --:------ 1FC9 006 21-31DA-797F75",
        #     " I --- 32:208628 30:098165 --:------ 1FC9 001 21",
        #     # I --- 32:208628 63:262142 --:------ 10E0 030 00-0001C85A0101-6C-FFFFFFFFFFFF010607E0564D4E2D32334C4D48323300",
        #     # I --- 32:208628 --:------ 32:208628 1060 003 00-FF01",  # sends x3
        # ),
    },
    {
        SZ_RESPONDENT: {
            "32:155617": {"class": "FAN", "scheme": "itho", "_notes": "Itho Spider HRU"}
        },
        SZ_SUPPLICANT: {
            "37:171871": {"class": "CO2", "scheme": "itho", "_notes": "Itho Spider CO2"}
        },
        # PKT_FLOW: (
        #     " I --- 37:154011 --:------ 37:154011 1FC9 030 00-31E0-96599B 00-1298-96599B 00-2E10-96599B 01-10E0-96599B 00-1FC9-96599B",
        #     " W --- 18:126620 37:154011 --:------ 1FC9 012 00-31D9-49EE9C 00-31DA-49EE9C",
        #     " I --- 37:154011 18:126620 --:------ 1FC9 001 00",
        #     # I --- 37:154011 63:262142 --:------ 10E0 038 00-000100280901-01-FEFFFFFFFFFF140107E5564D532D31324333390000000000000000000000",
        # ),
    },
    {
        SZ_RESPONDENT: {
            "29:158183": {
                "class": "FAN",
                "scheme": "orcon",
                "_notes": "HRC-350 EcoMax/MaxComfort",
            }
        },
        SZ_SUPPLICANT: {
            "32:155617": {
                "class": "REM",
                "scheme": "orcon",
                "_notes": "Orcon VMN-15LF01",
            }
        },
        # PKT_FLOW: (
        #     " I --- 29:158183 63:262142 --:------ 1FC9 024 00-22F1-7669E7 00-22F3-7669E7 67-10E0-7669E7 00-1FC9-7669E7",
        #     " W --- 32:155617 29:158183 --:------ 1FC9 012 00-31D9-825FE1 00-31DA-825FE1",
        #     " I --- 29:158183 32:155617 --:------ 1FC9 001 00",
        #     # I --- 29:158183 63:262142 --:------ 10E0 038 00-0001C8270901-67-FFFFFFFFFFFF0D0207E3564D4E2D31354C46303100000000000000000000",
        #     # I --- 29:158183 --:------ 29:158183 1060 003 00-FF01",
        # ),
    },
    {
        SZ_RESPONDENT: {"32:155617": {"class": "FAN", "scheme": "orcon"}},
        SZ_SUPPLICANT: {"37:171871": {"class": "DIS", "scheme": "orcon"}},
        PKT_FLOW: (),
    },
    {
        SZ_RESPONDENT: {"01:145038": {"class": "CTL"}},
        SZ_SUPPLICANT: {"07:045960": {"class": "DHW"}},
        # PKT_FLOW: (
        #     " I --- 07:045960 --:------ 07:045960 1FC9 012 00-1260-1CB388 00-1FC9-1CB388",
        #     " W --- 01:145038 07:045960 --:------ 1FC9 006 00-10A0-06368E",
        #     " I --- 07:045960 01:145038 --:------ 1FC9 006 00-1260-1CB388",
        # ),  # TODO: need epilogue packets
    },
    {
        SZ_RESPONDENT: {"01:085545": {"class": "CTL"}},
        SZ_SUPPLICANT: {"22:057520": {"class": "THM"}},  # is THM, not STA
        PKT_FLOW: (
            " I --- 22:057520 --:------ 22:057520 1FC9 024 00-2309-58E0B0 00-30C9-58E0B0 00-0008-58E0B0 00-1FC9-58E0B0",
            " W --- 01:085545 22:057520 --:------ 1FC9 006 07-2309-054E29",
            " I --- 22:057520 01:085545 --:------ 1FC9 006 00-2309-58E0B0",
        ),
    },
    {
        SZ_RESPONDENT: {"01:145038": {"class": "CTL"}},
        SZ_SUPPLICANT: {"34:092243": {"class": "RND"}},
        # PKT_FLOW: (
        #     " I --- 34:259472 --:------ 34:259472 1FC9 024 00-2309-8BF590 00-30C9-8BF590 00-0008-8BF590 00-1FC9-8BF590",
        #     " W --- 01:220768 34:259472 --:------ 1FC9 006 01-2309-075E60",
        #     " I --- 34:259472 01:220768 --:------ 1FC9 006 01-2309-8BF590",
        #     # I --- 34:259472 63:262142 --:------ 10E0 038 00-0001C8380F01-00-F1FF070B07E6030507E15438375246323032350000000000000000000000",
        #     # I --- 34:259472 --:------ 34:259472 1060 003 00-FF01",
        #     # I --- 34:259472 --:------ 34:259472 0005 012 000A0000000F000000100000",
        #     # I --- 34:259472 --:------ 34:259472 000C 018 000A7FFFFFFF000F7FFFFFFF00107FFFFFFF",
        # ),
    },
]


def id_fnc(test_set):
    r_class = list(test_set[SZ_RESPONDENT].values())[0]["class"]
    s_class = list(test_set[SZ_SUPPLICANT].values())[0]["class"]
    return s_class + " binding to " + r_class


def pytest_generate_tests(metafunc):
    folders = TEST_SUITE_300
    metafunc.parametrize("test_set", folders, ids=id_fnc)


# ######################################################################################


class _QosProtocol(_ProtQosTimers, _BaseProtocol):
    """Test only QoS, not Duty cycle limits (& gaps) and Impersonation alerts."""

    pass


async def assert_protocol_ready(
    protocol: QosProtocol, max_sleep: int = DEFAULT_MAX_SLEEP
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if protocol._transport is not None:
            break
    assert protocol._transport is not None


async def assert_context_state(
    device: Fakeable, state: BindStateBase, max_sleep: int = DEFAULT_MAX_SLEEP
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if isinstance(device._context.state, state):
            break
    assert isinstance(device._context.state, state)


def rf_network_with_two_gateways(fnc):
    """Decorator to create a virtual RF network with two separate gateways.

    Each gateway has its own schema.
    """

    def get_or_set_hgi_id_from_known_list(idx: int, config: dict) -> str:
        """Extract or create/insert a HGI device ID from/into the configuration."""

        known_list = config["known_list"] = config.get("known_list", {})

        gwy_ids = [k for k, v in known_list.items() if v.get("class") == "HGI"]
        if not gwy_ids:
            gwy_ids = [
                k
                for k, v in known_list.items()
                if v.get("class") is None and k[:3] == "18:"
            ]
        gwy_id = gwy_ids[0] if gwy_ids else f"18:{str(idx) * 6}"

        if known_list.get(gwy_id):
            known_list[gwy_id]["class"] = "HGI"
        else:
            known_list[gwy_id] = {"class": "HGI"}

        return gwy_id

    @patch("ramses_rf.protocol.protocol.QosProtocol", _QosProtocol)
    @patch("ramses_rf.protocol.protocol_fsm.DEFAULT_WAIT_TIMEOUT", DEFAULT_WAIT_TIMEOUT)
    @functools.wraps(fnc)
    async def test_wrapper(config_0: dict, config_1: dict, *args, **kwargs):
        rf = VirtualRf(2, start=True)

        _gwys = []  # HACK:  we need a way to extract gwy object from rf

        for idx, config in enumerate((config_0, config_1)):
            gwy_addr = get_or_set_hgi_id_from_known_list(idx, config)

            rf.set_gateway(rf.ports[idx], gwy_addr)
            gwy = Gateway(rf.ports[idx], **config)
            await gwy.start()  # start_discovery=False)
            gwy._transport._extra["rf"] = rf
            await assert_protocol_ready(gwy._protocol)

            _gwys += [gwy]  # HACK: messy

        try:
            await fnc(_gwys[0], _gwys[1], *args, **kwargs)  # HACK
        finally:
            for gwy in _gwys:  # HACK
                await gwy.stop()
            await rf.stop()

    return test_wrapper


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


@patch("ramses_rf.binding_fsm._ACCEPT_WAIT_TIME", _ACCEPT_WAIT_TIME)  # waitfor Accept
@patch("ramses_rf.binding_fsm._TENDER_WAIT_TIME", _TENDER_WAIT_TIME)  # waitfor Offer
@patch("ramses_rf.binding_fsm._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN)
@rf_network_with_two_gateways
async def _test_flow_30x(
    gwy_r: Gateway, gwy_s: Gateway, pkt_flow_expected: list[str]
) -> None:
    """Check the change of state during a binding at device layer."""

    # STEP 0: Setup...
    loop = asyncio.get_running_loop()

    respondent: Fakeable = gwy_r.devices[0]
    ensure_fakeable(respondent)
    supplicant: Fakeable = gwy_s.devices[0]

    await assert_context_state(respondent, BindState.IDLE)
    await assert_context_state(supplicant, BindState.IDLE)

    # STEP 1: Start the listener
    task = loop.create_task(respondent.wait_for_binding_request([Code._31DA], idx="21"))
    await assert_context_state(respondent, BindState.LISTENING)

    # STEP 2: Start/finish the requester, oem_code="6C"?
    _ = await supplicant.initiate_binding_process(Code._22F1, oem_code="6C")
    await assert_context_state(supplicant, BindState.CONFIRMED)

    # STEP 3: Finish the requester
    _ = task.result()

    # STEP 4: Confirm the bindings
    await assert_context_state(respondent, BindState.BOUND_ACCEPTED)
    # takes another 0.25s, as have to wait for a timer to expire
    # await assert_context_state(supplicant, BindState.BOUND)

    # STEP 4: Confirm the flow (sequence) of packets
    pkt_flow_actual = [
        d[2].decode("ascii")[:-2]
        for d in gwy_r._transport.get_extra_info("rf")._log
        if d[1] == "SENT" and b" 7FFF " not in d[2]
    ]

    for a, e in zip(pkt_flow_actual, pkt_flow_expected):
        assert a == e


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_300(test_set: dict[str:dict]) -> None:
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

    await _test_flow_30x(config[SZ_RESPONDENT], config[SZ_SUPPLICANT], pkt_flow)
