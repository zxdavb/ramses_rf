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
from ramses_rf.bind_state import BindState, BindStateBase, Context
from ramses_rf.device import Fakeable
from ramses_rf.protocol.protocol import QosProtocol, _BaseProtocol, _ProtQosTimers

from .virtual_rf import VirtualRf

DEFAULT_MAX_RETRIES = 0  # #     patch ramses_rf.protocol.protocol
DEFAULT_WAIT_TIMEOUT = 0.05  # # patch ramses_rf.protocol.protocol_fsm
MAINTAIN_STATE_CHAIN = True  # # patch ramses_rf.protocol.protocol_fsm
MAX_DUTY_CYCLE = 1.0  # #        patch ramses_rf.protocol.protocol
MIN_GAP_BETWEEN_WRITES = 0  # #  patch ramses_rf.protocol.protocol


ASSERT_CYCLE_TIME = 0.0005  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 0.1


DEFAULT_GATEWAY_CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": True,
    }
}


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
            await assert_protocol_ready(gwy._protocol)

            _gwys += [gwy]  # HACK

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
    setattr(dev, "_context", Context(dev))
    setattr(dev, "_1fc9_state", {})


# ######################################################################################


@patch(  # maintain state chain (for debugging)
    "ramses_rf.protocol.protocol_fsm._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN
)
@rf_network_with_two_gateways
async def _test_flow_10x(gwy_r: Gateway, gwy_s: Gateway, *args, **kwargs) -> None:
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
    result_r = await supplicant.initiate_binding_process(
        [Code._22F1, Code._22F3], use_oem_code=True
    )
    await assert_context_state(supplicant, BindState.CONFIRMED)

    # STEP 3: Finish the requester
    result_s = task.result()
    assert result_r == result_s  # both Packets

    # STEP 4: Confirm the bindings
    await assert_context_state(respondent, BindState.BOUND_ACCEPTED)

    # takes another 0.25s, as have to wait for a timer to expire
    # await assert_context_state(supplicant, BindState.BOUND)


# ######################################################################################


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_100() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""

    config_0 = DEFAULT_GATEWAY_CONFIG | {
        "known_list": {
            "30:098165": {"class": "FAN", "scheme": "nuaire"},
            "32:208628": {"class": "REM"},
        },
        "orphans_hvac": ["30:098165"],
    }

    config_1 = DEFAULT_GATEWAY_CONFIG | {
        "known_list": {
            "30:098165": {"class": "FAN"},
            "32:208628": {"class": "REM", "scheme": "nuaire"},
        },
        "orphans_hvac": ["32:208628"],
    }

    await _test_flow_10x(config_0, config_1)
