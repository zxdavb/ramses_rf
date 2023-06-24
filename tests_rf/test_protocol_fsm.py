#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF - **using binding FSM**.

    NB: This test will likely fail with pytest-repeat (pytest -n x); maybe because of
    concurrent access to pty.openpty().
"""

import asyncio
import functools
from datetime import datetime as dt
from typing import TypeVar

import pytest

from ramses_rf import Command, Packet
from ramses_rf.bind_state import Context, State
from ramses_rf.device.base import Fakeable
from ramses_rf.protocol.protocol import QosProtocol, protocol_factory
from ramses_rf.protocol.protocol_fsm import ProtocolState
from ramses_rf.protocol.transport import transport_factory

from .virtual_rf import VirtualRf

_DeviceStateT = TypeVar("_DeviceStateT", bound=State)
_FakedDeviceT = TypeVar("_FakedDeviceT", bound=Fakeable)


CONFIRM_TIMEOUT_SECS = 0.001  # to patch ramses_rf.bind_state
WAITING_TIMEOUT_SECS = 0  # to patch ramses_rf.bind_state

ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 1


TEST_DATA = (
    (("40:111111", "CO2"), ("41:888888", "FAN"), ("1298",)),
)  # supplicant, respondent, codes


async def assert_context_state(
    ctx: Context, expected_state: type[_DeviceStateT], max_sleep: int = 0
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if ctx._state.__class__ is expected_state:
            break
    assert ctx._state.__class__ is expected_state


async def assert_protocol_state(
    protocol: QosProtocol,
    expected: type[ProtocolState],
    max_sleep: int = DEFAULT_MAX_SLEEP,
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if isinstance(protocol._context._state, expected):
            break
    assert isinstance(protocol._context._state, expected)


async def assert_protocol_ready(
    protocol: QosProtocol, max_sleep: int = DEFAULT_MAX_SLEEP
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if protocol._this_msg is not None:
            break
    assert protocol._this_msg and protocol._this_msg.code == "7FFF"


def _test_decorator(fnc):
    """Create a protocol stack with a virtual port."""

    @functools.wraps(fnc)
    async def test_wrapper():
        def msg_handler(msg) -> None:
            pass

        rf = VirtualRf(1, start=True)

        protocol = protocol_factory(msg_handler)
        await assert_protocol_state(protocol, ProtocolState.DEAD, max_sleep=0)

        transport = transport_factory(
            protocol,
            port_name=rf.ports[0],
            port_config={},
            enforce_include_list=False,
            exclude_list={},
            include_list={},
        )

        await assert_protocol_ready(protocol)
        await assert_protocol_state(protocol, ProtocolState.IDLE)

        try:
            await fnc(protocol)
        finally:
            transport.close()
            await rf.stop()

    return test_wrapper


async def _phase_0(protocol: QosProtocol) -> None:
    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

    # d = Command("RQ --- 18:111111 01:222222 --:------ 12B0 003 07")  # TODO: better handling than AttributeError

    rq = "RQ --- 18:000730 01:222222 --:------ 12B0 001 07"
    rp = "RP --- 01:222222 18:000730 --:------ 12B0 003 070000"

    # await protocol.send_cmd(Command(rq))
    protocol._context.send_cmd(Command(rq))
    await assert_protocol_state(protocol, ProtocolState.ECHO)

    protocol._context._pkt_received(Packet(dt.now(), "... " + rq))
    await assert_protocol_state(protocol, ProtocolState.WAIT)

    protocol._context._pkt_received(Packet(dt.now(), "... " + rp))
    await assert_protocol_state(protocol, ProtocolState.IDLE)


@_test_decorator
async def _test_flow_0(protocol: QosProtocol):
    """Check the change of state during a faultless send_cmd(cmd)."""

    await _phase_0(protocol)


@pytest.mark.xdist_group(name="serial")
async def test_flow_0():
    await _test_flow_0()
