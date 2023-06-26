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
from unittest.mock import patch

import pytest

from ramses_rf import Command, Gateway, Packet
from ramses_rf.bind_state import Context, State
from ramses_rf.device.base import Fakeable
from ramses_rf.protocol.protocol import QosProtocol, protocol_factory
from ramses_rf.protocol.protocol_fsm import ProtocolState
from ramses_rf.protocol.transport import transport_factory

from .virtual_rf import VirtualRf, stifle_impersonation_alert

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
        if isinstance(ctx._state, expected_state):
            break
    assert isinstance(ctx._state, expected_state)


async def assert_protocol_state(
    protocol: QosProtocol,
    expected_state: type[ProtocolState],
    max_sleep: int = DEFAULT_MAX_SLEEP,
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if isinstance(protocol._context._state, expected_state):
            break
    assert isinstance(protocol._context._state, expected_state), expected_state


async def assert_protocol_ready(
    protocol: QosProtocol, max_sleep: int = DEFAULT_MAX_SLEEP
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if protocol._this_msg is not None:
            break
    assert protocol._this_msg and protocol._this_msg.code == "7FFF"


def gateway_decorator(fnc):
    """Create a virtual RF network with a gateway."""

    @functools.wraps(fnc)
    async def test_wrapper():
        rf = VirtualRf(1)
        rf.set_gateway(rf.ports[0], "18:000730")

        gwy = Gateway(rf.ports[0])
        await gwy.start()

        # quiesce
        await assert_protocol_ready(gwy._protocol)
        # ait assert_device(gwy_0, "18:000730")

        await assert_protocol_state(gwy._protocol, ProtocolState.IDLE)

        try:
            await fnc(gwy)
        finally:
            gwy._transport.close()
            await rf.stop()

    return test_wrapper


def protocol_decorator(fnc):
    """Create a virtual RF network with a protocol stack."""

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

        # quiesce
        await assert_protocol_ready(protocol)
        # ait assert_device(gwy_0, "18:000730")

        await assert_protocol_state(protocol, ProtocolState.IDLE)

        try:
            await fnc(protocol)
        finally:
            transport.close()
            await rf.stop()

    return test_wrapper


# Command("RQ --- 18:111111 01:222222 --:------ 12B0 003 07")  # TODO: better handling than AttributeError

II_CMD_0 = " I --- 01:006056 --:------ 01:006056 1F09 003 0005C8"

RQ_CMD_0 = "RQ --- 18:000730 01:222222 --:------ 12B0 001 01"
RP_PKT_0 = "RP --- 01:222222 18:000730 --:------ 12B0 003 010000"

RQ_CMD_1 = "RQ --- 18:000730 01:222222 --:------ 12B0 001 02"
RP_PKT_1 = "RP --- 01:222222 18:000730 --:------ 12B0 003 020000"


async def _phase_01(protocol: QosProtocol) -> None:
    rq_cmd = RQ_CMD_0
    rp_pkt = RP_PKT_0

    await assert_context_state(protocol._context, ProtocolState.IDLE, max_sleep=0)

    protocol._context.send_cmd(Command(rq_cmd))
    await assert_context_state(protocol._context, ProtocolState.ECHO)

    protocol._context.pkt_received(Packet(dt.now(), "... " + rq_cmd))
    await assert_context_state(protocol._context, ProtocolState.WAIT)

    protocol._context.pkt_received(Packet(dt.now(), "... " + rp_pkt))
    await assert_context_state(protocol._context, ProtocolState.IDLE)


async def _phase_02(protocol: QosProtocol) -> None:
    rq_cmd = RQ_CMD_1
    rp_pkt = RP_PKT_1

    await assert_context_state(protocol._context, ProtocolState.IDLE, max_sleep=0)

    protocol._context.send_cmd(Command(rq_cmd))
    await assert_context_state(protocol._context, ProtocolState.ECHO)

    protocol._context.pkt_received(Packet(dt.now(), "... " + rq_cmd))
    await assert_context_state(protocol._context, ProtocolState.WAIT)

    protocol._context.pkt_received(Packet(dt.now(), "... " + rp_pkt))
    await assert_context_state(protocol._context, ProtocolState.IDLE)


async def _phase_11(protocol: QosProtocol) -> None:
    rq_cmd = RQ_CMD_0
    rp_pkt = RP_PKT_0

    await assert_context_state(protocol._context, ProtocolState.IDLE, max_sleep=0)

    await protocol.send_cmd(Command(rq_cmd))
    await assert_context_state(protocol._context, ProtocolState.ECHO)

    # Virtual RF will echo the sent cmd
    # await assert_context_state(protocol._context, ProtocolState.WAIT)
    await assert_protocol_state(protocol, ProtocolState.WAIT)
    await assert_context_state(protocol._context, ProtocolState.WAIT)

    protocol.pkt_received(Packet(dt.now(), "... " + rp_pkt))
    await assert_protocol_state(protocol, ProtocolState.IDLE)


async def _phase_12(protocol: QosProtocol) -> None:
    rq_cmd = RQ_CMD_1
    rp_pkt = RP_PKT_1

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

    await protocol.send_cmd(Command(rq_cmd))
    await assert_protocol_state(protocol, ProtocolState.ECHO)

    # Virtual RF will echo the sent cmd
    await assert_protocol_state(protocol, ProtocolState.WAIT)

    protocol.pkt_received(Packet(dt.now(), "... " + rp_pkt))
    # await assert_protocol_state(protocol, ProtocolState.IDLE)


# ######################################################################################


@protocol_decorator
async def _test_flow_00(protocol: QosProtocol):
    await assert_context_state(protocol._context, ProtocolState.IDLE, max_sleep=0)

    protocol._context.send_cmd(Command(II_CMD_0))
    protocol._context.pkt_received(Packet(dt.now(), "... " + II_CMD_0))

    protocol._context.send_cmd(Command(RQ_CMD_0))
    protocol._context.pkt_received(Packet(dt.now(), "... " + RQ_CMD_0))
    protocol._context.pkt_received(Packet(dt.now(), "... " + RP_PKT_0))

    await assert_context_state(protocol._context, ProtocolState.IDLE, max_sleep=0)


@protocol_decorator
async def _test_flow_01(protocol: QosProtocol):
    await _phase_01(protocol)


@protocol_decorator
async def _test_flow_02(protocol: QosProtocol):
    await _phase_01(protocol)
    await _phase_02(protocol)


@protocol_decorator
async def _test_flow_03(protocol: QosProtocol):
    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

    protocol._context.send_cmd(Command(RQ_CMD_0))
    await assert_protocol_state(protocol, ProtocolState.ECHO)

    protocol._context.pkt_received(Packet(dt.now(), "... " + RQ_CMD_0))
    await assert_protocol_state(protocol, ProtocolState.WAIT)

    try:
        protocol._context.send_cmd(Command(RQ_CMD_0))
    except RuntimeError:
        pass
    else:
        assert False


@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", 0)
@patch(
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_10(protocol: QosProtocol):
    await assert_context_state(protocol._context, ProtocolState.IDLE, max_sleep=0)

    await protocol.send_cmd(Command(II_CMD_0))  # no response expected

    await protocol.send_cmd(Command(RQ_CMD_0))
    await asyncio.sleep(0.005)  # TODO: figure out why this is needed
    protocol.pkt_received(Packet(dt.now(), "... " + RP_PKT_0))

    await assert_context_state(protocol._context, ProtocolState.IDLE, max_sleep=0)


@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", 0)
@patch(
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_11(protocol: QosProtocol):
    await _phase_11(protocol)


@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", 0)
@patch(
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_12(protocol: QosProtocol):
    await _phase_11(protocol)
    await _phase_12(protocol)


@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", 0)
@patch(
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@gateway_decorator
async def _test_flow_20(gwy: Gateway):
    await assert_context_state(gwy._protocol._context, ProtocolState.IDLE, max_sleep=0)

    await gwy.async_send_cmd(Command(II_CMD_0))  # no response expected
    await gwy.async_send_cmd(Command(RQ_CMD_0))

    await assert_context_state(gwy._protocol._context, ProtocolState.IDLE, max_sleep=0)


@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", 0)
@patch(
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@gateway_decorator
async def _test_flow_30(gwy: Gateway):
    await assert_context_state(gwy._protocol._context, ProtocolState.IDLE, max_sleep=0)

    gwy.send_cmd(Command(II_CMD_0))  # no response expected
    gwy.send_cmd(Command(RQ_CMD_0))

    await assert_context_state(gwy._protocol._context, ProtocolState.IDLE, max_sleep=0)


# ######################################################################################


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_00():
    """Check state change of inappropriate send during a RQ/RP pair."""
    await _test_flow_00()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_01():
    """Check state change of a faultless send using context primitives."""
    await _test_flow_01()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_02():
    """Check state change of two faultless sends using context primitives."""
    await _test_flow_02()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_03():
    """Check state change of inappropriate send during a RQ/RP pair."""
    await _test_flow_03()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_10():
    """Check state change of two sends using protocol methods."""
    await _test_flow_10()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_11():
    """Check state change of a faultless send using protocol methods."""
    await _test_flow_11()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_12():
    """Check state change of a faultless send using protocol methods."""
    await _test_flow_12()


@pytest.mark.xdist_group(name="virtual_rf")
async def out_test_flow_20():
    """Check state change of two sends using async gateway methods."""
    await _test_flow_20()


@pytest.mark.xdist_group(name="virtual_rf")
async def out_test_flow_30():
    """Check state change of two sends using non-async gateway methods."""
    await _test_flow_30()
