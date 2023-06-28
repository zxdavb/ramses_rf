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
import serial

from ramses_rf import Command, Gateway, Packet
from ramses_rf.bind_state import State
from ramses_rf.device.base import Fakeable
from ramses_rf.protocol.protocol import QosProtocol, protocol_factory
from ramses_rf.protocol.protocol_fsm import ProtocolState
from ramses_rf.protocol.transport import transport_factory

from .virtual_rf import VirtualRf, stifle_impersonation_alert

_DeviceStateT = TypeVar("_DeviceStateT", bound=State)
_FakedDeviceT = TypeVar("_FakedDeviceT", bound=Fakeable)


DEFAULT_MAX_WAIT = 0.05  # #  to patch: ramses_rf.protocol.protocol
MIN_GAP_BETWEEN_WRITES = 0  # to patch: ramses_rf.protocol.transport

ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 1


# Command("RQ --- 18:111111 01:222222 --:------ 12B0 003 07")  # TODO: better handling than AttributeError

II_CMD_STR_0 = " I --- 01:006056 --:------ 01:006056 1F09 003 0005C8"
II_CMD_0 = Command(II_CMD_STR_0)
II_PKT_0 = Packet(dt.now(), f"... {II_CMD_STR_0}")

# TIP: using 18:000730 as the source will prevent impersonation alerts

RQ_CMD_STR_0 = "RQ --- 18:000730 01:222222 --:------ 12B0 001 00"
RP_CMD_STR_0 = "RP --- 01:222222 18:000730 --:------ 12B0 003 000000"

RQ_CMD_0 = Command(RQ_CMD_STR_0)
RQ_PKT_0 = Packet(dt.now(), f"... {RQ_CMD_STR_0}")
RP_PKT_0 = Packet(dt.now(), f"... {RP_CMD_STR_0}")

RQ_CMD_STR_1 = "RQ --- 18:000730 01:222222 --:------ 12B0 001 01"
RP_CMD_STR_1 = "RP --- 01:222222 18:000730 --:------ 12B0 003 010000"

RQ_CMD_1 = Command(RQ_CMD_STR_1)
RQ_PKT_1 = Packet(dt.now(), f"... {RQ_CMD_STR_1}")
RP_PKT_1 = Packet(dt.now(), f"... {RP_CMD_STR_1}")


async def assert_protocol_ready(
    protocol: QosProtocol, max_sleep: int = DEFAULT_MAX_SLEEP
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if protocol._this_msg is not None:
            break
    assert protocol._this_msg and protocol._this_msg.code == "7FFF"


async def assert_protocol_state(
    protocol: QosProtocol,
    expected_state: type[ProtocolState],
    max_sleep: int = DEFAULT_MAX_SLEEP,
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if isinstance(protocol._context._state, expected_state):
            break
    assert isinstance(protocol._context._state, expected_state)


def gateway_decorator(fnc):
    """Create a virtual RF network with a gateway."""

    @functools.wraps(fnc)
    async def test_wrapper():
        rf = VirtualRf(2)
        rf.set_gateway(rf.ports[0], "18:000730")

        gwy = Gateway(rf.ports[0])
        await gwy.start()

        # ensure protocol has quiesced
        await assert_protocol_ready(gwy._protocol)
        await assert_protocol_state(gwy._protocol, ProtocolState.IDLE)

        try:
            await fnc(rf, gwy)
        finally:
            gwy._transport.close()  # await gwy.stop()
            await rf.stop()

    return test_wrapper


def protocol_decorator(fnc):
    """Create a virtual RF network with a protocol stack."""

    @functools.wraps(fnc)
    async def test_wrapper():
        def msg_handler(msg) -> None:
            pass

        rf = VirtualRf(2, start=True)

        protocol = protocol_factory(msg_handler)
        await assert_protocol_state(protocol, ProtocolState.DEAD, max_sleep=0)

        transport: asyncio.Transport = transport_factory(
            protocol,
            port_name=rf.ports[0],
            port_config={},
            enforce_include_list=False,
            exclude_list={},
            include_list={},
        )

        # ensure protocol has quiesced
        await assert_protocol_ready(protocol)
        await assert_protocol_state(protocol, ProtocolState.IDLE)

        try:
            await fnc(rf, protocol)
        finally:
            transport.close()
            await rf.stop()

    return test_wrapper


async def _send_rq_cmd_via_context(
    protocol: QosProtocol,
    rq_cmd: Command,
    rq_pkt: Packet,
    rp_pkt: Packet,
    disable_sleeps: bool = None,
) -> None:
    """Using context primitives, send an RQ, and wait for the corresponding RP."""

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    assert protocol._context._cmd is None

    await protocol._context.send_cmd(rq_cmd)
    if not disable_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
        assert protocol._context._cmd == rq_cmd

    protocol._context.pkt_received(rq_pkt)
    if not disable_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
        assert protocol._context._cmd == rq_cmd

    protocol._context.pkt_received(rp_pkt)
    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    assert protocol._context._cmd is None


async def _send_rq_cmd_via_protocol(
    protocol: QosProtocol, rq_cmd: Command, rp_pkt: Packet
) -> None:
    """Using protocol methods, send and RQ, and wait for the corresponding RP."""

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

    await protocol.send_cmd(rq_cmd)
    await assert_protocol_state(protocol, ProtocolState.ECHO)

    # Virtual RF will echo the sent cmd  # protocol.pkt_received(rq_pkt)
    await assert_protocol_state(protocol, ProtocolState.RPLY)

    protocol.pkt_received(rp_pkt)
    await assert_protocol_state(protocol, ProtocolState.IDLE)


async def _test_flow_via_context(
    _: VirtualRf, protocol: QosProtocol, disable_sleeps: bool = None
) -> None:
    """Send two cmds via context primitives."""

    # Step 0: Setup, and check initial conditions
    # ser = serial.Serial(rf.ports[1])  # not needed

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

    # Step 1: Send a command that doesn't invoke a response (only an echo)
    await protocol._context.send_cmd(II_CMD_0)  # no response expected...
    protocol._context.pkt_received(II_PKT_0)  # ...but still need an echo

    if not disable_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

    # Step 2A: Send a command that invokes a response
    await protocol._context.send_cmd(RQ_CMD_0)
    protocol._context.pkt_received(RQ_PKT_0)

    if not disable_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)

    # Step 2B: Receive the response (normally: protocol.pkt_received(RP_PKT_0))
    protocol._context.pkt_received(RP_PKT_0)
    #
    #

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)


async def _test_flow_via_protocol(
    rf: VirtualRf, protocol: QosProtocol, disable_sleeps: bool = None
) -> None:
    """Send two cmds via protocol methods, with responses from another device."""

    # Step 0: Setup, and check initial conditions
    ser = serial.Serial(rf.ports[1])

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

    # Step 1: Send a command that doesn't invoke a response (only an echo)
    await protocol.send_cmd(II_CMD_0)  # no response expected...
    # protocol.pkt_received(II_PKT_0)  # not needed: is echoed by virtual RF

    if not disable_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE)

    # Step 2A: Send a command that invokes a response
    await protocol.send_cmd(RQ_CMD_0)
    # await protocol.send_cmd(RQ_CMD_0)  # not needed: is echoed by virtual RF

    if not disable_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY)

    # Step 2B: Receive the response (normally: protocol.pkt_received(RP_PKT_0))
    asyncio.get_running_loop().call_later(  # NOTE: not loop.call_soon
        0.001, ser.write, bytes(RP_CMD_STR_0.encode("ascii")) + b"\r\n"
    )  # or simply: ser.write(bytes(RP_CMD_STR_0.encode("ascii")) + b"\r\n")

    await assert_protocol_state(protocol, ProtocolState.IDLE)


# ######################################################################################


@protocol_decorator
async def _test_flow_00(rf: VirtualRf, protocol: QosProtocol) -> None:
    """Send two cmds via context primitives."""
    await _test_flow_via_context(rf, protocol)


@protocol_decorator
async def _test_flow_01(rf: VirtualRf, protocol: QosProtocol) -> None:
    """Send two cmds via context primitives without intervening asyncio.sleep()s."""
    await _test_flow_via_context(rf, protocol, disable_sleeps=True)


@protocol_decorator
async def _test_flow_02(_: VirtualRf, protocol: QosProtocol) -> None:
    """Send two RQs back-to-back via context primitives."""
    await _send_rq_cmd_via_context(protocol, RQ_CMD_0, RQ_PKT_0, RP_PKT_0)
    await _send_rq_cmd_via_context(protocol, RQ_CMD_1, RQ_PKT_1, RP_PKT_1)


@protocol_decorator
async def _test_flow_03(_: VirtualRf, protocol: QosProtocol) -> None:
    """Send two RQs back-to-back via context primitives."""
    await _send_rq_cmd_via_context(
        protocol, RQ_CMD_0, RQ_PKT_0, RP_PKT_0, disable_sleeps=True
    )
    await _send_rq_cmd_via_context(
        protocol, RQ_CMD_1, RQ_PKT_1, RP_PKT_1, disable_sleeps=True
    )


@patch("ramses_rf.protocol.protocol_fsm.DEFAULT_WAIT_TIMEOUT", DEFAULT_MAX_WAIT)
@protocol_decorator
async def _test_flow_05(_: VirtualRf, protocol: QosProtocol) -> None:
    """A 2nd RQ is sent before 1st RQ receives its reply."""

    def assert_state(cmd, cmd_sends) -> None:  # TODO: can remove, later
        assert protocol._context._cmd is cmd
        assert protocol._context.is_sending is bool(cmd)
        assert protocol._context._state.cmd is cmd
        assert protocol._context._state.cmd_sends == cmd_sends

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    assert_state(None, 0)

    await protocol._context.send_cmd(RQ_CMD_0)
    await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
    assert_state(RQ_CMD_0, 1)

    protocol._context.pkt_received(RQ_PKT_0)
    await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
    assert_state(RQ_CMD_0, 1)

    asyncio.get_running_loop().create_task(
        protocol._context.send_cmd(RQ_CMD_0)  # expecing RP, but re-transmit of RQ
    )
    await assert_protocol_state(protocol, ProtocolState.RPLY)
    assert_state(RQ_CMD_0, 2)

    asyncio.get_running_loop().create_task(
        protocol._context.send_cmd(RQ_CMD_1)  # got different RQ instead of RP
    )

    protocol._context.pkt_received(RP_PKT_0)
    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    assert_state(None, 0)

    await assert_protocol_state(protocol, ProtocolState.ECHO)
    assert_state(RQ_CMD_1, 1)

    protocol._context.pkt_received(RQ_PKT_1)  # cmd was already sent, above
    await assert_protocol_state(protocol, ProtocolState.RPLY)
    assert_state(RQ_CMD_1, 1)

    protocol._context.pkt_received(RP_PKT_1)  # cmd was already sent, above
    await assert_protocol_state(protocol, ProtocolState.IDLE)
    assert_state(None, 0)


@patch("ramses_rf.protocol.protocol.DEFAULT_MAX_WAIT", DEFAULT_MAX_WAIT)
@protocol_decorator
async def _test_flow_07(_: VirtualRf, protocol: QosProtocol) -> None:
    """Send a second RQ before the first gets its RP via context primitives."""

    # Step 0: Setup, and check initial conditions
    # ser = serial.Serial(rf.ports[1])  # not needed

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

    # # Step 1: Send a command that doesn't invoke a response (only an echo)
    # await protocol._context.send_cmd(II_CMD_0)  # no response expected...
    # protocol._context.pkt_received(II_PKT_0)  # ...but still need an echo

    # if not disable_sleeps:
    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

    # Step 2: Send a command that invokes a response
    await protocol._context.send_cmd(RQ_CMD_0)
    await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)

    # Step 3: Receive the response (normally: protocol.pkt_received(RP_PKT_0))
    protocol._context.pkt_received(RQ_PKT_0)
    await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)

    try:
        await protocol._context.send_cmd(RQ_CMD_1)
    except RuntimeError:
        pass
    else:
        raise False

    await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)


# @patch("ramses_rf.protocol.protocol.DEFAULT_MAX_WAIT", DEFAULT_MAX_WAIT)
@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_10(rf: VirtualRf, protocol: QosProtocol) -> None:
    """Send two cmds via protocol methods."""
    await _test_flow_via_protocol(rf, protocol)


@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_11(rf: VirtualRf, protocol: QosProtocol) -> None:
    """Send two cmds via protocol methods without intervening asyncio.sleep()s."""
    await _test_flow_via_protocol(rf, protocol, disable_sleeps=True)


@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_12(_: VirtualRf, protocol: QosProtocol) -> None:
    """Send two RQs back-to-back via protocol methods."""
    await _send_rq_cmd_via_protocol(protocol, RQ_CMD_0, RP_PKT_0)
    await _send_rq_cmd_via_protocol(protocol, RQ_CMD_1, RP_PKT_1)


# @patch("ramses_rf.protocol.protocol.DEFAULT_MAX_WAIT", DEFAULT_MAX_WAIT)
@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_13(rf: VirtualRf, protocol: QosProtocol) -> None:
    """Send a second RQ before the first gets its RP via protocol methods."""

    # Step 0: Setup, and check initial conditions
    # ser = serial.Serial(rf.ports[1])

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    assert protocol._context._state.cmd is None

    # # Step 1A: Send a command that doesn't invoke a response (only an echo)
    # await protocol.send_cmd(II_CMD_0)  # no response expected
    # # protocol.pkt_received(II_PKT_0)  # not needed as will be echoed by virtual RF

    # # if ...
    # await assert_protocol_state(protocol, ProtocolState.IDLE)
    # assert protocol._context._state.cmd is None

    # Step 2A: Send a command that invokes a response
    await protocol.send_cmd(RQ_CMD_0)
    # if ...
    await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
    assert protocol._context._state.cmd == RQ_CMD_0

    # protocol.pkt_received(RQ_PKT_0)  # NOTE: not needed as will be echoed by virtual RF
    # if ...
    await assert_protocol_state(protocol, ProtocolState.RPLY)
    assert protocol._context._state.cmd == RQ_CMD_0

    # Step 3A: Send (queue) a different command that invokes a response
    try:  # expectation is that prev RQ should finish, or timeout before this timesout
        await protocol.send_cmd(RQ_CMD_1)  # expecting RP, but got a different RQ
    except asyncio.TimeoutError:
        pass
    else:
        raise False

    # if ...
    await assert_protocol_state(protocol, ProtocolState.RPLY)
    assert protocol._context._state.cmd == RQ_CMD_0

    # Step 2B: Receive the 1st response
    protocol.pkt_received(RP_PKT_0)  # FIXME: doesn't queue?
    #
    #

    # # if ...
    await assert_protocol_state(protocol, ProtocolState.RPLY)
    assert protocol._context._state.cmd == RP_PKT_1

    # Step 3B: Receive the 2nd response
    protocol.pkt_received(RP_PKT_1)
    #
    #

    # Step 4: Finished!
    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    assert protocol._context._state.cmd is None


# @patch("ramses_rf.protocol.protocol.DEFAULT_MAX_WAIT", DEFAULT_MAX_WAIT)
@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_17(
    rf: VirtualRf, protocol: QosProtocol, disable_sleeps: bool = False
) -> None:
    """Send a second RQ before the first gets its RP via protocol methods."""

    # Step 0: Setup, and check initial conditions
    ser = serial.Serial(rf.ports[1])  # not needed

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    assert protocol._context._state.cmd is None

    # Step 1A: Send a command that doesn't invoke a response (only an echo)
    await protocol.send_cmd(
        II_CMD_0
    )  # asyncio.create_task()???  # no response expected
    # protocol.pkt_received(II_PKT_0)  # not needed: is echoed by virtual RF

    # if...
    await assert_protocol_state(protocol, ProtocolState.IDLE)
    assert protocol._context._state.cmd is None

    # Step 2A: Send a command that invokes a response
    asyncio.create_task(protocol.send_cmd(RQ_CMD_0))
    # if ...
    await assert_protocol_state(protocol, ProtocolState.ECHO)
    assert protocol._context._state.cmd == RQ_CMD_0

    # protocol.pkt_received(RQ_PKT_0)  # not needed as will be echoed by virtual RF
    # if ...
    await assert_protocol_state(protocol, ProtocolState.RPLY)
    assert protocol._context._state.cmd == RQ_CMD_0

    # Step 3A: Send (queue) a different command that invokes a response
    try:
        await protocol.send_cmd(RQ_CMD_1)  # expecting RP, but got a different RQ
    except asyncio.TimeoutError:
        pass
    else:
        raise False

    # if ...
    await assert_protocol_state(protocol, ProtocolState.RPLY)
    assert protocol._context._state.cmd == RQ_CMD_0

    # Step 2B: Receive the 1st response (normally: protocol.pkt_received(RP_PKT_0))
    asyncio.get_running_loop().call_soon(
        ser.write, bytes(RP_CMD_STR_0.encode("ascii")) + b"\r\n"
    )  # protocol.pkt_received(RP_PKT_0)

    # # if ...
    # await assert_protocol_state(protocol, ProtocolState.WAIT, max_sleep=0)
    # assert protocol._context._state.cmd == RQ_CMD_0

    # Step 3B: Receive the 2nd response
    asyncio.get_running_loop().call_soon(
        ser.write, bytes(RP_CMD_STR_1.encode("ascii")) + b"\r\n"
    )  # protocol.pkt_received(RP_PKT_0)

    # Step 4: Finished!
    await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
    # assert protocol._context._state.cmd is None


# @patch("ramses_rf.protocol.protocol.DEFAULT_MAX_WAIT", DEFAULT_MAX_WAIT)
@patch("ramses_rf.protocol.transport.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_19(
    rf: VirtualRf, protocol: QosProtocol, disable_sleeps: bool = False
) -> None:
    """Send three commands before the second gets its response, via protocol methods."""

    # Step 0: Setup, and check initial conditions
    ser = serial.Serial(rf.ports[1])

    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    assert protocol._context._state.cmd is None

    # Step 1A: Send (queue) a command that doesn't invoke a response (only an echo)
    # Step 2A: Send (queue) a command that invokes a response
    # Step 3A: Send (queue) a different command that invokes a response
    asyncio.gather(
        protocol.send_cmd(II_CMD_0),  # no response expected...
        protocol.send_cmd(RQ_CMD_0),
        protocol.send_cmd(RQ_CMD_1),
    )

    if not disable_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY)
        assert protocol._context._state.cmd == RQ_CMD_0
    # await asyncio.sleep(0.05)

    # Step 2B: Receive the 1st response (normally: protocol.pkt_received(RP_PKT_0))
    # protocol.pkt_received(RP_PKT_0)
    asyncio.get_running_loop().call_soon(
        ser.write, bytes(RP_CMD_STR_0.encode("ascii")) + b"\r\n"
    )

    if not disable_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY)
        # assert protocol._context._state.cmd == RQ_CMD_1
    # await asyncio.sleep(0.05)

    # Step 3B: Receive the 2nd response
    # protocol.pkt_received(RP_PKT_1)
    asyncio.get_running_loop().call_soon(
        ser.write, bytes(RP_CMD_STR_1.encode("ascii")) + b"\r\n"
    )

    # Step 4: Finished!
    await assert_protocol_state(protocol, ProtocolState.IDLE)
    assert protocol._context._state.cmd is None


# ######################################################################################


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_00() -> None:
    """Check state change of two sends using context primitives."""
    await _test_flow_00()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_01() -> None:
    """Check state change of a faultless send using context primitives."""
    await _test_flow_01()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_02() -> None:
    """Check state change of two faultless sends using context primitives."""
    await _test_flow_02()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_03() -> None:
    """Check state change of inappropriate send during a RQ/RP pair."""
    await _test_flow_03()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_05() -> None:
    """Check state change of inappropriate send during a RQ/RP pair."""
    await _test_flow_05()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_07() -> None:
    """Check context sending 2nd RQ before first RQ has finished being sent."""
    await _test_flow_07()


@pytest.mark.xdist_group(name="virtual_rf")
async def OUT_test_flow_10() -> None:
    """Check state change of two sends using protocol methods."""
    await _test_flow_10()


@pytest.mark.xdist_group(name="virtual_rf")
async def OUT_test_flow_11() -> None:
    """Check state change of a faultless send using protocol methods."""
    await _test_flow_11()


@pytest.mark.xdist_group(name="virtual_rf")
async def OUT_test_flow_12() -> None:
    """Check state change of a faultless send using protocol methods."""
    await _test_flow_12()


@pytest.mark.xdist_group(name="virtual_rf")
async def OUT_test_flow_13() -> None:
    """Check state change of a faultless send using protocol methods."""
    await _test_flow_13()


@pytest.mark.xdist_group(name="virtual_rf")
async def OUT_test_flow_17() -> None:
    """Check protocol sending 2nd RQ before first RQ has finished being sent."""
    await _test_flow_17()


@pytest.mark.xdist_group(name="virtual_rf")
async def OUT_test_flow_19() -> None:
    """Check protocol sending 2nd RQ before first RQ has finished being sent."""
    await _test_flow_19()
