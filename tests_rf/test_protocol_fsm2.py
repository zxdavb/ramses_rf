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

from ramses_rf import Command, Packet
from ramses_rf.protocol.protocol import QosProtocol, protocol_factory
from ramses_rf.protocol.protocol_fsm import ProtocolState
from ramses_rf.protocol.transport import transport_factory

from .virtual_rf import VirtualRf

# from unittest.mock import patch

# import pytest
# import serial


DEFAULT_MAX_WAIT = 0.05  # #  to patch: ramses_rf.protocol.protocol
MIN_GAP_BETWEEN_WRITES = 0  # to patch: ramses_rf.protocol.transport

ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 1


# TODO: better handling than AttributeError for this...
# Command("RQ --- 18:111111 01:222222 --:------ 12B0 003 07")

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


def protocol_decorator(fnc):
    """Create a virtual RF network with a protocol stack."""

    @functools.wraps(fnc)
    async def test_wrapper(*args, **kwargs):
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
            await fnc(rf, protocol, *args, **kwargs)
        finally:
            transport.close()
            await rf.stop()

        # ensure protocol has quiesced, again
        await assert_protocol_state(protocol, ProtocolState.DEAD)

    return test_wrapper


# ######################################################################################


@protocol_decorator
async def _test_flow_100(
    _: VirtualRf, protocol: QosProtocol, min_sleeps: bool = None
) -> None:
    def assert_state(cmd, cmd_sends) -> None:  # TODO: consider removing
        assert protocol._context._cmd is cmd
        assert protocol._context.is_sending is bool(cmd)
        assert protocol._context._state.cmd is cmd
        assert protocol._context._state.cmd_sends == cmd_sends

    #
    # ##################################################################################
    # STEP 1A: Send an RQ cmd, then receive an RP pkt...
    await protocol._context.send_cmd(RQ_CMD_0)

    # STEP 1B: Expect/Receive the echo pkt...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
        assert_state(RQ_CMD_0, 1)
    protocol._context.pkt_received(RQ_PKT_0)

    # STEP 1C: Expect the rply pkt...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
        assert_state(RQ_CMD_0, 1)
    # protocol._context.pkt_received(RP_PKT_0)

    #
    #
    #

    # # STEP 1C: Receive the rply pkt...
    # if not min_sleeps:
    #     await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
    #     assert_state(RQ_CMD_0, 1)
    protocol._context.pkt_received(RP_PKT_0)

    # STEP 1X: Check state is now Idle...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        assert_state(None, 0)

    #
    # ##################################################################################
    # STEP 2A: Send an I cmd *twice* (no reply)...
    await protocol._context.send_cmd(II_CMD_0)  # sent 1st time

    # STEP 2B: Expect/Receive the echo of 1st pkt...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
        assert_state(II_CMD_0, 1)
    protocol._context.pkt_received(II_PKT_0)  # NOTE: see FIXME, below

    # STEP 2C: Expect the rply pkt...
    #
    #
    #
    #

    # NOTE: sending cmd a second time...
    await protocol._context.send_cmd(II_CMD_0)  # sent 2nd time
    # NOTE: sending cmd a second time...

    # STEP 2B: Expect/Receive the echo of 2bd pkt...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
        assert_state(II_CMD_0, 1)
    protocol._context.pkt_received(II_PKT_0)  # NOTE: see FIXME, below

    # STEP 2X: Check is now Idle (no reply expected)...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        assert_state(None, 0)

    #
    # ##################################################################################
    # STEP 3A: Send an RQ cmd *twice*, then receive an RP pkt...
    await protocol._context.send_cmd(RQ_CMD_1)  # sent 1st time

    # STEP 3B: Expect/Receive the echo pkt...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
        assert_state(RQ_CMD_1, 1)
    protocol._context.pkt_received(RQ_PKT_1)

    # STEP 3C: Expect (not Receive) the rply pkt...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
        assert_state(RQ_CMD_1, 1)
    # protocol._context.pkt_received(RP_PKT_1)  # NOTE: see FIXME below

    # NOTE: sending a second time...
    await protocol._context.send_cmd(RQ_CMD_1)  # sent 2nd time
    #

    # STEP 3C: Expect/Receive the rply pkt...
    # if not min_sleeps:
    #     await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
    #     assert_state(RQ_CMD_1, 2)  # FIXME: see NOTE above
    protocol._context.pkt_received(RP_PKT_1)

    # STEP 3X: Receive the rply and check is now Idle...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        assert_state(None, 0)


@protocol_decorator
async def _test_flow_200(
    rf: VirtualRf, protocol: QosProtocol, min_sleeps: bool = None
) -> None:
    def assert_state(cmd, cmd_sends) -> None:  # TODO: consider removing
        assert protocol._context._cmd is cmd
        assert protocol._context.is_sending is bool(cmd)
        assert protocol._context._state.cmd is cmd
        assert protocol._context._state.cmd_sends == cmd_sends

    #
    # ##################################################################################
    # STEP 1A: Send an RQ cmd, then receive an RP pkt...
    task = rf._loop.create_task(protocol.send_cmd(RQ_CMD_0))

    # STEP 1B: Expect/Receive the echo pkt...
    if False:
        if not min_sleeps:
            await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
            assert_state(RQ_CMD_0, 1)
        protocol.pkt_received(RQ_PKT_0)

    # STEP 1C: Expect the rply pkt...
    await assert_protocol_state(protocol, ProtocolState.RPLY)
    assert_state(RQ_CMD_0, 1)
    # protocol.pkt_received(RP_PKT_0)

    #
    #
    #

    # # STEP 1C: Receive the rply pkt...
    # if not min_sleeps:
    #     await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
    #     assert_state(RQ_CMD_0, 1)
    protocol.pkt_received(RP_PKT_0)
    # rf._loop.call_soon(protocol.pkt_received, RP_PKT_0)

    # STEP 1X: Check state is now Idle...
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        assert_state(None, 0)
    await task

    # # #
    # # # ##################################################################################
    # # # STEP 2A: Send an I cmd *twice* (no reply)...
    # # task = rf._loop.create_task(protocol.send_cmd(II_CMD_0))  # sent 1st time

    # # # STEP 2B: Expect/Receive the echo of 1st pkt...
    # # if False:
    # #     if not min_sleeps:
    # #         await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
    # #         assert_state(II_CMD_0, 1)
    # #     protocol.pkt_received(II_PKT_0)  # NOTE: see FIXME, below

    # # # STEP 2C: Expect the rply pkt...
    # # #
    # # #
    # # #
    # # #

    # # # NOTE: sending cmd a second time...
    # # task = rf._loop.create_task(protocol.send_cmd(II_CMD_0))  # sent 2nd time
    # # # NOTE: sending cmd a second time...

    # # # STEP 2B: Expect/Receive the echo of 2bd pkt...
    # # if False:
    # #     if not min_sleeps:
    # #         await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
    # #         assert_state(II_CMD_0, 1)
    # #     protocol.pkt_received(II_PKT_0)  # NOTE: see FIXME, below

    # # # STEP 2X: Check is now Idle (no reply expected)...
    # # if not min_sleeps:
    # #     await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    # #     assert_state(None, 0)

    # # #
    # # # ##################################################################################
    # # # STEP 3A: Send an RQ cmd *twice*, then receive an RP pkt...
    # # task = rf._loop.create_task(protocol.send_cmd(RQ_CMD_1))  # sent 1st time

    # # # STEP 3B: Expect/Receive the echo pkt...
    # # if False:
    # #     if not min_sleeps:
    # #         await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
    # #         assert_state(RQ_CMD_1, 1)
    # #     protocol.pkt_received(RQ_PKT_1)

    # # # STEP 3C: Expect (not Receive) the rply pkt...
    # # if not min_sleeps:
    # #     await assert_protocol_state(protocol, ProtocolState.RPLY)
    # #     assert_state(RQ_CMD_1, 1)
    # # # protocol.pkt_received(RP_PKT_1)  # NOTE: see FIXME below

    # # # NOTE: sending a second time...
    # # task = rf._loop.create_task(protocol.send_cmd(RQ_CMD_1))  # sent 2nd time
    # # #

    # # # STEP 3C: Expect/Receive the rply pkt...
    # # # if not min_sleeps:
    # # #     await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
    # # #     assert_state(RQ_CMD_1, 2)  # FIXME: see NOTE above
    # # protocol.pkt_received(RP_PKT_1)

    # # # STEP 3X: Receive the rply and check is now Idle...
    # # if not min_sleeps:
    # #     await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    # #     assert_state(None, 0)


# ######################################################################################


# pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_100() -> None:
    """Check state change of RQ/I/RQ cmds using context primitives."""
    await _test_flow_100()


# pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_101() -> None:
    """Check state change of RQ/I/RQ cmds using context primitives."""
    await _test_flow_100(min_sleeps=False)


# pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_200() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""
    await _test_flow_200()


# pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_201() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""
    await _test_flow_200(min_sleeps=False)
