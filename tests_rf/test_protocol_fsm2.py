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
from unittest.mock import patch

import pytest
import pytest_asyncio
import serial
import serial_asyncio

from ramses_rf import Command, Packet
from ramses_rf.protocol.protocol import QosProtocol, protocol_factory
from ramses_rf.protocol.protocol_fsm import ProtocolState
from ramses_rf.protocol.transport import transport_factory

from .virtual_rf import VirtualRf, stifle_impersonation_alert

DEFAULT_MAX_RETRIES = 0  # #     patch ramses_rf.protocol.protocol (was 3)
DEFAULT_WAIT_TIMEOUT = 0.05  # # patch ramses_rf.protocol.protocol_fsm (was 3)
MAINTAIN_STATE_CHAIN = True  # # patch ramses_rf.protocol.protocol_fsm (was False)
MIN_GAP_BETWEEN_WRITES = 0.05  # patch ramses_rf.protocol.protocol (was 0.2)


ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 0.5


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
        if isinstance(protocol._context.state, expected_state):
            break
    assert isinstance(protocol._context.state, expected_state)


def protocol_decorator(fnc):
    """Create a virtual RF network with a protocol stack."""

    @functools.wraps(fnc)
    async def test_wrapper(*args, **kwargs):
        def _msg_handler(msg) -> None:
            pass

        rf = VirtualRf(2, start=True)

        protocol = protocol_factory(kwargs.pop("msg_handler", _msg_handler))
        await assert_protocol_state(protocol, ProtocolState.DEAD, max_sleep=0)

        transport: serial_asyncio.SerialTransport = transport_factory(
            protocol,
            port_name=rf.ports[0],
            port_config=kwargs.pop("port_config", {}),
            enforce_include_list=kwargs.pop("enforce_include_list", False),
            exclude_list=kwargs.pop("exclude_list", {}),
            include_list=kwargs.pop("include_list", {}),
        )
        transport._extra["virtual_rf"] = rf

        # ensure protocol has quiesced
        await assert_protocol_ready(protocol)
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)

        try:
            await fnc(rf, protocol, *args, **kwargs)
        except serial.SerialException as exc:
            transport._close(exc=exc)
            raise
        except (AssertionError, asyncio.InvalidStateError, asyncio.TimeoutError):
            transport.close()
            raise
        else:
            transport.close()
        finally:
            await rf.stop()

        # ensure protocol has quiesced, again
        await assert_protocol_state(protocol, ProtocolState.DEAD, max_sleep=0)

    return test_wrapper


def _read_ready(self) -> None:  # HACK: resolves an issue with Virtual RF
    # data to self._bytes_received() instead of self._protocol.data_received()
    try:
        data: bytes = self._serial.read(self._max_read_size)
    except serial.SerialException as e:
        if e.args and e.args[0].startswith("device reports readiness to read but"):
            data = b""
            # _LOGGER.warning("      *** Device disconnected/multiple access on port")
        else:
            self._close(exc=e)
            return

    if data:
        self._bytes_received(data)  # was: self._protocol.pkt_received(data)


# ######################################################################################


@protocol_decorator
async def _test_flow_10x(
    _: VirtualRf, protocol: QosProtocol, min_sleeps: bool = None
) -> None:
    def assert_state_temp(cmd, cmd_sends) -> None:  # TODO: consider removing
        assert protocol._context._cmd is cmd
        assert protocol._context.is_sending is bool(cmd)
        assert protocol._context.state.cmd is cmd
        assert protocol._context.state.cmd_sends == cmd_sends

    # ser = serial.Serial(rf.ports[1])

    # STEP 1A: Send an RQ cmd, then receive the corresponding RP pkt...
    await protocol._context.send_cmd(RQ_CMD_0)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
        assert_state_temp(RQ_CMD_0, 1)

    protocol._context.pkt_received(RQ_PKT_0)  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
        assert_state_temp(RQ_CMD_0, 1)

    protocol._context.pkt_received(RP_PKT_0)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        assert_state_temp(None, 0)

    # gather

    # STEP 2A: Send an I cmd (no reply) *twice*...
    await protocol._context.send_cmd(II_CMD_0)  # sent 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
        assert_state_temp(II_CMD_0, 1)

    protocol._context.pkt_received(II_PKT_0)  # NOTE: FIXME, below  # receive the echo
    # if not...

    await protocol._context.send_cmd(II_CMD_0)  # sent 2nd time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
        assert_state_temp(II_CMD_0, 1)

    protocol._context.pkt_received(II_PKT_0)  # NOTE: FIXME  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        assert_state_temp(None, 0)

    # gather

    # STEP 3A: Send an RQ cmd *twice*, then receive the corresponding RP pkt...
    await protocol._context.send_cmd(RQ_CMD_1)  # sent 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=0)
        assert_state_temp(RQ_CMD_1, 1)

    protocol._context.pkt_received(RQ_PKT_1)  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
        assert_state_temp(RQ_CMD_1, 1)

    await protocol._context.send_cmd(RQ_CMD_1)  # sent 2nd time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
        assert_state_temp(RQ_CMD_1, 2)  # FIXME: see NOTE above

    protocol._context.pkt_received(RQ_PKT_1)  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
        assert_state_temp(RQ_CMD_1, 2)

    protocol._context.pkt_received(RP_PKT_1)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        assert_state_temp(None, 0)

    # gather
    await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)


@patch("ramses_rf.protocol.protocol.DEFAULT_MAX_RETRIES", DEFAULT_MAX_RETRIES)
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch("ramses_rf.protocol.protocol_fsm.MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_20x(
    rf: VirtualRf, protocol: QosProtocol, min_sleeps: bool = None
) -> None:
    PKT_RECEIVED_METHOD = 0

    async def async_send_cmds(cmd: Command, num_sends: int = 1) -> list[asyncio.Task]:
        await assert_protocol_state(protocol, ProtocolState.IDLE)
        assert_state_temp(None, 0)

        if num_sends <= 0:
            return
        tasks = []
        for idx in range(1, num_sends + 1):
            tasks += [rf._loop.create_task(protocol.send_cmd(cmd), name=f"send_{idx}")]

            if num_sends <= DEFAULT_MAX_RETRIES + 1:
                state = ProtocolState.RPLY if cmd.rx_header else ProtocolState.IDLE
            else:
                state = ProtocolState.IDLE

            await assert_protocol_state(protocol, state)
            if state == ProtocolState.IDLE:
                assert_state_temp(None, 0)
            else:
                assert_state_temp(cmd, idx)

        return tasks

    async def async_pkt_received(
        pkt: Packet, method: int = PKT_RECEIVED_METHOD
    ) -> None:
        # await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        # assert_state_temp(None, 0)

        if method == 0:
            return protocol.pkt_received(pkt)
        elif method == 1:
            return rf._loop.call_soon(protocol.pkt_received, pkt)

        else:
            frame = bytes(str(pkt).encode("ascii")) + b"\r\n"

            if method == 2:
                ser.write(frame)
            elif method == 3:
                rf._loop.call_soon(ser.write, frame)
            else:
                rf._loop.call_later(0.001, ser.write, frame)

        # await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        # assert_state_temp(None, 0)

    def assert_state_temp(cmd, cmd_sends) -> None:  # TODO: consider removing
        assert protocol._context._cmd is cmd
        assert protocol._context.is_sending is bool(cmd)
        assert protocol._context.state.cmd is cmd
        assert protocol._context.state.cmd_sends == cmd_sends

    ser = serial.Serial(rf.ports[1])

    # STEP 1A: Send an RQ cmd, then receive the corresponding RP pkt...
    tasks = await async_send_cmds(RQ_CMD_0, num_sends=1)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
        assert_state_temp(RQ_CMD_0, 1)

    # the echo is sent by Virtual RF...
    # if not min_sleeps:
    #     await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=0)
    #     assert_state_temp(RQ_CMD_0, 1)

    await async_pkt_received(RP_PKT_0)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
        assert_state_temp(None, 0)

    await asyncio.gather(*tasks)

    # STEP 2A: Send an I cmd (no reply) *twice*...
    tasks = await async_send_cmds(II_CMD_0, num_sends=1)  # send * 2
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE)  # , max_sleep=0)
        assert_state_temp(None, 0)

    # the echo is sent by Virtual RF...
    # if not..

    tasks += await async_send_cmds(II_CMD_0, num_sends=1)  # send * 2
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE)  # , max_sleep=0)
        assert_state_temp(None, 0)

    # the echo is sent by Virtual RF...
    # if not..
    #
    #

    await asyncio.gather(*tasks)  # no reply pkt expected

    # STEP 3A: Send an RQ cmd *twice*, then receive the corresponding RP pkt...
    tasks = await async_send_cmds(RQ_CMD_1, num_sends=1)  # send 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY)  # , max_sleep=0)
        assert_state_temp(RQ_CMD_1, 1)

    # the echo is sent by Virtual RF...
    # if not..
    #
    #

    tasks += await async_send_cmds(RQ_CMD_1, num_sends=1)  # send 2nd time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY)  # , max_sleep=0)
        assert_state_temp(RQ_CMD_1, 1)

    # the echo is sent by Virtual RF...
    # if not..
    #
    #

    await async_pkt_received(RP_PKT_1)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE)  # , max_sleep=0)
        assert_state_temp(None, 0)

    await asyncio.gather(*tasks)
    await assert_protocol_state(protocol, ProtocolState.IDLE)  # , max_sleep=0)


# ######################################################################################


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_100() -> None:
    """Check state change of RQ/I/RQ cmds using context primitives."""
    await _test_flow_10x()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_101() -> None:
    """Check state change of RQ/I/RQ cmds using context primitives."""
    await _test_flow_10x(min_sleeps=False)


@pytest.mark.xdist_group(name="virtual_rf")
@patch("ramses_rf.protocol.transport._PortTransport._read_ready", _read_ready)
async def test_flow_200() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""
    await _test_flow_20x()


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_201() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""
    await _test_flow_20x(min_sleeps=False)


@pytest_asyncio.fixture
async def async_benchmark(benchmark, event_loop: asyncio.AbstractEventLoop):
    def _wrapper(func, *args, **kwargs):
        if asyncio.iscoroutinefunction(func):

            @benchmark
            def _():
                return event_loop.run_until_complete(func(*args, **kwargs))

        else:
            benchmark(func, *args, **kwargs)

    return _wrapper


# @pytest.mark.xdist_group(name="virtual_rf")
# def test_benchmark_200(async_benchmark):
#     async_benchmark(_test_flow_20x)


# @pytest.mark.xdist_group(name="virtual_rf")
# def test_benchmark_100(async_benchmark):
#     async_benchmark(_test_flow_10x)
