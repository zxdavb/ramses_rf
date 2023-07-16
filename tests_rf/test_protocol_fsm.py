#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol with a virtual RF

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
from ramses_rf.protocol.protocol_fsm import _DEFAULT_WAIT_TIMEOUT, ProtocolState
from ramses_rf.protocol.transport import transport_factory

from .virtual_rf import VirtualRf, stifle_impersonation_alert

DEFAULT_MAX_RETRIES = 0  # #     patch ramses_rf.protocol.protocol
DEFAULT_WAIT_TIMEOUT = 0.05  # # patch ramses_rf.protocol.protocol_fsm
MAINTAIN_STATE_CHAIN = True  # # patch ramses_rf.protocol.protocol_fsm
MIN_GAP_BETWEEN_WRITES = 0  # #  patch ramses_rf.protocol.protocol


ASSERT_CYCLE_TIME = 0.0005  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 0.1


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


def assert_protocol_state_detail(
    protocol: QosProtocol, cmd: Command, cmd_sends: int
) -> None:
    assert cmd is None or protocol._context._is_active_cmd(cmd)  # duplicate test
    assert protocol._context.state.cmd is cmd  # duplicate of above
    assert protocol._context.state.cmd_sends == cmd_sends
    assert bool(cmd) is isinstance(
        protocol._context.state, (ProtocolState.ECHO, ProtocolState.RPLY)
    )


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
        transport._extra["virtual_rf"] = rf  # injected to aid any debugging

        try:
            await assert_protocol_ready(protocol)  # ensure protocol has quiesced
            await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
            await fnc(rf, protocol, *args, **kwargs)
            await assert_protocol_state(protocol, ProtocolState.IDLE)
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

        await assert_protocol_state(protocol, ProtocolState.DEAD, max_sleep=0)

    return test_wrapper


def _read_ready(self) -> None:  # HACK: resolves an issue with Virtual RF
    # data to self._bytes_received() instead of self._protocol.data_received()
    try:
        data: bytes = self._serial.read(self._max_read_size)
    except serial.SerialException as e:
        if e.args and e.args[0].startswith("device reports readiness to read but"):
            data = b""
            # _LOGGER.warning("Device disconnected/multiple access on port")
        else:
            self._close(exc=e)
            return

    if data:
        self._bytes_received(data)  # was: self._protocol.pkt_received(data)


async def async_pkt_received(
    protocol: QosProtocol,
    pkt: Packet,
    method: int = 0,
    ser: None | serial.Serial = None,
) -> None:
    # await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    # assert_state_temp(protocol, None, 0)

    if method == 0:
        return protocol.pkt_received(pkt)
    elif method == 1:
        return protocol._loop.call_soon(protocol.pkt_received, pkt)

    else:
        assert ser is not None
        frame = bytes(str(pkt).encode("ascii")) + b"\r\n"

        if method == 2:
            ser.write(frame)
        elif method == 3:
            protocol._loop.call_soon(ser.write, frame)
        else:
            protocol._loop.call_later(0.001, ser.write, frame)

    # await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    # assert_state_temp(protocol, None, 0)


async def async_send_cmds(
    protocol: QosProtocol, cmd: Command, num_sends: int = 1
) -> list[asyncio.Task]:
    # TODO: put these back in
    # await assert_protocol_state(protocol, ProtocolState.IDLE)
    # assert_state_temp(protocol, None, 0)

    if num_sends <= 0:
        return
    tasks = []
    for idx in range(1, num_sends + 1):
        tasks += [
            protocol._loop.create_task(protocol.send_cmd(cmd), name=f"send_{idx}")
        ]

        if num_sends <= DEFAULT_MAX_RETRIES + 1:
            state = ProtocolState.RPLY if cmd.rx_header else ProtocolState.IDLE
        else:
            state = ProtocolState.IDLE

        await assert_protocol_state(protocol, state)
        if state == ProtocolState.IDLE:
            assert_protocol_state_detail(protocol, None, 0)
        # else:
        #     assert_protocol_state_detail(protocol, cmd, idx)  # bug is here

    return tasks


# ######################################################################################


@patch(  # maintain state chain (for debugging)
    "ramses_rf.protocol.protocol_fsm._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN
)
@protocol_decorator
async def _test_flow_10x(
    rf: VirtualRf,
    protocol: QosProtocol,
    pkt_rcvd_method: int = 0,
    min_sleeps: bool = None,
) -> None:
    async def send_cmd_wrapper(cmd: Command) -> None:
        await protocol._context._wait_for_send_cmd(
            protocol._context.state, cmd, _DEFAULT_WAIT_TIMEOUT
        )
        protocol._context.state.sent_cmd(cmd, DEFAULT_MAX_RETRIES)

    # STEP 0: Setup...
    # ser = serial.Serial(rf.ports[1])
    max_sleep = 0 if pkt_rcvd_method == 0 else DEFAULT_MAX_SLEEP

    # STEP 1: Send an I cmd (no reply)...
    await send_cmd_wrapper(II_CMD_0)  # sent 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, II_CMD_0, 1)

    await async_pkt_received(
        protocol, II_PKT_0, method=pkt_rcvd_method
    )  # receive the echo
    if not min_sleeps:  # these waits not needed for pkt_rcvd_method != 0
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # gather

    # STEP 2: Send an RQ cmd, then receive the corresponding RP pkt...
    await send_cmd_wrapper(RQ_CMD_0)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_0, 1)

    await async_pkt_received(
        protocol, RQ_PKT_0, method=pkt_rcvd_method
    )  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_0, 1)

    await async_pkt_received(protocol, RP_PKT_0, method=pkt_rcvd_method)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # gather

    # STEP 3: Send an I cmd (no reply) *twice* (TODO: with no intervening echo)...
    await send_cmd_wrapper(II_CMD_0)  # sent 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, II_CMD_0, 1)

    await async_pkt_received(
        protocol, II_PKT_0, method=pkt_rcvd_method
    )  # receive the echo
    if not min_sleeps:  # these waits not needed for pkt_rcvd_method != 0
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    await send_cmd_wrapper(II_CMD_0)  # sent 2nd time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, II_CMD_0, 1)  # would be 2, if no echo

    await async_pkt_received(
        protocol, II_PKT_0, method=pkt_rcvd_method
    )  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # gather

    # STEP 4: Send an RQ cmd, then receive the corresponding RP pkt...
    await send_cmd_wrapper(RQ_CMD_1)  # sent 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 1)

    await async_pkt_received(
        protocol, RQ_PKT_1, method=pkt_rcvd_method
    )  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 1)

    await async_pkt_received(protocol, RP_PKT_1, method=pkt_rcvd_method)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # gather


@patch(  # maintain state chain (for debugging)
    "ramses_rf.protocol.protocol_fsm._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN
)
@protocol_decorator
async def _test_flow_10y(
    rf: VirtualRf,
    protocol: QosProtocol,
    pkt_rcvd_method: int = 0,
    min_sleeps: bool = None,
) -> None:
    # STEP 0: Setup...
    # ser = serial.Serial(rf.ports[1])
    max_sleep = 0 if pkt_rcvd_method == 0 else DEFAULT_MAX_SLEEP

    # STEP 4A: Send an RQ cmd *twice*, then receive the corresponding RP pkt...
    await protocol._context.send_cmd(RQ_CMD_1)  # sent 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.ECHO, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 1)

    await async_pkt_received(
        protocol, RQ_PKT_1, method=pkt_rcvd_method
    )  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 1)

    await protocol._context.send_cmd(RQ_CMD_1)  # sent 2nd time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 2)

    await async_pkt_received(
        protocol, RQ_PKT_1, method=pkt_rcvd_method
    )  # receive the 2nd echo
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 2)

    await async_pkt_received(protocol, RP_PKT_1, method=pkt_rcvd_method)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # gather


@patch("ramses_rf.protocol.protocol.DEFAULT_MAX_RETRIES", DEFAULT_MAX_RETRIES)
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(  # maintain state chain (for debugging)
    "ramses_rf.protocol.protocol_fsm._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN
)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_20x(
    rf: VirtualRf,
    protocol: QosProtocol,
    pkt_rcvd_method: int = 0,
    min_sleeps: bool = None,
) -> None:
    # STEP 0: Setup...
    ser = serial.Serial(rf.ports[1])
    max_sleep = 0 if pkt_rcvd_method == 0 else DEFAULT_MAX_SLEEP

    # STEP 1: Send an I cmd (no reply)...
    tasks = await async_send_cmds(protocol, II_CMD_0, num_sends=1)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # the echo is sent by Virtual RF...
    # if not..

    await asyncio.gather(*tasks)  # no reply pkt expected

    # STEP 2: Send an RQ cmd, then receive the corresponding RP pkt...
    tasks = await async_send_cmds(protocol, RQ_CMD_0, num_sends=1)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_0, 1)

    # the echo is sent by Virtual RF...
    # if not min_sleeps:

    await async_pkt_received(protocol, RP_PKT_0, method=pkt_rcvd_method, ser=ser)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    await asyncio.gather(*tasks)

    # STEP 3: Send an I cmd (no reply) *twice*...
    tasks = await async_send_cmds(protocol, II_CMD_0, num_sends=2)  # send * 2
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # the echo is sent by Virtual RF...
    # if not..

    tasks += await async_send_cmds(protocol, II_CMD_0, num_sends=1)  # send * 2
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # the echo is sent by Virtual RF...
    # if not..

    await asyncio.gather(*tasks)  # no reply pkt expected

    # STEP 4: Send an RQ cmd, then receive the corresponding RP pkt...
    tasks = await async_send_cmds(protocol, RQ_CMD_1, num_sends=1)  # send 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 1)

    # the echo is sent by Virtual RF...
    # if not..

    await async_pkt_received(protocol, RP_PKT_1, method=pkt_rcvd_method, ser=ser)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE)  # , max_sleep=0)
        assert_protocol_state_detail(protocol, None, 0)

    await asyncio.gather(*tasks)


@patch("ramses_rf.protocol.protocol.DEFAULT_MAX_RETRIES", DEFAULT_MAX_RETRIES)
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(  # maintain state chain (for debugging)
    "ramses_rf.protocol.protocol_fsm._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN
)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_20y(
    rf: VirtualRf,
    protocol: QosProtocol,
    pkt_rcvd_method: int = 0,
    min_sleeps: bool = None,
) -> None:
    # STEP 0: Setup...
    ser = serial.Serial(rf.ports[1])
    max_sleep = 0 if pkt_rcvd_method == 0 else DEFAULT_MAX_SLEEP

    # STEP 1: Send an RQ cmd *twice*, then receive the corresponding RP pkt...
    tasks = await async_send_cmds(protocol, RQ_CMD_1, num_sends=1)  # send 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 1)

    # the echo is sent by Virtual RF...
    # if not..

    # TODO: get this working...
    tasks += await async_send_cmds(protocol, RQ_CMD_1, num_sends=1)  # send 2nd time
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.RPLY)  # , max_sleep=0)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 2)

    # the echo is sent by Virtual RF...
    # if not..

    await async_pkt_received(protocol, ser, RP_PKT_1, method=pkt_rcvd_method, ser=ser)
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE)  # , max_sleep=0)
        assert_protocol_state_detail(protocol, None, 0)

    await asyncio.gather(*tasks)

    # STEP 9: Final checks
    await assert_protocol_state(protocol, ProtocolState.IDLE)  # , max_sleep=0)


@patch("ramses_rf.protocol.protocol.DEFAULT_MAX_RETRIES", DEFAULT_MAX_RETRIES)
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(  # maintain state chain (for debugging)
    "ramses_rf.protocol.protocol_fsm._DEBUG_MAINTAIN_STATE_CHAIN", MAINTAIN_STATE_CHAIN
)
@patch(  # stifle impersonation alerts
    "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
@protocol_decorator
async def _test_flow_20z(
    rf: VirtualRf,
    protocol: QosProtocol,
    pkt_rcvd_method: int = 0,
    min_sleeps: bool = None,
) -> None:
    # STEP 0: Setup...
    # ser = serial.Serial(rf.ports[1])
    max_sleep = 0 if pkt_rcvd_method == 0 else DEFAULT_MAX_SLEEP

    # STEP 1: Send an I cmd (no reply)...
    task = protocol._loop.create_task(protocol._send_cmd(II_CMD_0))
    if not min_sleeps:
        await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # the echo is sent by Virtual RF...
    # if not..

    assert await task == II_CMD_0  # no reply pkt expected

    # # # STEP 2: Send an RQ cmd, then receive the corresponding RP pkt...
    # # task = protocol._loop.create_task(protocol._send_cmd(RQ_CMD_0))
    # # if not min_sleeps:
    # #     await assert_protocol_state(
    # #         protocol, ProtocolState.RPLY, max_sleep=DEFAULT_MAX_SLEEP
    # #     )
    # #     assert_protocol_state_detail(protocol, RQ_CMD_0, 1)

    # # # the echo is sent by Virtual RF...
    # # # if not min_sleeps:

    # # await async_pkt_received(protocol, RP_PKT_0, method=pkt_rcvd_method, ser=ser)
    # # if not min_sleeps:
    # #     await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=0)
    # #     assert_protocol_state_detail(protocol, None, 0)

    # # assert await task == RP_PKT_0

    # # # STEP 3: Send an I cmd (no reply) *twice*...
    # # task = protocol._loop.create_task(protocol._send_cmd(II_CMD_0))
    # # if not min_sleeps:
    # #     await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
    # #     assert_protocol_state_detail(protocol, None, 0)

    # # # the echo is sent by Virtual RF...
    # # # if not..

    # # task = protocol._loop.create_task(protocol._send_cmd(II_CMD_0))
    # # if not min_sleeps:
    # #     await assert_protocol_state(protocol, ProtocolState.IDLE, max_sleep=max_sleep)
    # #     assert_protocol_state_detail(protocol, None, 0)

    # # # the echo is sent by Virtual RF...
    # # # if not..

    # # assert await task == II_CMD_0  # no reply pkt expected

    # # # STEP 4: Send an RQ cmd, then receive the corresponding RP pkt...
    # # task = protocol._loop.create_task(protocol._send_cmd(RQ_CMD_1))
    # # if not min_sleeps:
    # #     await assert_protocol_state(protocol, ProtocolState.RPLY, max_sleep=DEFAULT_MAX_SLEEP)
    # #     assert_protocol_state_detail(protocol, RQ_CMD_1, 1)

    # # # the echo is sent by Virtual RF...
    # # # if not..

    # # await async_pkt_received(protocol, RP_PKT_1, method=pkt_rcvd_method, ser=ser)
    # # if not min_sleeps:
    # #     await assert_protocol_state(protocol, ProtocolState.IDLE)  # , max_sleep=0)
    # #     assert_protocol_state_detail(protocol, None, 0)

    # # assert await task == RP_PKT_1


# ######################################################################################


@pytest.mark.xdist_group(name="virtual_rf")
# @patch("ramses_rf.protocol.transport._PortTransport._read_ready", _read_ready)
async def test_flow_100() -> None:
    """Check state change of RQ/I/RQ cmds using context primitives."""
    await _test_flow_10x()
    await _test_flow_10x(min_sleeps=True)


@pytest.mark.xdist_group(name="virtual_rf")
# @patch("ramses_rf.protocol.transport._PortTransport._read_ready", _read_ready)
async def OUT_test_flow_110() -> None:
    """Check state change of RQ/I/RQ cmds using context primitives."""
    await _test_flow_10x(pkt_rcvd_method=1)
    await _test_flow_10x(pkt_rcvd_method=1, min_sleeps=True)


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_200() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""
    await _test_flow_20z(pkt_rcvd_method=0)
    # await _test_flow_20z(pkt_rcvd_method=0, min_sleeps=True)


@pytest.mark.xdist_group(name="virtual_rf")
async def OUT_test_flow_210() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""
    await _test_flow_20x(pkt_rcvd_method=1)
    await _test_flow_20x(pkt_rcvd_method=1, min_sleeps=True)


@pytest.mark.xdist_group(name="virtual_rf")
async def OUT_test_flow_220() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""
    await _test_flow_20x(pkt_rcvd_method=2)
    await _test_flow_20x(pkt_rcvd_method=2, min_sleeps=True)


@pytest.mark.xdist_group(name="virtual_rf")
async def test_flow_230() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""
    await _test_flow_20x(pkt_rcvd_method=3)
    await _test_flow_20x(pkt_rcvd_method=3, min_sleeps=True)


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
# def test_benchmark_100(async_benchmark):
#     async_benchmark(_test_flow_10x)


# @pytest.mark.xdist_group(name="virtual_rf")
# def test_benchmark_230(async_benchmark):
#     async_benchmark(_test_flow_20x)
