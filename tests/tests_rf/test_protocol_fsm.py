#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

# TODO: replace protocol_decorator with a factory or fixture

"""RAMSES RF - Test the binding protocol with a virtual RF

    NB: This test will likely fail with pytest -n x, because of the protocol's throttle
    limits.
"""

import asyncio
import functools
from datetime import datetime as dt

import pytest
import pytest_asyncio
import serial
import serial_asyncio

from ramses_rf import Command, Packet
from ramses_tx.protocol import QosProtocol, protocol_factory
from ramses_tx.protocol_fsm import (
    Inactive,
    IsFailed,
    IsInIdle,
    WantEcho,
    WantRply,
    _ProtocolStateT,
)
from ramses_tx.transport import transport_factory
from ramses_tx.typing import QosParams

from .virtual_rf import VirtualRf

# patched constants
_DBG_DISABLE_IMPERSONATION_ALERTS = True  # # ramses_tx.protocol
_DBG_MAINTAIN_STATE_CHAIN = False  # #        ramses_tx.protocol_fsm
DEFAULT_MAX_RETRIES = 0  # #                    ramses_tx.protocol
DEFAULT_TIMEOUT = 0.05  # #                     ramses_tx.protocol_fsm
MAX_DUTY_CYCLE = 1.0  # #                       ramses_tx.protocol
_GAP_BETWEEN_WRITES = 0  # #             ramses_tx.protocol

# other constants
CALL_LATER_DELAY = 0.001  # FIXME: this is hardware-specific

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


# ### FIXTURES #########################################################################


@pytest.fixture(autouse=True)
def patches_for_tests(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "ramses_tx.protocol._DBG_DISABLE_IMPERSONATION_ALERTS",
        _DBG_DISABLE_IMPERSONATION_ALERTS,
    )
    monkeypatch.setattr("ramses_tx.protocol._GAP_BETWEEN_WRITES", _GAP_BETWEEN_WRITES)
    monkeypatch.setattr(
        "ramses_tx.protocol_fsm._DBG_MAINTAIN_STATE_CHAIN",
        _DBG_MAINTAIN_STATE_CHAIN,
    )


def protocol_decorator(fnc):  # TODO: make a fixture
    """Create a virtual RF network with a protocol stack."""

    @functools.wraps(fnc)
    async def test_wrapper(*args, **kwargs):
        def _msg_handler(msg) -> None:
            pass

        rf = VirtualRf(2, start=True)

        protocol = protocol_factory(kwargs.pop("msg_handler", _msg_handler))
        await assert_protocol_state(protocol, Inactive, max_sleep=0)

        transport: serial_asyncio.SerialTransport = await transport_factory(
            protocol,
            port_name=rf.ports[0],
            port_config=kwargs.pop("port_config", {}),
            enforce_include_list=kwargs.pop("enforce_include_list", False),
            exclude_list=kwargs.pop("exclude_list", {}),
            include_list=kwargs.pop("include_list", {}),
        )
        transport._extra["virtual_rf"] = rf  # injected to aid any debugging

        try:
            await assert_protocol_state(protocol, IsInIdle, max_sleep=0)
            await fnc(rf, protocol, *args, **kwargs)
            await assert_protocol_state(protocol, (IsInIdle, IsFailed))
        except serial.SerialException as err:
            transport._close(err=err)
            raise
        except (AssertionError, asyncio.InvalidStateError, asyncio.TimeoutError):
            transport.close()
            raise
        else:
            transport.close()
        finally:
            await rf.stop()

        await assert_protocol_state(protocol, Inactive, max_sleep=0)

    return test_wrapper


# ######################################################################################


async def assert_protocol_state(
    protocol: QosProtocol,
    expected_state: _ProtocolStateT,
    max_sleep: int = DEFAULT_MAX_SLEEP,
) -> None:
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if isinstance(protocol._context.state, expected_state):
            break
    assert isinstance(protocol._context.state, expected_state)


def assert_protocol_state_detail(
    protocol: QosProtocol, cmd: Command, num_sends: int
) -> None:
    assert protocol._context.state.is_active_cmd(cmd)
    assert protocol._context.state.num_sends == num_sends
    assert bool(cmd) is isinstance(protocol._context.state, WantEcho | WantRply)


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


# ### TESTS ############################################################################


@protocol_decorator
async def _test_flow_10x(
    rf: VirtualRf,
    protocol: QosProtocol,
    rcvd_method: int = 0,
    min_sleeps: bool = None,
) -> None:
    async def send_cmd_wrapper(cmd: Command) -> Packet:
        async def _send_cmd(cmd) -> None:
            # await protocol._send_frame(str(cmd))
            pass

        # BUG: To make this work after the refactor, would have to create_task
        return await protocol._context.send_cmd(_send_cmd, cmd)

    # STEP 0: Setup...
    # ser = serial.Serial(rf.ports[1])
    max_sleep = 0 if rcvd_method == 0 else DEFAULT_MAX_SLEEP

    # STEP 1: Send an I cmd (no reply)...
    await send_cmd_wrapper(II_CMD_0)  # sent 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, WantEcho, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, II_CMD_0, 1)

    await async_pkt_received(protocol, II_PKT_0, method=rcvd_method)  # receive the echo
    if not min_sleeps:  # these waits not needed for rcvd_method != 0
        await assert_protocol_state(protocol, IsInIdle, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # gather

    # STEP 2: Send an RQ cmd, then receive the corresponding RP pkt...
    await send_cmd_wrapper(RQ_CMD_0)
    if not min_sleeps:
        await assert_protocol_state(protocol, WantEcho, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_0, 1)

    await async_pkt_received(protocol, RQ_PKT_0, method=rcvd_method)  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, WantRply, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_0, 1)

    await async_pkt_received(protocol, RP_PKT_0, method=rcvd_method)
    if not min_sleeps:
        await assert_protocol_state(protocol, IsInIdle, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # gather

    # STEP 3: Send an I cmd (no reply) *twice* (TODO: with no intervening echo)...
    await send_cmd_wrapper(II_CMD_0)  # sent 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, WantEcho, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, II_CMD_0, 1)

    await async_pkt_received(protocol, II_PKT_0, method=rcvd_method)  # receive the echo
    if not min_sleeps:  # these waits not needed for rcvd_method != 0
        await assert_protocol_state(protocol, IsInIdle, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    await send_cmd_wrapper(II_CMD_0)  # sent 2nd time
    if not min_sleeps:
        await assert_protocol_state(protocol, WantEcho, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, II_CMD_0, 1)  # would be 2, if no echo

    await async_pkt_received(protocol, II_PKT_0, method=rcvd_method)  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, IsInIdle, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # gather

    # STEP 4: Send an RQ cmd, then receive the corresponding RP pkt...
    await send_cmd_wrapper(RQ_CMD_1)  # sent 1st time
    if not min_sleeps:
        await assert_protocol_state(protocol, WantEcho, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 1)

    await async_pkt_received(protocol, RQ_PKT_1, method=rcvd_method)  # receive the echo
    if not min_sleeps:
        await assert_protocol_state(protocol, WantRply, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, RQ_CMD_1, 1)

    await async_pkt_received(protocol, RP_PKT_1, method=rcvd_method)
    if not min_sleeps:
        await assert_protocol_state(protocol, IsInIdle, max_sleep=max_sleep)
        assert_protocol_state_detail(protocol, None, 0)

    # gather


@protocol_decorator
async def _test_flow_30x(
    rf: VirtualRf,
    protocol: QosProtocol,
) -> None:
    # STEP 0: Setup...
    ser = serial.Serial(rf.ports[1])

    qos = QosParams()

    # STEP 1: Send an I cmd (no reply)...
    task = protocol._loop.create_task(
        protocol._send_cmd(II_CMD_0, qos=qos), name="send_1"
    )
    assert await task == II_CMD_0  # no reply pkt expected

    # STEP 2: Send an RQ cmd, then receive the corresponding RP pkt...
    task = protocol._loop.create_task(
        protocol._send_cmd(RQ_CMD_0, qos=qos), name="send_2"
    )
    protocol._loop.call_later(
        CALL_LATER_DELAY, ser.write, bytes(str(RP_PKT_0).encode("ascii")) + b"\r\n"
    )
    assert await task == RP_PKT_0

    # STEP 3: Send an I cmd (no reply) *twice*...
    task = protocol._loop.create_task(
        protocol._send_cmd(II_CMD_0, qos=qos), name="send_3A"
    )
    assert await task == II_CMD_0  # no reply pkt expected

    task = protocol._loop.create_task(
        protocol._send_cmd(II_CMD_0, qos=qos), name="send_3B"
    )
    assert await task == II_CMD_0  # no reply pkt expected

    # STEP 4: Send an RQ cmd, then receive the corresponding RP pkt...
    task = protocol._loop.create_task(
        protocol._send_cmd(RQ_CMD_1, qos=qos), name="send_4A"
    )
    # sk = protocol._loop.create_task(protocol._send_cmd(RQ_CMD_1, qos=qos), name="send_4B")

    # TODO: make these deterministic so ser replies *only after* it receives cmd
    protocol._loop.call_later(
        CALL_LATER_DELAY, ser.write, bytes(str(RP_PKT_0).encode("ascii")) + b"\r\n"
    )
    protocol._loop.call_later(
        CALL_LATER_DELAY, ser.write, bytes(str(RP_PKT_1).encode("ascii")) + b"\r\n"
    )

    assert await task == RP_PKT_1


@protocol_decorator
async def _test_flow_qos(rf: VirtualRf, protocol: QosProtocol) -> None:
    #
    # Simple test for an I (does not expect any rx)...
    cmd = Command.put_sensor_temp("03:333333", 19.5)  # 3C09| I|03:333333

    pkt = await protocol._send_cmd(cmd)
    assert pkt is None

    pkt = await protocol._send_cmd(cmd, qos=None)
    assert pkt is None

    pkt = await protocol._send_cmd(cmd, qos=QosParams())
    assert pkt == cmd

    for x in (None, False, True):
        pkt = await protocol._send_cmd(cmd, qos=QosParams(wait_for_reply=x))
        assert pkt == cmd

    # Simple test for an RQ (expects an RP)...
    cmd = Command.get_system_time("01:333333")  # 1F09|RQ|01:333333

    pkt = await protocol._send_cmd(cmd)
    assert pkt is None

    pkt = await protocol._send_cmd(cmd, qos=None)
    assert pkt is None

    # try:
    #     pkt = await protocol._send_cmd(cmd, qos=QosParams())
    # except exc.ProtocolSendFailed:
    #     pass
    # else:
    #     assert False, "Expected ProtocolSendFailed"

    pkt = await protocol._send_cmd(cmd, qos=QosParams(wait_for_reply=False))
    assert pkt == cmd

    # for x in (None, True):
    #     try:
    #         pkt = await protocol._send_cmd(cmd, qos=QosParams(wait_for_reply=x))
    #     except exc.ProtocolSendFailed:
    #         pass
    #     else:
    #         assert False, "Expected ProtocolSendFailed"


@protocol_decorator
async def _test_flow_60x(rf: VirtualRf, protocol: QosProtocol, num_cmds=1) -> None:
    #
    # Setup...
    tasks = []
    for idx in range(num_cmds):
        cmd = Command.get_zone_temp("01:123456", f"{idx:02X}")
        coro = protocol._send_cmd(cmd, qos=QosParams(wait_for_reply=False))
        tasks.append(protocol._loop.create_task(coro, name=f"cmd_{idx:02X}"))

    assert await asyncio.gather(*tasks)


# ######################################################################################


# TODO: needs work after refactor, see BUG, above
@pytest.mark.xdist_group(name="virt_serial")
async def _test_flow_100() -> None:
    """Check state change of RQ/I/RQ cmds using context primitives."""
    await _test_flow_10x(rcvd_method=0)  # try 0, 1
    await _test_flow_10x(rcvd_method=0, min_sleeps=True)


@pytest.mark.xdist_group(name="virt_serial")
async def test_flow_300() -> None:
    """Check state change of RQ/I/RQ cmds using protocol methods."""
    await _test_flow_30x()


@pytest.mark.xdist_group(name="virt_serial")
async def test_flow_qos() -> None:
    """Check the wait_for_reply kwarg."""
    await _test_flow_qos()


@pytest.mark.xdist_group(name="virt_serial")
async def test_flow_601() -> None:
    """Check the wait_for_reply kwarg."""
    await _test_flow_60x()


@pytest.mark.xdist_group(name="virt_serial")
async def _test_flow_602() -> None:
    """Check the wait_for_reply kwarg."""
    await _test_flow_60x(num_cmds=2)


@pytest_asyncio.fixture
async def async_benchmark(benchmark):
    event_loop = asyncio.get_running_loop()

    def _wrapper(func, *args, **kwargs):
        if asyncio.iscoroutinefunction(func):

            @benchmark
            def _():
                return event_loop.run_until_complete(func(*args, **kwargs))

        else:
            benchmark(func, *args, **kwargs)

    return _wrapper


# @pytest.mark.xdist_group(name="virt_serial")
# def test_benchmark_100(async_benchmark):
#     async_benchmark(_test_flow_10x)


# @pytest.mark.xdist_group(name="virt_serial")
# def test_benchmark_300(async_benchmark):
#     async_benchmark(_test_flow_30x)
