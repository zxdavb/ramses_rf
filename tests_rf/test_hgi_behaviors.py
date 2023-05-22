#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the gwy Addr detection and the Gateway.send_cmd API from '18:000730'.
"""

import asyncio
from unittest.mock import patch

import pytest
from serial import SerialException
from serial.tools.list_ports import comports

from ramses_rf import Command, Device, Gateway
from tests_rf.virtual_rf import HgiFwTypes, VirtualRf

MIN_GAP_BETWEEN_WRITES = 0  # to patch ramses_rf.protocol.transport

ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 0.05  # 0.01/0.05 minimum for mocked (virtual RF)/actual

HGI_ID_ = "18:000730"
TST_ID_ = "18:222222"

CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}


TEST_CMDS = (  # test command strings
    r" I --- 18:000730 --:------ 18:000730 30C9 003 000666",
    f" I --- 18:000730 --:------ {TST_ID_} 30C9 003 000777",
    f" I --- {TST_ID_} --:------ 18:000730 30C9 003 000888",
    f" I --- {TST_ID_} --:------ {TST_ID_} 30C9 003 000999",
    r"RQ --- 18:000730 63:262142 --:------ 10E0 001 00",
    f"RQ --- {TST_ID_} 63:262142 --:------ 10E0 001 00",
    f" I --- --:------ --:------ {TST_ID_} 0008 002 0011",
    r" I --- --:------ --:------ 18:000730 0008 002 0022",
)


def pytest_generate_tests(metafunc):
    def id_fnc(param):
        return param._name_

    metafunc.parametrize("test_idx", range(len(TEST_CMDS)))  # , ids=id_fnc)


async def _alert_is_impersonating(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


async def assert_devices(
    gwy: Gateway, devices: list[Device], max_sleep: int = DEFAULT_MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if len(gwy.devices) == len(devices):
            break
    assert sorted(d.id for d in gwy.devices) == sorted(devices)


async def assert_expected_pkt(
    gwy: Gateway, expected_frame: str, max_sleep: int = DEFAULT_MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if gwy._this_msg and str(gwy._this_msg._pkt) == expected_frame:
            break
    assert str(gwy._this_msg._pkt) == expected_frame


async def assert_hgi_id(gwy: Gateway, hgi_id=None, max_sleep: int = DEFAULT_MAX_SLEEP):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if gwy.hgi is not None:
            break
    assert gwy.hgi is not None


_global_failed_ports: list[str] = []


@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    _alert_is_impersonating,
)
async def _test_hgi_addrs(port_name, org_str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    gwy_0 = Gateway(port_name, **CONFIG)

    assert gwy_0.devices == []
    assert gwy_0.hgi is None

    await gwy_0.start()

    try:
        await assert_hgi_id(gwy_0)
        assert gwy_0.hgi.id != HGI_ID_

        cmd_str = org_str.replace(TST_ID_, gwy_0.hgi.id)
        pkt_str = cmd_str.replace(HGI_ID_, gwy_0.hgi.id)

        cmd = Command(cmd_str, qos={"retries": 0})
        assert str(cmd) == cmd_str

        gwy_0.send_cmd(cmd)
        await assert_expected_pkt(gwy_0, pkt_str)
    except AssertionError:
        raise
    finally:
        await gwy_0.stop()


@pytest.mark.xdist_group(name="real_serial")
@pytest.mark.skipif(
    not [p for p in comports() if "evofw3" in p.product],
    reason="No evofw3 devices found",
)
async def test_actual_evofw3(test_idx):
    """Check the virtual RF network behaves as expected (device discovery)."""

    global _global_failed_ports

    if test_idx in (0, 2, 7):
        pytest.skip("these tests are TBD")

    port = [p.device for p in comports() if "evofw3" in p.product][0]

    if port in _global_failed_ports:
        pytest.xfail(f"previous SerialException on: {port}")

    try:
        await _test_hgi_addrs(port, TEST_CMDS[test_idx])
    except SerialException as exc:
        _global_failed_ports.append(port)
        pytest.xfail(str(exc))


@pytest.mark.xdist_group(name="real_serial")
@pytest.mark.skipif(
    not [p for p in comports() if "TUSB3410" in p.product],
    reason="No ti3410 devices found",
)
async def test_actual_ti3410(test_idx):
    """Check the virtual RF network behaves as expected (device discovery)."""

    global _global_failed_ports

    if False:
        pytest.skip("these tests are TBD")

    port = [p.device for p in comports() if "TUSB3410" in p.product][0]

    if port in _global_failed_ports:
        pytest.xfail(f"previous SerialException on: {port}")

    try:
        await _test_hgi_addrs(port, TEST_CMDS[test_idx])
    except SerialException as exc:
        _global_failed_ports.append(port)
        pytest.xfail(str(exc))


@pytest.mark.xdist_group(name="mock_serial")
@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def test_mocked_evofw3(test_idx):
    """Check the virtual RF network behaves as expected (device discovery)."""

    rf = VirtualRf(1)
    rf.set_gateway(rf.ports[0], TST_ID_, fw_version=HgiFwTypes.EVOFW3)

    with patch("ramses_rf.protocol.transport.comports", rf.comports):
        try:
            await _test_hgi_addrs(rf.ports[0], TEST_CMDS[test_idx])
        finally:
            await rf.stop()


@pytest.mark.xdist_group(name="mock_serial")
@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def test_mocked_ti4310(test_idx):
    """Check the virtual RF network behaves as expected (device discovery)."""

    if test_idx in (0, 2, 7):
        pytest.skip("test is TBD")

    rf = VirtualRf(1)
    rf.set_gateway(rf.ports[0], TST_ID_, fw_version=HgiFwTypes.NATIVE)

    with patch("ramses_rf.protocol.transport.comports", rf.comports):
        try:
            await _test_hgi_addrs(rf.ports[0], TEST_CMDS[test_idx])
        finally:
            await rf.stop()
