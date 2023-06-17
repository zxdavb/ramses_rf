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
from tests_rf.virtual_rf import HgiFwTypes, VirtualRf, stifle_impersonation_alert

MIN_GAP_BETWEEN_WRITES = 0  # to patch ramses_rf.protocol.transport

ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 0.05  # 0.01/0.05 minimum for mocked (virtual RF)/actual

HGI_ID_ = "18:000730"  # the generic ID
TST_ID_ = "18:222222"  # .a specific ID

CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}


TEST_CMDS = {  # test command strings (no impersonation)
    10: f"RQ --- {TST_ID_} 63:262142 --:------ 10E0 001 00",
    11: r"RQ --- 18:000730 63:262142 --:------ 10E0 001 00",
    20: f" I --- {TST_ID_} {TST_ID_} --:------ 30C9 003 000222",
    21: f" I --- 18:000730 {TST_ID_} --:------ 30C9 003 000333",
    30: f"RP --- {TST_ID_} 18:000730 --:------ 30C9 003 000444",  # addr1 unchanged
    31: r"RP --- 18:000730 18:000730 --:------ 30C9 003 000555",  # addr1 unchanged
    40: f" I --- {TST_ID_} --:------ {TST_ID_} 30C9 003 000666",
    41: f" I --- 18:000730 --:------ {TST_ID_} 30C9 003 000777",
    50: f" I --- {TST_ID_} --:------ 18:000730 30C9 003 000888",  # addr2 unchanged
    51: r" I --- 18:000730 --:------ 18:000730 30C9 003 000999",  # addr2 unchanged
    60: f" I --- --:------ --:------ {TST_ID_} 0008 002 00AA",
    61: r" I --- --:------ --:------ 18:000730 0008 002 00BB",  # . addr2 unchanged
}


def pytest_generate_tests(metafunc):
    def id_fnc(param):
        return param._name_

    metafunc.parametrize("test_idx", TEST_CMDS)  # , ids=id_fnc)


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
    # gwy._this_msg._pkt
    # gwy._protocol._this_msg._pkt
    # gwy._transport._this_pkt
    assert str(gwy._this_msg._pkt) == expected_frame


async def assert_is_evofw3(
    gwy: Gateway, is_evofw3: bool, max_sleep: int = DEFAULT_MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if gwy._protocol._is_evofw3 is not None:
            break
    assert gwy._protocol._is_evofw3 == is_evofw3


async def assert_found_hgi(
    gwy: Gateway, hgi_id=None, max_sleep: int = DEFAULT_MAX_SLEEP
):
    """Check the gateway device is the expected type (evofw3,or HGI80)."""

    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if gwy.hgi is not None:
            break
    assert gwy.hgi is not None
    if hgi_id:
        assert gwy.hgi.id == hgi_id


_global_failed_ports: list[str] = []


@patch("ramses_rf.protocol.address._STRICT_CHECKING", False)
@patch(
    "ramses_rf.protocol.transport_new.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES
)
@patch(
    "ramses_rf.protocol.protocol_new._ProtImpersonate._send_impersonation_alert",
    stifle_impersonation_alert,
)
async def _test_hgi(port_name, org_str, is_evofw3: bool):
    """Check the virtual RF network behaves as expected (device discovery)."""

    gwy_0 = Gateway(port_name, **CONFIG)

    assert gwy_0.devices == []
    assert gwy_0.hgi is None

    await gwy_0.start()
    await assert_is_evofw3(gwy_0, is_evofw3)

    try:
        await assert_found_hgi(gwy_0)  # , hgi_id=TST_ID_)
        assert gwy_0.hgi.id != HGI_ID_

        cmd_str = org_str.replace(TST_ID_, gwy_0.hgi.id)
        # expected pkt: only addr0 is corrected by the gateway device...
        if cmd_str[7:16] == HGI_ID_:
            pkt_str = cmd_str[:7] + gwy_0.hgi.id + cmd_str[16:]
        else:
            pkt_str = cmd_str

        cmd = Command(cmd_str, qos={"retries": 0})
        assert str(cmd) == cmd_str

        # TODO: also test: gwy_0.send_cmd(cmd)
        await gwy_0.async_send_cmd(cmd)
        # TODO: consider: await gwy_0._protocol._send_cmd(cmd)
        await assert_expected_pkt(gwy_0, pkt_str)

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

    port = [p.device for p in comports() if "evofw3" in p.product][0]

    if port in _global_failed_ports:
        pytest.skip(f"previous SerialException on: {port}")

    try:
        await _test_hgi(port, TEST_CMDS[test_idx], is_evofw3=True)
    except SerialException as exc:
        _global_failed_ports.append(port)
        pytest.xfail(str(exc))  # not skip, as we'd determined port exists, above


@pytest.mark.xdist_group(name="real_serial")
@pytest.mark.skipif(
    not [p for p in comports() if "TUSB3410" in p.product],
    reason="No ti3410 devices found",
)
async def _test_actual_ti3410(test_idx):
    """Check the virtual RF network behaves as expected (device discovery)."""

    global _global_failed_ports

    port = [p.device for p in comports() if "TUSB3410" in p.product][0]

    if port in _global_failed_ports:
        pytest.skip(f"previous SerialException on: {port}")

    try:
        await _test_hgi(port, TEST_CMDS[test_idx], is_evofw3=False)
    except SerialException as exc:
        _global_failed_ports.append(port)
        pytest.xfail(str(exc))  # not skip, as we'd determined port exists, above


@pytest.mark.xdist_group(name="mock_serial")
@patch(
    "ramses_rf.protocol.transport_new.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES
)
async def test_mocked_evofw3(test_idx):
    """Check the virtual RF network behaves as expected (device discovery)."""

    rf = VirtualRf(1)
    rf.set_gateway(rf.ports[0], TST_ID_, fw_version=HgiFwTypes.EVOFW3)

    with patch("ramses_rf.protocol.transport_new.comports", rf.comports):
        try:
            await _test_hgi(rf.ports[0], TEST_CMDS[test_idx], is_evofw3=True)
        finally:
            await rf.stop()


@pytest.mark.xdist_group(name="mock_serial")
@patch(
    "ramses_rf.protocol.transport_new.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES
)
async def test_mocked_ti4310(test_idx):
    """Check the virtual RF network behaves as expected (device discovery)."""

    rf = VirtualRf(1)
    rf.set_gateway(rf.ports[0], TST_ID_, fw_version=HgiFwTypes.NATIVE)

    with patch("ramses_rf.protocol.transport_new.comports", rf.comports):
        try:
            await _test_hgi(rf.ports[0], TEST_CMDS[test_idx], is_evofw3=False)
        finally:
            await rf.stop()
