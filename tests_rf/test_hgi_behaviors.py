#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the gwy Addr detection and the Gateway.send_cmd API from '18:000730'.
"""

from unittest.mock import patch

import pytest
from serial import SerialException
from serial.tools.list_ports import comports

from ramses_rf import Command, Gateway
from tests_rf.virtual_rf import HgiFwTypes, VirtualRf

# patched constants
_DEBUG_DISABLE_IMPERSONATION_ALERTS = True  # ramses_rf.protocol.protocol
DISABLE_QOS = True  # #                       ramses_rf.protocol.protocol
DISABLE_STRICT_CHECKING = True  # #           ramses_rf.protocol.address
MIN_GAP_BETWEEN_WRITES = 0  # #               ramses_rf.protocol.transport

# other constants
ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 0.05  # 0.01/0.05 minimum for mocked (virtual RF)/actual

HGI_ID_ = "18:000730"  # the generic ID
TST_ID_ = "18:222222"  # .a specific ID

CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    },
    "known_list": {"18:000730": {}},  # required to thwart foreign HGI blacklisting
}


TEST_CMDS = {  # test command strings (no impersonation)
    10: f"RQ --- {TST_ID_} 63:262142 --:------ 10E0 001 00",
    11: r"RQ --- 18:000730 63:262142 --:------ 10E0 001 00",
    20: f" I --- {TST_ID_} {TST_ID_} --:------ 30C9 003 000222",
    21: f" I --- 18:000730 {TST_ID_} --:------ 30C9 003 000333",
    30: f"RP --- {TST_ID_} 18:000730 --:------ 30C9 003 000444",  # addr1 unchanged - foreign gwy
    31: r"RP --- 18:000730 18:000730 --:------ 30C9 003 000555",  # addr1 unchanged - foreign gwy
    40: f" I --- {TST_ID_} --:------ {TST_ID_} 30C9 003 000666",
    41: f" I --- 18:000730 --:------ {TST_ID_} 30C9 003 000777",
    50: f" I --- {TST_ID_} --:------ 18:000730 30C9 003 000888",  # addr2 unchanged - foreign gwy
    51: r" I --- 18:000730 --:------ 18:000730 30C9 003 000999",  # addr2 unchanged - foreign gwy
    60: f" I --- --:------ --:------ {TST_ID_} 0008 002 00AA",
    61: r" I --- --:------ --:------ 18:000730 0008 002 00BB",  # . addr2 unchanged - foreign gwy
}


def pytest_generate_tests(metafunc: pytest.Metafunc):
    metafunc.parametrize("test_idx", TEST_CMDS)


@pytest.fixture()
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def fake_evofw3():
    """Utilize a virtual evofw3-compatible gateway."""

    rf = VirtualRf(1)
    rf.set_gateway(rf.ports[0], TST_ID_, fw_version=HgiFwTypes.EVOFW3)

    with patch("ramses_rf.protocol.transport.comports", rf.comports):
        gwy = Gateway(rf.ports[0], **CONFIG)
        assert gwy.devices == []
        assert gwy.hgi is None

        await gwy.start()
        assert gwy.hgi and gwy.hgi.id not in (None, HGI_ID_)
        assert gwy._protocol._is_evofw3 is True

        return gwy  # TODO: yield gwy

    await gwy.stop()
    await rf.stop()


@pytest.fixture()
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def fake_ti3410():
    """Utilize a virtual HGI80-compatible gateway."""

    rf = VirtualRf(1)
    rf.set_gateway(rf.ports[0], TST_ID_, fw_version=HgiFwTypes.HGI_80)

    with patch("ramses_rf.protocol.transport.comports", rf.comports):
        gwy = Gateway(rf.ports[0], **CONFIG)
        assert gwy.devices == []
        assert gwy.hgi is None

        await gwy.start()
        assert gwy.hgi and gwy.hgi.id not in (None, HGI_ID_)
        assert gwy._protocol._is_evofw3 is False

        return gwy  # TODO: yield gwy

    await gwy.stop()
    await rf.stop()


@pytest.fixture()
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def real_evofw3():
    """Utilize an actual evofw3-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "evofw3" in p.product]
    port_names = port_names or ["/dev/ttyUSB1"]

    gwy = Gateway(port_names[0], **CONFIG)
    assert gwy.devices == []
    assert gwy.hgi is None

    await gwy.start()
    assert gwy.hgi and gwy.hgi.id not in (None, HGI_ID_)
    assert gwy._protocol._is_evofw3 is True

    yield gwy  # TODO: yield gwy
    await gwy.stop()


@pytest.fixture()
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def real_ti3410():
    """Utilize an actual HGI80-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "TUSB3410" in p.product]
    port_names = port_names or ["/dev/ttyUSB0"]

    gwy = Gateway(port_names[0], **CONFIG)
    assert gwy.devices == []
    assert gwy.hgi is None

    await gwy.start()
    assert gwy.hgi and gwy.hgi.id not in (None, HGI_ID_)
    # assert gwy._protocol._is_evofw3 is False  # FIXME

    return gwy  # TODO: yield gwy
    await gwy.stop()


_global_failed_ports: list[str] = []


@patch(
    "ramses_rf.protocol.address._DEBUG_DISABLE_STRICT_CHECKING", DISABLE_STRICT_CHECKING
)
async def _test_gwy_device(gwy: Gateway, test_idx: str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    raw_str = TEST_CMDS[test_idx]

    cmd_str = raw_str.replace(TST_ID_, gwy.hgi.id)
    # expected pkt: only addr0 is corrected by the gateway device...

    if cmd_str[7:16] == HGI_ID_:
        pkt_str = cmd_str[:7] + gwy.hgi.id + cmd_str[16:]
    else:
        pkt_str = cmd_str

    cmd = Command(cmd_str, qos={"retries": 0})
    assert str(cmd) == cmd_str, test_idx

    pkt = await gwy.async_send_cmd(cmd, max_retries=0, wait_for_reply=False)
    assert pkt._frame == pkt_str


@pytest.mark.xdist_group(name="real_serial")
# @pytest.mark.skipif(not [p for p in comports() if p.product and "evofw3" in p.product], reason="No evofw3 devices found")
@patch(
    "ramses_rf.protocol.protocol._DEBUG_DISABLE_IMPERSONATION_ALERTS",
    _DEBUG_DISABLE_IMPERSONATION_ALERTS,
)
async def test_factual_evofw3(real_evofw3: Gateway, test_idx: str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    global _global_failed_ports

    gwy: Gateway = await anext(real_evofw3)

    if gwy.ser_name in _global_failed_ports:
        pytest.skip(f"previous SerialException on: {gwy.ser_name}")

    try:
        await _test_gwy_device(gwy, test_idx)
    except SerialException as exc:
        _global_failed_ports.append(gwy.ser_name)
        pytest.xfail(str(exc))  # not skip, as we'd determined port exists, above


@pytest.mark.xdist_group(name="real_serial")
# @pytest.mark.skipif(not [p for p in comports() if p.product and "TUSB3410" in p.product], reason="No ti3410 devices found")
@patch(
    "ramses_rf.protocol.protocol._DEBUG_DISABLE_IMPERSONATION_ALERTS",
    _DEBUG_DISABLE_IMPERSONATION_ALERTS,
)
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def test_factual_ti3410(real_ti3410: Gateway, test_idx: str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    global _global_failed_ports

    gwy = real_ti3410

    if gwy.ser_name in _global_failed_ports:
        pytest.skip(f"previous SerialException on: {gwy.ser_name}")

    try:
        await _test_gwy_device(gwy, test_idx)
    except SerialException as exc:
        _global_failed_ports.append(gwy.ser_name)
        pytest.xfail(str(exc))  # not skip, as we'd determined port exists, above


@pytest.mark.xdist_group(name="fake_serial")
# @patch("ramses_rf.protocol.protocol._DEBUG_DISABLE_IMPERSONATION_ALERTS", _DEBUG_DISABLE_IMPERSONATION_ALERTS)
# @patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def test_virtual_evofw3(fake_evofw3: Gateway, test_idx: str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    gwy = fake_evofw3

    await _test_gwy_device(gwy, test_idx)


@pytest.mark.xdist_group(name="fake_serial")
@patch(
    "ramses_rf.protocol.protocol._DEBUG_DISABLE_IMPERSONATION_ALERTS",
    _DEBUG_DISABLE_IMPERSONATION_ALERTS,
)
@patch("ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def test_virtual_ti4310(fake_ti3410: Gateway, test_idx: str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    gwy = fake_ti3410

    await _test_gwy_device(gwy, test_idx)
