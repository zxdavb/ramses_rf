#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

# TODO: Remove unittest.mock.patch (use monkeypatch instead of unittest patch)
# TODO: Test with strict address checking

"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the gwy Addr detection and the Gateway.send_cmd API from '18:000730'.
"""

import asyncio
from unittest.mock import patch

import pytest
from serial import SerialException
from serial.tools.list_ports import comports

from ramses_rf import Command, Gateway
from ramses_rf.device import HgiGateway
from ramses_tx.exceptions import ProtocolSendFailed
from tests_rf.virtual_rf import HgiFwTypes, VirtualRf

# patched constants
_DEBUG_DISABLE_DUTY_CYCLE_LIMIT = True  # #   ramses_tx.protocol
_DEBUG_DISABLE_IMPERSONATION_ALERTS = True  # ramses_tx.protocol
_DEBUG_DISABLE_STRICT_CHECKING = True  # #    ramses_tx.address
MIN_GAP_BETWEEN_WRITES = 0  # #               ramses_tx.transport

# other constants
ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 0.05  # 0.01/0.05 minimum for mocked (virtual RF)/actual

HGI_ID_ = "18:000730"  # the sentinel value
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
    30: f"RP --- {TST_ID_} 18:000730 --:------ 30C9 003 000444",
    31: r"RP --- 18:000730 18:000730 --:------ 30C9 003 000555",
    40: f" I --- {TST_ID_} --:------ {TST_ID_} 30C9 003 000666",
    41: f" I --- 18:000730 --:------ {TST_ID_} 30C9 003 000777",
    50: f" I --- {TST_ID_} --:------ 18:000730 30C9 003 000888",
    51: r" I --- 18:000730 --:------ 18:000730 30C9 003 000999",
    60: f" I --- --:------ --:------ {TST_ID_} 0008 002 00AA",
    61: r" I --- --:------ --:------ 18:000730 0008 002 00BB",
}
# NOTE: HGI80 will silently discard all frames that have addr0 != 18:000730
TEST_CMDS_FAIL_ON_HGI80 = [k for k, v in TEST_CMDS.items() if v[7:16] == TST_ID_]


_global_failed_ports: list[str] = []


# ### FIXTURES #########################################################################


@pytest.fixture(autouse=True)
def patches_for_tests(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "ramses_tx.protocol._DEBUG_DISABLE_DUTY_CYCLE_LIMIT",
        _DEBUG_DISABLE_DUTY_CYCLE_LIMIT,
    )
    monkeypatch.setattr(
        "ramses_tx.protocol._DEBUG_DISABLE_IMPERSONATION_ALERTS",
        _DEBUG_DISABLE_IMPERSONATION_ALERTS,
    )
    monkeypatch.setattr(
        "ramses_tx.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES
    )


def pytest_generate_tests(metafunc: pytest.Metafunc):
    metafunc.parametrize("test_idx", TEST_CMDS)


@pytest.fixture(scope="module")
def event_loop():
    """Overrides pytest default function scoped event loop"""
    loop = asyncio.get_event_loop()
    try:
        yield loop
    finally:
        loop.close()


@pytest.fixture(scope="module")
async def fake_evofw3():
    """Utilize a virtual evofw3-compatible gateway."""

    rf = VirtualRf(1)
    rf.set_gateway(rf.ports[0], TST_ID_, fw_type=HgiFwTypes.EVOFW3)

    with patch("ramses_tx.transport.comports", rf.comports):
        gwy = Gateway(rf.ports[0], **CONFIG)
        assert gwy.hgi is None and gwy.devices == []

        await gwy.start()
        assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id == TST_ID_
        assert gwy._protocol._is_evofw3 is True

        try:
            yield gwy
        finally:
            await gwy.stop()
            await rf.stop()


@pytest.fixture(scope="module")
async def fake_ti3410():
    """Utilize a virtual HGI80-compatible gateway."""

    rf = VirtualRf(1)
    rf.set_gateway(rf.ports[0], TST_ID_, fw_type=HgiFwTypes.HGI_80)

    with patch("ramses_tx.transport.comports", rf.comports):
        gwy = Gateway(rf.ports[0], **CONFIG)
        assert gwy.hgi is None and gwy.devices == []

        await gwy.start()
        assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id == TST_ID_
        assert gwy._protocol._is_evofw3 is False

        try:
            yield gwy
        finally:
            await gwy.stop()
            await rf.stop()


@pytest.fixture(scope="module")  # TODO: remove HACK
async def real_evofw3():
    """Utilize an actual evofw3-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "evofw3" in p.product]
    port_names = port_names or ["/dev/ttyUSB1"]  # HACK: FIXME (should not be needed)

    gwy = Gateway(port_names[0], **CONFIG)
    assert gwy.hgi is None and gwy.devices == []

    await gwy.start()
    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id not in (None, HGI_ID_)
    assert gwy._protocol._is_evofw3 is True

    try:
        yield gwy
    finally:
        await gwy.stop()


@pytest.fixture(scope="module")  # TODO: remove HACK
async def real_ti3410():
    """Utilize an actual HGI80-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "TUSB3410" in p.product]
    port_names = port_names or ["/dev/ttyUSB0"]  # HACK: FIXME (should not be needed)

    gwy = Gateway(port_names[0], **CONFIG)
    assert gwy.hgi is None and gwy.devices == []

    await gwy.start()
    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id not in (None, HGI_ID_)
    gwy._protocol._is_evofw3 = False  # HACK: FIXME (should not be needed)
    assert gwy._protocol._is_evofw3 is False

    try:
        yield gwy
    finally:
        await gwy.stop()


# ### TESTS ############################################################################


@patch(  # DISABLE_STRICT_CHECKING
    "ramses_tx.address._DEBUG_DISABLE_STRICT_CHECKING",
    _DEBUG_DISABLE_STRICT_CHECKING,
)
async def _test_gwy_device(gwy: Gateway, test_idx: str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    # for testing, we replace the sentinel value with the gateway's actual device_id
    cmd_str = TEST_CMDS[test_idx].replace(TST_ID_, gwy.hgi.id)

    cmd = Command(cmd_str, qos={"retries": 0})
    assert str(cmd) == cmd_str

    is_hgi80 = not gwy._protocol._is_evofw3  # TODO: is_hgi80?

    try:
        # NOTE: using gwy._protocol.send_cmd() instead of gwy.async_send_cmd() as the
        # latter may swallow the exception we wish to capture (ProtocolSendFailed)
        pkt = await gwy._protocol.send_cmd(cmd, max_retries=0, wait_for_reply=False)
    except ProtocolSendFailed:
        if is_hgi80 and cmd_str[7:16] != HGI_ID_:
            return  # should have failed, and has
        raise

    if is_hgi80 and cmd_str[7:16] != HGI_ID_:
        assert False, pkt  # should have failed, but did not!

    # NOTE: HGI80/evofw3 will both swap out addr0 (only) for its own device_id
    if cmd_str[7:16] == HGI_ID_:
        pkt_str = cmd_str[:7] + gwy.hgi.id + cmd_str[16:]
    else:
        pkt_str = cmd_str

    assert pkt._frame == pkt_str


@pytest.mark.xdist_group(name="real_serial")
@pytest.mark.skipif(
    not [p for p in comports() if p.product and "evofw3" in p.product],
    reason="No evofw3 devices found",
)
async def test_real_evofw3(real_evofw3: Gateway, test_idx: str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    global _global_failed_ports

    gwy = real_evofw3

    if gwy.ser_name in _global_failed_ports:
        pytest.skip(f"previous SerialException on: {gwy.ser_name}")

    try:
        await _test_gwy_device(gwy, test_idx)
    except SerialException as exc:
        _global_failed_ports.append(gwy.ser_name)
        pytest.xfail(str(exc))  # not skip, as we'd determined port exists, above


@pytest.mark.xdist_group(name="real_serial")
@pytest.mark.skipif(
    not [p for p in comports() if p.product and "TUSB3410" in p.product],
    reason="No ti3410 devices found",
)
async def test_real_ti3410(real_ti3410: Gateway, test_idx: str):
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


@pytest.mark.xdist_group(name="virt_serial")
async def test_fake_evofw3(fake_evofw3: Gateway, test_idx: str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    await _test_gwy_device(fake_evofw3, test_idx)


@pytest.mark.xdist_group(name="virt_serial")
async def test_fake_ti3410(fake_ti3410: Gateway, test_idx: str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    await _test_gwy_device(fake_ti3410, test_idx)
