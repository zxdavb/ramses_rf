#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

# TODO: Remove unittest.mock.patch (use monkeypatch instead of unittest patch)
# TODO: Test with strict address checking

"""RAMSES RF - Check GWY address/type detection and its treatment of addr0."""

from unittest.mock import patch

import pytest
import serial as ser

from ramses_rf import Command, Gateway
from ramses_rf.device import HgiGateway
from ramses_tx import exceptions as exc
from ramses_tx.address import HGI_DEVICE_ID
from ramses_tx.protocol import PortProtocol
from ramses_tx.typing import QosParams
from tests_rf.virtual_rf import VirtualRf

# patched constants
_DBG_DISABLE_STRICT_CHECKING = True  # #    ramses_tx.address

# other constants
ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 0.05  # 0.01/0.05 minimum for mocked (virtual RF)/actual

HGI_ID_ = HGI_DEVICE_ID  # the sentinel value
TST_ID_ = "18:222222"  # a specific ID

GWY_CONFIG = {
    "config": {
        "disable_discovery": True,
        "disable_qos": False,  # this is required for this test
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

pytestmark = pytest.mark.asyncio(scope="session")


def pytest_generate_tests(metafunc: pytest.Metafunc):
    metafunc.parametrize("test_idx", TEST_CMDS)


@pytest.fixture(scope="session")
async def fake_evofw3(fake_evofw3_port, rf: VirtualRf):
    """Utilize a virtual evofw3-compatible gateway."""

    with patch("ramses_tx.transport.comports", rf.comports):
        gwy = Gateway(fake_evofw3_port, **GWY_CONFIG)
        assert gwy.hgi is None and gwy.devices == []

        await gwy.start()
        assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id == TST_ID_
        assert gwy._protocol._is_evofw3 is True

        try:
            yield gwy
        finally:
            await gwy.stop()


@pytest.fixture(scope="session")
async def fake_ti3410(fake_ti3410_port, rf: VirtualRf):
    """Utilize a virtual HGI80-compatible gateway."""

    with patch("ramses_tx.transport.comports", rf.comports):
        gwy = Gateway(fake_ti3410_port, **GWY_CONFIG)
        assert gwy.hgi is None and gwy.devices == []

        await gwy.start()
        assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id == TST_ID_
        assert gwy._protocol._is_evofw3 is False

        try:
            yield gwy
        finally:
            await gwy.stop()


@pytest.fixture(scope="session")
async def real_evofw3(real_evofw3_port):
    """Utilize an actual evofw3-compatible gateway."""

    global _global_failed_ports

    try:
        gwy = Gateway(real_evofw3_port, **GWY_CONFIG)
    except (ser.SerialException, exc.TransportSerialError) as err:
        _global_failed_ports.append(real_evofw3_port)
        pytest.xfail(str(err))  # not skip, as we'd determined port exists, above

    assert gwy.hgi is None and gwy.devices == []

    await gwy.start()
    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id not in (None, HGI_ID_)
    assert gwy._protocol._is_evofw3 is True

    try:
        yield gwy
    finally:
        await gwy.stop()


@pytest.fixture(scope="session")
async def real_ti3410(real_ti3410_port):
    """Utilize an actual HGI80-compatible gateway."""

    global _global_failed_ports

    try:
        gwy = Gateway(real_ti3410_port, **GWY_CONFIG)
    except (ser.SerialException, exc.TransportSerialError) as err:
        _global_failed_ports.append(real_ti3410_port)
        pytest.xfail(str(err))  # not skip, as we'd determined port exists, above

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
    "ramses_tx.address._DBG_DISABLE_STRICT_CHECKING",
    _DBG_DISABLE_STRICT_CHECKING,
)
async def _test_gwy_device(gwy: Gateway, test_idx: str):
    """Check GWY address/type detection, and behaviour of its treatment of addr0."""

    if not isinstance(gwy._protocol, PortProtocol) or not gwy._protocol._context:
        assert False, "QoS protocol not enabled"  # use assert, not skip

    # we replace the (non-sentinel) gwy_id with the real gwy's actual dev_id
    cmd_str = TEST_CMDS[test_idx].replace(TST_ID_, gwy.hgi.id)
    # this is irrevelent for fake (virtual) gwys, as they been assigned this id

    cmd = Command(cmd_str)
    assert str(cmd) == cmd_str  # sanity check

    is_hgi80 = not gwy._protocol._is_evofw3  # TODO: is_hgi80?

    # NOTE: HGI80 will silently discard all frames that have addr0 != 18:000730

    try:
        # using gwy._protocol.send_cmd() instead of gwy.async_send_cmd() as the
        # latter may swallow the exception we wish to capture (ProtocolSendFailed)
        pkt = await gwy._protocol.send_cmd(
            cmd, qos=QosParams(wait_for_reply=False, timeout=0.1)
        )  # for this test, we only need the cmd echo
    except exc.ProtocolSendFailed:
        if is_hgi80 and cmd_str[7:16] != HGI_ID_:
            return  # should have failed, and has
        raise  # should not have failed, but has!

    assert pkt is not None

    if is_hgi80 and cmd_str[7:16] != HGI_ID_:
        assert False, pkt  # should have failed, but has not!

    # NOTE: both HGI80/evofw3 will swap out addr0 (only) for its own device_id

    if cmd_str[7:16] == HGI_ID_:
        pkt_str = cmd_str[:7] + gwy.hgi.id + cmd_str[16:]
    else:
        pkt_str = cmd_str

    assert pkt._frame == pkt_str


@pytest.mark.xdist_group(name="real_serial")
async def test_real_evofw3(real_evofw3: Gateway, test_idx: str):
    """Validate the GWY test against a real (physical) evofw3."""

    await _test_gwy_device(real_evofw3, test_idx)


@pytest.mark.xdist_group(name="real_serial")
async def test_real_ti3410(real_ti3410: Gateway, test_idx: str):
    """Validate the GWY test against a real (physical) HGI80."""

    await _test_gwy_device(real_ti3410, test_idx)


@pytest.mark.xdist_group(name="virt_serial")
async def test_fake_evofw3(fake_evofw3: Gateway, test_idx: str):
    """Check the behaviour of the fake (virtual) evofw3 against the GWY test."""

    await _test_gwy_device(fake_evofw3, test_idx)


@pytest.mark.xdist_group(name="virt_serial")
async def test_fake_ti3410(fake_ti3410: Gateway, test_idx: str):
    """Check the behaviour of the fake (virtual) HGI80 against the GWY test."""

    await _test_gwy_device(fake_ti3410, test_idx)
