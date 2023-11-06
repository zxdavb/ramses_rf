#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

# TODO: Add assert_protocol_ready to VirtualRF factory (or in library?)

"""Test the Virtual RF library.

    VirtualRF is used for testing.
"""

import asyncio

import pytest
import serial

from ramses_rf import Code, Command, Device, Gateway
from tests_rf.virtual_rf import DEFAULT_GWY_CONFIG, VirtualRf, rf_factory

# patched constants
_DEBUG_DISABLE_DUTY_CYCLE_LIMIT = True  # #   ramses_tx.protocol
_DEBUG_DISABLE_IMPERSONATION_ALERTS = True  # ramses_tx.protocol
MIN_GAP_BETWEEN_WRITES = 0  # #               ramses_tx.protocol

# other constants
ASSERT_CYCLE_TIME = 0.001  # max_cycles_per_assert = max_sleep / ASSERT_CYCLE_TIME
DEFAULT_MAX_SLEEP = 1


SCHEMA_0 = {
    "orphans_hvac": ["41:111111"],
    "known_list": {"41:111111": {"class": "REM"}},
}

SCHEMA_1 = {
    "orphans_hvac": ["42:222222"],
    "known_list": {"42:222222": {"class": "FAN"}},
}


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


# ######################################################################################


async def assert_code_in_device_msgz(
    gwy: Gateway,
    dev_id: str,
    code: Code,
    max_sleep: int = DEFAULT_MAX_SLEEP,
    test_not: bool = False,
):
    """Fail if the device doesn't exist, or if it doesn't have the code in its DB."""

    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if ((dev := gwy.device_by_id.get(dev_id)) and (code in dev._msgz)) != test_not:
            break
    assert (
        (dev := gwy.device_by_id.get(dev_id)) and (code in dev._msgz)
    ) != test_not  # TODO: fix me


async def assert_devices(
    gwy: Gateway, devices: list[Device], max_sleep: int = DEFAULT_MAX_SLEEP
):
    """Fail if the two sets of devices are not equal."""

    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if len(gwy.devices) == len(devices):
            break
    assert sorted(d.id for d in gwy.devices) == sorted(devices)


async def assert_this_pkt(transport, cmd: Command, max_sleep: int = DEFAULT_MAX_SLEEP):
    """Check, at the transport layer, that the current packet is as expected."""
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if transport._this_pkt and transport._this_pkt._frame == cmd._frame:
            break
    assert transport._this_pkt and transport._this_pkt._frame == cmd._frame


# ### TESTS ############################################################################


# NOTE: does not use factory
@pytest.mark.xdist_group(name="virt_serial")
async def test_virtual_rf_dev_disc():
    """Check the virtual RF network behaves as expected (device discovery)."""

    rf = VirtualRf(3)

    rf.set_gateway(rf.ports[0], "18:000000")
    gwy_0 = Gateway(rf.ports[0], **DEFAULT_GWY_CONFIG)
    await assert_devices(gwy_0, [])

    rf.set_gateway(rf.ports[1], "18:111111")
    gwy_1 = Gateway(rf.ports[1], **DEFAULT_GWY_CONFIG)
    await assert_devices(gwy_1, [])

    ser_2 = serial.Serial(rf.ports[2])

    # TEST 0: Tx of fingerprint packet with one on/one off
    await gwy_0.start()
    assert gwy_0._protocol._transport

    await assert_devices(gwy_0, ["18:000000"])
    await assert_devices(gwy_1, [])

    await gwy_1.start()
    assert gwy_1._protocol._transport

    await assert_devices(gwy_0, ["18:000000"])  # not "18:111111", as is foreign
    await assert_devices(gwy_1, ["18:111111"])

    # TEST 1: Tx to all from GWY /dev/pty/0 (NB: no RSSI)
    cmd = Command("RP --- 01:111111 --:------ 01:111111 1F09 003 0004B5")
    gwy_0.send_cmd(cmd)

    await assert_devices(gwy_0, ["01:111111", "18:000000"])
    await assert_devices(gwy_1, ["01:111111", "18:111111"])

    # TEST 2: Tx to all from non-GWY /dev/pty/2 (NB: no RSSI)
    cmd = Command("RP --- 01:222222 --:------ 01:222222 1F09 003 0004B5")
    ser_2.write(bytes(f"{cmd}\r\n".encode("ascii")))

    await assert_devices(gwy_0, ["01:111111", "01:222222", "18:000000"])
    await assert_devices(gwy_1, ["01:111111", "01:222222", "18:111111"])

    # TEST 3: Rx only by *only one* GWY (NB: needs RSSI)
    cmd = Command("RP --- 01:333333 --:------ 01:333333 1F09 003 0004B5")
    list(rf._file_objs.values())[1].write(bytes(f"000 {cmd}\r\n".encode("ascii")))

    await assert_devices(gwy_0, ["01:111111", "01:222222", "18:000000"])
    await assert_devices(gwy_1, ["01:111111", "01:222222", "01:333333", "18:111111"])

    await gwy_0.stop()
    await gwy_1.stop()
    await rf.stop()


# NOTE: uses factory
@pytest.mark.xdist_group(name="virt_serial")
async def test_virtual_rf_pkt_flow():
    """Check the virtual RF network behaves as expected (packet flow)."""

    rf, (gwy_0, gwy_1) = await rf_factory(
        [DEFAULT_GWY_CONFIG | SCHEMA_0, DEFAULT_GWY_CONFIG | SCHEMA_1]
    )

    assert gwy_0._protocol._transport
    await assert_devices(gwy_0, ["18:000000", "41:111111"])

    assert gwy_1._protocol._transport
    await assert_devices(gwy_1, ["18:111111", "42:222222"])

    # TEST 1:
    await assert_code_in_device_msgz(
        gwy_0, "01:333333", Code._1F09, max_sleep=0, test_not=True
    )  # device wont exist

    cmd = Command(
        "RP --- 01:333333 --:------ 01:333333 1F09 003 0004B5", qos={"retries": 0}
    )  # no retries, otherwise long duration
    gwy_0.send_cmd(cmd)

    await assert_devices(gwy_0, ["18:000000", "01:333333", "41:111111"])
    await assert_code_in_device_msgz(gwy_0, "01:333333", Code._1F09)

    await assert_this_pkt(gwy_0._transport, cmd)
    await assert_this_pkt(gwy_1._transport, cmd)

    # TEST 2:
    await assert_code_in_device_msgz(
        gwy_0, "41:111111", Code._22F1, max_sleep=0, test_not=True
    )

    cmd = Command(
        " I --- 41:111111 --:------ 41:111111 22F1 003 000507", qos={"retries": 0}
    )  # no retries, otherwise long duration
    gwy_0.send_cmd(cmd)

    await assert_code_in_device_msgz(gwy_0, "41:111111", Code._22F1)

    await assert_this_pkt(gwy_0._transport, cmd)
    await assert_this_pkt(gwy_1._transport, cmd)

    await assert_devices(gwy_0, ["18:000000", "01:333333", "41:111111"])
    await assert_devices(gwy_1, ["18:111111", "01:333333", "41:111111", "42:222222"])

    await gwy_0.stop()
    await gwy_1.stop()
    await rf.stop()
