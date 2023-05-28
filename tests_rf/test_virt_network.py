#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the Virtual RF library.

    VirtualRF is used for testing.
"""

import asyncio
from unittest.mock import patch

import pytest
import serial

from ramses_rf import Code, Command, Device, Gateway
from tests_rf.virtual_rf import (
    CONFIG,
    MIN_GAP_BETWEEN_WRITES,
    VirtualRf,
    stifle_impersonation_alerts,
)

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


async def assert_code_in_device_msgz(
    gwy: Gateway,
    dev_id: str,
    code: Code,
    max_sleep: int = DEFAULT_MAX_SLEEP,
    test_not: bool = False,
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if ((dev := gwy.device_by_id.get(dev_id)) and (code in dev._msgz)) != test_not:
            break
    assert ((dev := gwy.device_by_id.get(dev_id)) and (code in dev._msgz)) != test_not


async def assert_devices(
    gwy: Gateway, devices: list[Device], max_sleep: int = DEFAULT_MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if len(gwy.devices) == len(devices):
            break
    assert sorted(d.id for d in gwy.devices) == sorted(devices)


async def assert_this_pkt(
    pkt_protocol, cmd: Command, max_sleep: int = DEFAULT_MAX_SLEEP
):
    for _ in range(int(max_sleep / ASSERT_CYCLE_TIME)):
        await asyncio.sleep(ASSERT_CYCLE_TIME)
        if pkt_protocol._this_pkt and pkt_protocol._this_pkt._frame == cmd._frame:
            break
    assert pkt_protocol._this_pkt and pkt_protocol._this_pkt._frame == cmd._frame


@pytest.mark.xdist_group(name="serial")
@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    stifle_impersonation_alerts,
)
@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def test_virtual_rf_dev_disc():
    """Check the virtual RF network behaves as expected (device discovery)."""

    rf = VirtualRf(3)

    # rf.set_gateway(rf.ports[0], "18:111111")
    # rf.set_gateway(rf.ports[1], "18:222222")

    gwy_0 = Gateway(rf.ports[0], **CONFIG)
    gwy_1 = Gateway(rf.ports[1], **CONFIG)
    ser_2 = serial.Serial(rf.ports[2])

    await assert_devices(gwy_0, [])
    await assert_devices(gwy_1, [])

    await gwy_0.start()

    await assert_devices(gwy_0, ["18:000730"])
    await assert_devices(gwy_1, [])

    await gwy_1.start()

    await assert_devices(gwy_0, ["18:000730"])
    await assert_devices(gwy_1, ["18:000730"])

    # TEST 1: Tx to all from GWY /dev/pty/0 (NB: no RSSI)
    cmd = Command("RP --- 01:111111 --:------ 01:111111 1F09 003 0004B5")
    gwy_0.send_cmd(cmd)

    await assert_devices(gwy_0, ["18:000730", "01:111111"])
    await assert_devices(gwy_1, ["18:000730", "01:111111"])

    # TEST 2: Tx to all from non-GWY /dev/pty/2 (NB: no RSSI)
    cmd = Command("RP --- 01:222222 --:------ 01:222222 1F09 003 0004B5")
    ser_2.write(bytes(f"{cmd}\r\n".encode("ascii")))

    await assert_devices(gwy_0, ["18:000730", "01:111111", "01:222222"])
    await assert_devices(gwy_1, ["18:000730", "01:111111", "01:222222"])

    # TEST 3: Rx only by one GWY /dev/pty/0 (needs RSSI)
    cmd = Command("RP --- 01:333333 --:------ 01:333333 1F09 003 0004B5")
    list(rf._file_objs.values())[0].write(bytes(f"000 {cmd}\r\n".encode("ascii")))

    await assert_devices(gwy_0, ["18:000730", "01:111111", "01:222222", "01:333333"])
    await assert_devices(gwy_1, ["18:000730", "01:111111", "01:222222"])

    await gwy_0.stop()
    await gwy_1.stop()
    await rf.stop()


@pytest.mark.xdist_group(name="serial")
@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    stifle_impersonation_alerts,
)
@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def test_virtual_rf_pkt_flow():
    """Check the virtual RF network behaves as expected (packet flow)."""

    rf = VirtualRf(2)

    # rf.set_gateway(rf.ports[0], "18:111111")
    # rf.set_gateway(rf.ports[1], "18:222222")

    gwy_0 = Gateway(rf.ports[0], **CONFIG, **SCHEMA_0)
    gwy_1 = Gateway(rf.ports[1], **CONFIG, **SCHEMA_1)

    await gwy_0.start()
    await gwy_1.start()

    # await assert_devices(gwy_0, ["18:000730", "41:111111"])
    # await assert_devices(gwy_1, ["18:000730", "42:222222"])

    # TEST 1:
    await assert_code_in_device_msgz(
        gwy_0, "01:333333", Code._1F09, max_sleep=0, test_not=True
    )  # device wont exist

    cmd = Command(
        "RP --- 01:333333 --:------ 01:333333 1F09 003 0004B5", qos={"retries": 0}
    )  # no retries, otherwise long duration
    gwy_0.send_cmd(cmd)

    await assert_code_in_device_msgz(gwy_0, "01:333333", Code._1F09)

    await assert_this_pkt(gwy_0.pkt_protocol, cmd)
    await assert_this_pkt(gwy_1.pkt_protocol, cmd)

    # TEST 2:
    await assert_code_in_device_msgz(
        gwy_0, "41:111111", Code._22F1, max_sleep=0, test_not=True
    )

    cmd = Command(
        " I --- 41:111111 --:------ 41:111111 22F1 003 000507", qos={"retries": 0}
    )  # no retries, otherwise long duration
    gwy_0.send_cmd(cmd)

    await assert_code_in_device_msgz(gwy_0, "41:111111", Code._22F1)

    await assert_this_pkt(gwy_0.pkt_protocol, cmd)
    await assert_this_pkt(gwy_1.pkt_protocol, cmd)

    # await assert_devices(gwy_0, ["18:000730", "01:333333", "41:111111"])
    # await assert_devices(gwy_1, ["18:000730", "01:333333", "41:111111", "42:222222"])

    await gwy_0.stop()
    await gwy_1.stop()
    await rf.stop()
