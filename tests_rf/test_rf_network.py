#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol."""

import asyncio
from unittest.mock import patch

import serial

from ramses_rf import Gateway
from ramses_rf.const import Code
from ramses_rf.device import Device
from ramses_rf.protocol.command import Command
from tests_rf.virtual_rf import VirtualRF

MAX_SLEEP = 1

CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}
SCHEMA_0 = {
    "orphans_hvac": ["41:111111"],
    "known_list": {"41:111111": {"class": "REM"}},
}
SCHEMA_1 = {
    "orphans_hvac": ["42:222222"],
    "known_list": {"42:222222": {"class": "FAN"}},
}


async def _alert_is_impersonating(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


async def assert_code_in_device_msgz(
    gwy: Gateway,
    dev_id: str,
    code: Code,
    max_sleep: int = MAX_SLEEP,
    test_not: bool = False,
):
    for _ in range(int(max_sleep / 0.001)):
        await asyncio.sleep(0.001)
        if ((dev := gwy.device_by_id.get(dev_id)) and (code in dev._msgz)) != test_not:
            break
    assert ((dev := gwy.device_by_id.get(dev_id)) and (code in dev._msgz)) != test_not


async def assert_devices(
    gwy: Gateway, devices: list[Device], max_sleep: int = MAX_SLEEP
):
    for _ in range(int(max_sleep / 0.001)):
        await asyncio.sleep(0.001)
        if len(gwy.devices) == len(devices):
            break
    assert sorted(d.id for d in gwy.devices) == sorted(devices)


async def assert_this_pkt(pkt_protocol, cmd: Command, max_sleep: int = MAX_SLEEP):
    for _ in range(int(max_sleep / 0.001)):
        await asyncio.sleep(0.001)
        if pkt_protocol._this_pkt and pkt_protocol._this_pkt._frame == cmd._frame:
            break
    assert pkt_protocol._this_pkt and pkt_protocol._this_pkt._frame == cmd._frame


@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    _alert_is_impersonating,
)
@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", 0)
async def test_virtual_rf_1():
    """Check the virtual RF network behaves as expected (device discovery)."""

    rf = VirtualRF(3)
    await rf.start()

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


@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    _alert_is_impersonating,
)
@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", 0)
async def test_virtual_rf_2():
    """Check the virtual RF network behaves as expected (packet flow)."""

    rf = VirtualRF(2)
    await rf.start()

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
