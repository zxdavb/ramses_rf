#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Test the binding protocol."""

import asyncio
from concurrent import futures
from unittest.mock import patch

from ramses_rf import Gateway
from ramses_rf.const import Code
from ramses_rf.protocol.command import Command
from tests.virtual_rf import VirtualRF

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


@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    _alert_is_impersonating,
)
async def test_virtual_rf():
    """Check the virtual RF network behaves as expected."""

    rf = VirtualRF(2)
    await rf.start()

    gwy_0 = Gateway(rf.ports[0], **CONFIG, **SCHEMA_0)
    assert gwy_0._schema["orphans_hvac"] == SCHEMA_0["orphans_hvac"]
    await gwy_0.start()

    gwy_1 = Gateway(rf.ports[1], **CONFIG, **SCHEMA_1)
    assert gwy_1._schema["orphans_hvac"] == SCHEMA_1["orphans_hvac"]
    await gwy_1.start()

    cmd = Command(" I --- 41:111111 --:------ 41:111111 22F1 003 000507")
    fut = gwy_0.send_cmd(cmd)
    assert Code._22F1 not in gwy_0.devices[0]._msgz

    await asyncio.sleep(0.1)  # TODO: should accept 0.005
    futures.wait([fut])  # NOTE: is not asynchronous
    assert Code._22F1 in gwy_0.devices[0]._msgz

    assert gwy_1.pkt_protocol._this_pkt._frame == cmd._frame

    cmd = Command(" I --- 01:333333 --:------ 01:333333 1F09 003 FF04B5")
    fut = gwy_0.send_cmd(cmd)

    await asyncio.sleep(0.3)  # TODO: should accept 0.005
    futures.wait([fut])  # NOTE: is not asynchronous

    await asyncio.sleep(0.3)  # TODO: should accept 0.005
    assert gwy_1.pkt_protocol._this_pkt._frame == cmd._frame

    assert len(gwy_0.devices) == 2
    assert len(gwy_1.devices) == 3

    await gwy_0.stop()
    await gwy_1.stop()

    await rf.stop()
