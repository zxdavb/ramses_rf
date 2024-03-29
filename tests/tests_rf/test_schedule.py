#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Check get/set of zone/DHW schedules."""

from typing import Any

import pytest
from serial.tools.list_ports import comports

from ramses_rf import Gateway
from ramses_rf.device import Controller
from ramses_rf.system import Evohome, Zone

#
GWY_CONFIG = {
    "config": {
        "disable_discovery": True,
        "disable_qos": False,  # this is required for this test
        "enforce_known_list": False,
    },
    "known_list": {"18:000730": {}},  # required to thwart foreign HGI blacklisting
}


#######################################################################################


@pytest.mark.xdist_group(name="virt_serial")
async def _test_get_schedule(gwy: Gateway, ctl_id: str, idx: str):
    """Test obtaining the schedule version."""

    await gwy.start()

    # TODO: These values should be asserted in protocol FSM tests
    assert gwy._protocol._context.echo_timeout == 0.5
    assert gwy._protocol._context.reply_timeout == 0.2
    assert gwy._protocol._context.SEND_TIMEOUT_LIMIT == 15.0

    _: Controller = gwy.get_device(ctl_id)

    tcs: Evohome = gwy.tcs
    global_ver, did_io = await tcs._schedule_version()
    assert isinstance(global_ver, int) and did_io

    zon: Zone = tcs.get_htg_zone(idx)
    schedule: dict[str, Any] = await zon.get_schedule()
    assert len(schedule) == 7  # days of week


#######################################################################################


@pytest.mark.xdist_group(name="real_serial")
@pytest.mark.skipif(
    not [p for p in comports() if p.name in ("ttyACM0", "ttyUSB0")],
    reason="No evofw3 devices found",
)
async def test_get_schedule_real():
    """Test obtaining the schedule version from a real controller."""

    ports = [p.device for p in comports() if p.name in ("ttyACM0", "ttyUSB0")]

    try:
        gwy = Gateway(ports[0], **GWY_CONFIG)
        await _test_get_schedule(gwy, "01:145038", "01")

    finally:
        if gwy:
            await gwy.stop()
