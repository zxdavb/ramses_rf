#!/usr/bin/env python3
#
"""RAMSES RF - Check get/set of zone/DHW schedules."""

import asyncio
from typing import Any

import pytest

from ramses_rf import Gateway
from ramses_rf.device import Controller
from ramses_rf.system import Evohome, Zone
from ramses_tx.address import HGI_DEVICE_ID
from ramses_tx.schemas import DeviceIdT

# ### FIXTURES #########################################################################

pytestmark = pytest.mark.asyncio()  # scope="module")


@pytest.fixture()  # scope="module")
def gwy_config() -> dict[str, Any]:
    return {
        "config": {
            "disable_discovery": True,
            "disable_qos": False,  # this is required for this test
            "enforce_known_list": False,
        },
        "known_list": {HGI_DEVICE_ID: {}},  # req'd to thwart foreign HGI blacklisting
    }


#######################################################################################


@pytest.mark.xdist_group(name="virt_serial")
async def _test_get_schedule(gwy: Gateway, ctl_id: DeviceIdT, idx: str) -> None:
    """Test obtaining the version and schedule."""

    assert gwy._loop is asyncio.get_running_loop()  # scope BUG is here

    _: Controller = gwy.get_device(ctl_id)

    tcs: Evohome = gwy.tcs
    global_ver, did_io = await tcs._schedule_version()
    assert isinstance(global_ver, int) and did_io

    zon: Zone = tcs.get_htg_zone(idx)
    schedule: dict[str, Any] = await zon.get_schedule()
    assert len(schedule) == 7  # days of week


#######################################################################################


@pytest.mark.xdist_group(name="real_serial")
async def _test_get_schedule_mqtt(mqtt_evofw3: Gateway) -> None:
    """Test obtaining the schedule from a real controller via MQTT."""

    await _test_get_schedule(mqtt_evofw3, "01:145038", "01")


@pytest.mark.xdist_group(name="real_serial")
async def test_get_schedule_real(real_evofw3: Gateway) -> None:
    """Test obtaining the schedule from a real controller via RF."""

    await _test_get_schedule(real_evofw3, "01:145038", "01")
