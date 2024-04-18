#!/usr/bin/env python3
"""RAMSES RF - Check get of TCS fault logs."""

import asyncio

import pytest

from ramses_rf import Gateway
from ramses_rf.device import Controller
from ramses_rf.system import Evohome
from ramses_tx.address import HGI_DEVICE_ID
from ramses_tx.protocol import PortProtocol
from ramses_tx.schemas import DeviceIdT

from .conftest import _GwyConfigDictT

# ### FIXTURES #########################################################################

pytestmark = pytest.mark.asyncio()


@pytest.fixture()
def gwy_config() -> _GwyConfigDictT:
    return {
        "config": {
            "disable_discovery": True,
            "disable_qos": False,  # QoS is required for this test
            "enforce_known_list": False,
        },
        "known_list": {HGI_DEVICE_ID: {}},  # req'd to thwart foreign HGI blacklisting
    }


#######################################################################################


async def _test_get_faultlog(gwy: Gateway, ctl_id: DeviceIdT) -> None:
    """Test obtaining the fault log."""

    assert gwy._loop is asyncio.get_running_loop()  # scope BUG is here
    assert isinstance(gwy._protocol, PortProtocol)  # mypy
    assert gwy._protocol._disable_qos is False  # QoS is required for this test

    _: Controller = gwy.get_device(ctl_id)  # type: ignore[assignment]

    tcs: Evohome | None = gwy.tcs
    assert isinstance(tcs, Evohome)  # mypy

    faultlog = await tcs.get_faultlog()
    assert faultlog


#######################################################################################


@pytest.mark.xdist_group(name="real_serial")
async def test_get_faultlog_mqtt(mqtt_evofw3: Gateway) -> None:
    """Test obtaining the fault log from a real controller via MQTT."""

    await _test_get_faultlog(mqtt_evofw3, "01:145038")


@pytest.mark.xdist_group(name="real_serial")
async def test_get_faultlog_real(real_evofw3: Gateway) -> None:
    """Test obtaining the fault log from a real controller via RF."""

    await _test_get_faultlog(real_evofw3, "01:145038")
