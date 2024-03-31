#!/usr/bin/env python3
#
"""RAMSES RF - Check get of TCS fault logs."""

import asyncio

import pytest

from ramses_rf import Gateway
from ramses_rf.device import Controller
from ramses_rf.system import Evohome
from ramses_tx.address import HGI_DEVICE_ID
from ramses_tx.schemas import DeviceIdT

# ### FIXTURES #########################################################################

# pytestmark = pytest.mark.asyncio(scope="session")


@pytest.fixture(scope="session")
def gwy_config():
    return {
        "config": {
            "disable_discovery": True,
            "disable_qos": False,  # this is required for this test
            "enforce_known_list": False,
        },
        "known_list": {HGI_DEVICE_ID: {}},  # req'd to thwart foreign HGI blacklisting
    }


#######################################################################################


async def _test_get_faultlog(gwy: Gateway, ctl_id: DeviceIdT):
    """Test obtaining the fault log."""

    assert gwy._loop is asyncio.get_running_loop()  # BUG is here

    # TODO: These values should be asserted in protocol FSM tests
    assert gwy._protocol._context.echo_timeout == 0.5
    assert gwy._protocol._context.reply_timeout == 0.2
    assert gwy._protocol._context.SEND_TIMEOUT_LIMIT == 15.0

    _: Controller = gwy.get_device(ctl_id)

    tcs: Evohome = gwy.tcs
    faultlog = await tcs.get_faultlog()
    assert faultlog


#######################################################################################


@pytest.mark.xdist_group(name="real_serial")
async def test_get_faultlog_real(real_evofw3: Gateway):
    """Test obtaining the fault log from a real controller."""

    await _test_get_faultlog(real_evofw3, "01:145038")
