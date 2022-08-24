#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test faking of Heat devices.
"""

import asyncio

from ramses_rf.const import Code
from ramses_rf.device import HvacRemote, HvacVentilator
from ramses_rf.device.base import BindState, Fakeable
from tests_rf.common import MockGateway, abort_if_rf_test_fails, load_test_gwy


class HvacVentilatorFakable(HvacVentilator, Fakeable):
    pass


def pytest_generate_tests(metafunc):
    test_ports = {"/dev/ttyMOCK": MockGateway}  # don't use: from tests_rf.common...

    metafunc.parametrize("test_port", test_ports.items(), ids=test_ports.keys())


@abort_if_rf_test_fails
async def test_hvac_bind_remote(test_port):
    config = {
        "config": {"enable_eavesdrop": False, "enforce_known_list": True},
        "orphans_hvac": ["21:111111", "32:222222"],
        "known_list": {
            "21:111111": {"class": "FAN"},
            "32:222222": {"class": "REM", "faked": True},
        },
    }

    gwy = await load_test_gwy(*test_port, None, **config)

    fan: HvacVentilator = gwy.device_by_id["21:111111"]

    # make an unfakeable, fakeable...
    fan.__class__ = HvacVentilatorFakable
    setattr(fan, "_faked", None)
    setattr(fan, "_1fc9_state", {"state": BindState.UNKNOWN})

    fan._make_fake()
    fan._bind_waiting(Code._22F1)

    rem: HvacRemote = gwy.device_by_id["32:222222"]
    rem._bind()
    await asyncio.sleep(60)

    await gwy.stop()
