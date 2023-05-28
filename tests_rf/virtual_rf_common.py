#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

from typing import Callable, TypeVar
from unittest.mock import patch

from ramses_rf import Command, Device, Gateway
from ramses_rf.device import Fakeable
from ramses_rf.protocol import Address
from tests_rf.virtual_rf import VirtualRf

MIN_GAP_BETWEEN_WRITES = 0

CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}


class FakeableDevice(Address, Fakeable):  # for mypy typing
    _gwy: Gateway


_Faked = TypeVar("_Faked", bound="FakeableDevice")


def make_device_fakeable(dev: Device) -> None:
    """If a Device is not Fakeable, make it so."""

    class FakeableDevice(dev.__class__, Fakeable):
        pass

    dev.__class__ = FakeableDevice
    setattr(dev, "_faked", None)
    setattr(dev, "_context", None)
    setattr(dev, "_1fc9_state", {})


async def stifle_impersonation_alerts(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    stifle_impersonation_alerts,
)
@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def binding_test_wrapper(
    fnc: Callable, supp_schema: dict, resp_schema: dict, codes: tuple
):
    rf = VirtualRf(2)

    rf.set_gateway(rf.ports[0], "18:111111")
    rf.set_gateway(rf.ports[1], "18:222222")

    gwy_0 = Gateway(rf.ports[0], **CONFIG, **supp_schema)
    gwy_1 = Gateway(rf.ports[1], **CONFIG, **resp_schema)

    await gwy_0.start()
    await gwy_1.start()

    supplicant = gwy_0.device_by_id[supp_schema["orphans_hvac"][0]]
    respondent = gwy_1.device_by_id[resp_schema["orphans_hvac"][0]]

    if not isinstance(respondent, Fakeable):  # likely respondent is not fakeable...
        make_device_fakeable(respondent)

    await fnc(supplicant, respondent, codes)

    await gwy_0.stop()
    await gwy_1.stop()
    await rf.stop()
