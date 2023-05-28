#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - A pseudo-mocked serial port used for testing."""

from typing import Callable, TypeVar
from unittest.mock import patch

from ramses_rf import Gateway
from ramses_rf.device import Fakeable

from .helpers import CONFIG, MIN_GAP_BETWEEN_WRITES
from .helpers import FakeableDevice as _FakeableDevice
from .helpers import make_device_fakeable, stifle_impersonation_alerts
from .virtual_rf import HgiFwTypes  # noqa: F401, pylint: disable=unused-import
from .virtual_rf import VirtualRf

_Faked = TypeVar("_Faked", bound="_FakeableDevice")


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
