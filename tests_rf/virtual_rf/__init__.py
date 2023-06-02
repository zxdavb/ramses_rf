#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - A pseudo-mocked serial port used for testing."""

from functools import wraps
from typing import Any, Callable, Coroutine
from unittest.mock import patch

from ramses_rf import Command, Gateway

from .helpers import (  # noqa: F401, pylint: disable=unused-import
    FakeableDevice,
    make_device_fakeable,
)
from .virtual_rf import HgiFwTypes  # noqa: F401, pylint: disable=unused-import
from .virtual_rf import VirtualRf

MIN_GAP_BETWEEN_WRITES = 0

CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}


async def stifle_impersonation_alert(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


def factory(schema_0: dict, schema_1: dict) -> Callable:
    """Create a decorator with a two-gateway virtual RF: 18:111111 & 18:222222."""

    # result = rf_factory(schema_0, schema_1)(fnc)(gwy_0, gwy_1, *args, **kwargs)

    def decorator(fnc) -> Coroutine:
        @patch(  # stifle_impersonation_alert()
            "ramses_rf.protocol.protocol_new._ProtImpersonate._send_impersonation_alert",
            stifle_impersonation_alert,
        )
        @patch(  # MIN_GAP_BETWEEN_WRITES = 0
            "ramses_rf.protocol.transport_new.MIN_GAP_BETWEEN_WRITES",
            MIN_GAP_BETWEEN_WRITES,
        )
        @wraps(fnc)
        async def wrapper(*args, **kwargs) -> Any:
            rf = VirtualRf(2)

            rf.set_gateway(rf.ports[0], "18:111111")
            rf.set_gateway(rf.ports[1], "18:222222")

            gwy_0 = Gateway(rf.ports[0], **CONFIG, **schema_0)
            gwy_1 = Gateway(rf.ports[1], **CONFIG, **schema_1)

            await gwy_0.start()
            await gwy_1.start()

            try:
                return await fnc(gwy_0, gwy_1, *args, *kwargs)  # asserts within here
            finally:
                await gwy_0.stop()
                await gwy_1.stop()

                await rf.stop()

        return wrapper

    return decorator
