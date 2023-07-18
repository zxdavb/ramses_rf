#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - A pseudo-mocked serial port used for testing."""

from functools import wraps
from typing import Any, Callable, Coroutine
from unittest.mock import patch

from ramses_rf import Command, Gateway

from .helpers import ensure_fakeable  # noqa: F401, pylint: disable=unused-import
from .virtual_rf import HgiFwTypes  # noqa: F401, pylint: disable=unused-import
from .virtual_rf import VirtualRf

GWY_ID_0 = "18:000000"
GWY_ID_1 = "18:111111"

DEFAULT_GWY_CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}

MIN_GAP_BETWEEN_WRITES = 0.005  # patch ramses_rf.protocol.protocol


async def stifle_impersonation_alert(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


def _rf_net_create(
    schema_0: dict, schema_1: dict
) -> tuple[VirtualRf, Gateway, Gateway]:
    """Create a VirtualRf network with two well-known gateways."""

    rf = VirtualRf(2, start=False)

    rf.set_gateway(rf.ports[0], GWY_ID_0)
    rf.set_gateway(rf.ports[1], GWY_ID_1)

    gwy_0 = Gateway(rf.ports[0], **DEFAULT_GWY_CONFIG, **schema_0)
    gwy_1 = Gateway(rf.ports[1], **DEFAULT_GWY_CONFIG, **schema_1)

    rf.start()

    # try:
    #     fnc(gwy_0, gwy_1, *args, **kwargs)
    # finally:
    #     await rf_net_stop(rf, gwy_0, gwy_1)

    return rf, gwy_0, gwy_1


async def _rf_net_cleanup(rf: VirtualRf, gwy_0: Gateway, gwy_1: Gateway) -> None:
    """Cleanly destroy a VirtualRf network with two gateways."""

    await gwy_0.stop()
    await gwy_1.stop()

    await rf.stop()


def factory(schema_0: dict, schema_1: dict) -> Callable:
    """Create a decorator with a two-gateway VirtualRf (18:000000, 18:111111)."""

    # result = await? factory(schema_0, schema_1)(fnc)(gwy_0, gwy_1, *args, **kwargs)

    def decorator(fnc) -> Coroutine:
        """Wrap the decorated function as below and return the result."""

        @patch(  # stifle_impersonation_alert()
            "ramses_rf.protocol.protocol._ProtImpersonate._send_impersonation_alert",
            stifle_impersonation_alert,
        )
        @patch(
            "ramses_rf.protocol.protocol.MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES
        )
        @wraps(fnc)
        async def wrapper(*args, **kwargs) -> Any:
            rf, gwy_0, gwy_1 = _rf_net_create(schema_0, schema_1)

            await gwy_0.start()
            await gwy_1.start()

            try:  # enclose the decorated function in the wrapper
                return await fnc(gwy_0, gwy_1, *args, *kwargs)  # asserts within here
            finally:
                await _rf_net_cleanup(rf, gwy_0, gwy_1)

        return wrapper

    return decorator
