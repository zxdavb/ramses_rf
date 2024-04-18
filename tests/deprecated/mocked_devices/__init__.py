#!/usr/bin/env python3
"""RAMSES RF - A pseudo-mocked serial port used for testing."""

import logging

from ramses_rf import Gateway

from .const import (  # noqa: F401, pylint: disable=unused-import
    MOCKED_PORT,
    __dev_mode__,
)
from .device_heat import (  # noqa: F401, F811, pylint: disable=unused-import
    CTL_ID,
    THM_ID,
    MockDeviceCtl,
    MockDeviceThm,
)
from .device_hvac import (  # noqa: F401, F811, pylint: disable=unused-import
    FAN_ID,
    MockDeviceFan,
)
from .transport import create_pkt_stack

DEV_MODE = __dev_mode__


_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class MockGateway(Gateway):  # to use a bespoke create_pkt_stack()
    _create_pkt_stack = create_pkt_stack
