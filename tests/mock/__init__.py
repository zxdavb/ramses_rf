#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

A pseudo-mocked serial port used for testing.
"""

import logging

from ramses_rf import Gateway

from .const import (  # noqa: F401, pylint: disable=unused-import
    MOCKED_PORT,
    __dev_mode__,
)
from .device import (  # noqa: F401, F811, pylint: disable=unused-import
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
    def _start(self) -> None:
        """Initiate ad-hoc sending, and (polled) receiving."""

        (_LOGGER.warning if DEV_MODE else _LOGGER.debug)("ENGINE: Starting poller...")

        pkt_receiver = (
            self.msg_transport.get_extra_info(self.msg_transport.READER)
            if self.msg_transport
            else None
        )
        self.pkt_protocol, self.pkt_transport = create_pkt_stack(
            self, pkt_receiver, ser_port=self.ser_name
        )  # TODO: can raise SerialException
        if self.msg_transport:
            self.msg_transport._set_dispatcher(self.pkt_protocol.send_data)
