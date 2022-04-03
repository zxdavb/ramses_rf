#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""

import logging
from symtable import Class

from .const import __dev_mode__
from .devices_base import Device
from .devices_heat import HEAT_CLASS_BY_KLASS
from .devices_heat import zx_device_factory as best_heat_klass
from .devices_hvac import HVAC_CLASS_BY_KLASS
from .devices_hvac import zx_device_factory as best_hvac_klass
from .protocol import Address, Message
from .schema import SZ_KLASS

DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


_CLASS_BY_KLASS = HEAT_CLASS_BY_KLASS | HVAC_CLASS_BY_KLASS


def zx_device_factory(
    dev_addr: Address, msg: Message = None, eavesdrop: bool = False, **schema
) -> Class:
    """Return the device class for a given device id/msg/schema."""

    # a specified device class always takes precidence (even if it is wrong)...
    if klass := _CLASS_BY_KLASS[schema.get(SZ_KLASS)]:
        _LOGGER.debug(f"Using configured device class for: {dev_addr} ({klass})")
        return klass

    try:  # or, is it a well-known CH/DHW class, derived from the device type...
        if klass := best_heat_klass(dev_addr.type, msg=msg, eavesdrop=eavesdrop):
            _LOGGER.debug(f"Using default CH/DHW class for: {dev_addr} ({klass})")
            return klass  # might be HeatDevice
    except TypeError:
        pass

    try:  # or, a HVAC class, eavesdropped from the message code/payload...
        if klass := best_hvac_klass(dev_addr.type, msg=msg, eavesdrop=eavesdrop):
            _LOGGER.warning(f"Using eavesdropped HVAC class for: {dev_addr} ({klass})")
            return klass  # might be HvacDevice
    except TypeError:
        pass

    # otherwise, use the default device class...
    _LOGGER.warning(f"Using generic device class for: {dev_addr} ({Device})")
    return Device
