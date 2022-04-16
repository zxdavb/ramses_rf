#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""

import logging
from symtable import Class

from .const import __dev_mode__
from .protocol import Address, Message
from .schema import SZ_CLASS

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    DEV_ROLE_MAP,
    DEV_TYPE_MAP,
    ZON_CLASS_MAP,
)

# skipcq: PY-W2000
from .devices_base import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    BASE_CLASS_BY_SLUG,
    Device,
    HeatDevice,
    HgiGateway,
    HvacDevice,
)

# skipcq: PY-W2000
from .devices_heat import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    HEAT_CLASS_BY_SLUG,
    BdrSwitch,
    Controller,
    DhwSensor,
    Discover,
    OtbGateway,
    Temperature,
    TrvActuator,
    UfhController,
    class_dev_heat,
)

# skipcq: PY-W2000
from .devices_hvac import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    HVAC_CLASS_BY_SLUG,
    class_dev_hvac,
)

DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


_CLASS_BY_SLUG = BASE_CLASS_BY_SLUG | HEAT_CLASS_BY_SLUG | HVAC_CLASS_BY_SLUG


def device_role_best(
    dev_addr: Address,
    msg: Message = None,
    eavesdrop: bool = False,
    **schema,
) -> Class:
    """Return the best device role for a given device id/msg/schema."""

    # a specified device class always takes precidence (even if it is wrong)...
    if klass := _CLASS_BY_SLUG.get(schema.get(SZ_CLASS)):
        _LOGGER.debug(f"Using configured dev class for: {dev_addr} ({klass})")
        return klass

    if dev_addr.type == DEV_TYPE_MAP.HGI:
        _LOGGER.debug(f"Using default dev class for: {dev_addr} ({HgiGateway})")
        return HgiGateway

    try:  # or, is it a well-known CH/DHW class, derived from the device type...
        if klass := class_dev_heat(dev_addr, msg=msg, eavesdrop=eavesdrop):
            _LOGGER.debug(f"Using default dev class for: {dev_addr} ({klass})")
            return klass  # includes HeatDevice
    except TypeError:
        pass

    try:  # or, a HVAC class, eavesdropped from the message code/payload...
        if klass := class_dev_hvac(dev_addr, msg=msg, eavesdrop=eavesdrop):
            _LOGGER.warning(f"Using eavesdropped dev class for: {dev_addr} ({klass})")
            return klass  # includes HvacDevice
    except TypeError:
        pass

    # otherwise, use the default device class...
    _LOGGER.warning(f"Using generic dev class for: {dev_addr} ({Device})")
    return Device


def zx_device_factory(gwy, dev_addr: Address, msg: Message = None, **schema) -> Class:
    """Return the initial device class for a given device id/msg/schema.

    Some devices are promotable to s compatibel sub class.
    """

    return device_role_best(
        dev_addr,
        msg=msg,
        eavesdrop=gwy.config.enable_eavesdrop,
        **schema,
    ).zx_create_from_schema(gwy, dev_addr, **schema)
