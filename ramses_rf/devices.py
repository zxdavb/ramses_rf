#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""

import logging
from symtable import Class

from .const import DEV_TYPE_MAP, SZ_CLASS, __dev_mode__
from .protocol import Address, Message

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
)

# skipcq: PY-W2000
from .devices_base import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    BASE_CLASS_BY_SLUG,
    Device,
    DeviceHeat,
    HgiGateway,
    DeviceHvac,
)

# skipcq: PY-W2000
from .devices_heat import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    HEAT_CLASS_BY_SLUG,
    BdrSwitch,
    Controller,
    DhwSensor,
    OtbGateway,
    OutSensor,
    Temperature,
    Thermostat,
    TrvActuator,
    UfhCircuit,
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


def best_dev_role(
    dev_addr: Address,
    *,
    msg: Message = None,
    eavesdrop: bool = False,
    **schema,
) -> Class:
    """Return the best device role (object class) for a given device id/msg/schema.

    Heat (CH/DHW) devices can reliably be determined by their address type (e.g. '04:').
    Any device without a known Heat type is considered a HVAC device.

    HVAC devices must be explicity typed, or fingerprinted/eavesdropped.
    The generic HVAC class can be promoted later on, when more information is available.
    """

    cls: Device = None
    slug: str = None
    try:  # convert (say) 'dhw_sensor' to DHW
        slug = DEV_TYPE_MAP.slug(schema.get(SZ_CLASS))
    except KeyError:
        pass

    # a specified device class always takes precidence (even if it is wrong)...
    if cls := _CLASS_BY_SLUG.get(slug):
        _LOGGER.debug(
            f"Using an explicitly-defined class for: {dev_addr} ({cls._SLUG})"
        )
        return cls

    if dev_addr.type == DEV_TYPE_MAP.HGI:
        _LOGGER.debug(f"Using the default class for: {dev_addr} ({HgiGateway._SLUG})")
        return HgiGateway

    try:  # or, is it a well-known CH/DHW class, derived from the device type...
        if cls := class_dev_heat(dev_addr, msg=msg, eavesdrop=eavesdrop):
            _LOGGER.debug(f"Using the default Heat class for: {dev_addr} ({cls._SLUG})")
            return cls
    except TypeError:
        pass

    try:  # or, a HVAC class, eavesdropped from the message code/payload...
        if cls := class_dev_hvac(dev_addr, msg=msg, eavesdrop=eavesdrop):
            _LOGGER.debug(
                f"Using eavesdropped HVAC class for: {dev_addr} ({cls._SLUG})"
            )
            return cls  # includes DeviceHvac
    except TypeError:
        pass

    # otherwise, use the default device class...
    _LOGGER.debug(f"Using a promotable HVAC class for: {dev_addr} ({DeviceHvac._SLUG})")
    return DeviceHvac


def zx_device_factory(
    gwy, dev_addr: Address, *, msg: Message = None, **schema
) -> Device:
    """Return the initial device class for a given device id/msg/schema.

    Some devices are promotable to a compatible sub class.
    """

    return best_dev_role(
        dev_addr,
        msg=msg,
        eavesdrop=gwy.config.enable_eavesdrop,
        **schema,
    ).create_from_schema(gwy, dev_addr, **schema)
