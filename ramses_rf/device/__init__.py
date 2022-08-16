#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""
from __future__ import annotations

import logging

from ..const import DEV_TYPE_MAP, __dev_mode__
from ..protocol import Address, Message
from ..schemas import SZ_CLASS, SZ_FAKED

# skipcq: PY-W2000
from ..const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
)

# skipcq: PY-W2000
from .base import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    BASE_CLASS_BY_SLUG,
    Device,
    Fakeable,
    DeviceHeat,
    HgiGateway,
    DeviceHvac,
)

# skipcq: PY-W2000
from .heat import (  # noqa: F401, isort: skip, pylint: disable=unused-import
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
from .hvac import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    HVAC_CLASS_BY_SLUG,
    HvacCarbonDioxideSensor,
    HvacHumiditySensor,
    HvacRemote,
    HvacVentilator,
    RfsGateway,
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
) -> type[Device]:
    """Return the best device role (object class) for a given device id/msg/schema.

    Heat (CH/DHW) devices can reliably be determined by their address type (e.g. '04:').
    Any device without a known Heat type is considered a HVAC device.

    HVAC devices must be explicity typed, or fingerprinted/eavesdropped.
    The generic HVAC class can be promoted later on, when more information is available.
    """

    cls: None | type[Device] = None
    slug: None | str = None

    try:  # convert (say) 'dhw_sensor' to DHW
        slug = DEV_TYPE_MAP.slug(schema.get(SZ_CLASS))
    except KeyError:
        slug = schema.get(SZ_CLASS)

    # a specified device class always takes precidence (even if it is wrong)...
    if cls := _CLASS_BY_SLUG.get(slug):
        _LOGGER.debug(
            f"Using an explicitly-defined class for: {dev_addr!r} ({cls._SLUG})"
        )
        return cls

    if dev_addr.type == DEV_TYPE_MAP.HGI:
        _LOGGER.debug(f"Using the default class for: {dev_addr!r} ({HgiGateway._SLUG})")
        return HgiGateway  # type: ignore[return-value]

    try:  # or, is it a well-known CH/DHW class, derived from the device type...
        if cls := class_dev_heat(dev_addr, msg=msg, eavesdrop=eavesdrop):
            _LOGGER.debug(
                f"Using the default Heat class for: {dev_addr!r} ({cls._SLUG})"  # type: ignore[attr-defined]
            )
            return cls
    except TypeError:
        pass

    try:  # or, a HVAC class, eavesdropped from the message code/payload...
        if cls := class_dev_hvac(dev_addr, msg=msg, eavesdrop=eavesdrop):
            _LOGGER.debug(
                f"Using eavesdropped HVAC class for: {dev_addr!r} ({cls._SLUG})"  # type: ignore[attr-defined]
            )
            return cls  # includes DeviceHvac
    except TypeError:
        pass

    # otherwise, use the default device class...
    _LOGGER.debug(
        f"Using a promotable HVAC class for: {dev_addr!r} ({DeviceHvac._SLUG})"
    )
    return DeviceHvac  # type: ignore[return-value]


def device_factory(gwy, dev_addr: Address, *, msg: Message = None, **traits) -> Device:
    """Return the initial device class for a given device id/msg/traits.

    Devices of certain classes are promotable to a compatible sub class.
    """

    cls: type[Device] = best_dev_role(
        dev_addr,
        msg=msg,
        eavesdrop=gwy.config.enable_eavesdrop,
        **traits,
    )

    if (
        isinstance(cls, DeviceHvac)
        and traits.get(SZ_CLASS) in (DEV_TYPE_MAP.HVC, None)
        and traits.get(SZ_FAKED)
    ):
        raise TypeError(
            "Faked devices from the HVAC domain must have an explicit class: {dev_addr}"
        )

    return cls.create_from_schema(gwy, dev_addr, **traits)
