#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""

import logging

from ..const import DEV_KLASS, __dev_mode__
from ..protocol.address import id_to_address
from ..protocol.message import Message
from .base import _CLASS_BY_KLASS as _BASE_CLASS_BY_KLASS
from .const import Discover
from .entity_base import Entity, class_by_attr, discover_decorator
from .heat import _CLASS_BY_KLASS as _HEAT_CLASS_BY_KLASS
from .heat import _KLASS_BY_TYPE
from .hvac import _CLASS_BY_KLASS as _HVAC_CLASS_BY_KLASS
from .hvac import _best_hvac_klass

from .base import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    Device,
    HeatDevice,
    HgiGateway,
    HvacDevice,
)
from .heat import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    BdrSwitch,
    Controller,
    DhwSensor,
    OtbGateway,
    OutSensor,
    Programmer,
    RfgGateway,
    Thermostat,
    TrvActuator,
    UfhController,
)
from .hvac import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    HvacCarbonDioxide,
    HvacHumidity,
    HvacSwitch,
    HvacVentilator,
    RfsGateway,
)

_CLASS_BY_KLASS = _BASE_CLASS_BY_KLASS | _HEAT_CLASS_BY_KLASS | _HVAC_CLASS_BY_KLASS

DEV_MODE = __dev_mode__  # and False
OTB_MODE = False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def _best_device_klass(dev_id: str, msg: Message, eavesdrop: bool = None) -> str:
    """Return the most approprite device class."""

    if klass := _best_hvac_klass(dev_id[:2], msg):
        (_LOGGER.error if DEV_MODE else _LOGGER.warning)(
            f"Using an eavesdropped class for: {dev_id} ({klass}): is/could be HVAC"
        )

    if klass is None:
        klass = _KLASS_BY_TYPE.get(dev_id[:2], DEV_KLASS.DEV)
        _LOGGER.debug(f"Using the default device class for: {dev_id} ({klass})")

    return klass


def create_device(
    gwy, dev_id: str, klass: str = None, msg: Message = None, **kwargs
) -> Device:
    """Create a device, and optionally perform discovery & start polling."""

    if klass is None:
        klass = _best_device_klass(dev_id, msg, eavesdrop=gwy.config.enable_eavesdrop)

    device = _CLASS_BY_KLASS[klass](gwy, id_to_address(dev_id), msg=msg, **kwargs)

    if not gwy.config.disable_discovery:
        device._start_discovery()

    return device


if False and DEV_MODE:
    # check that each entity with a non-null _STATE_ATTR has that attr
    [
        d
        for d in class_by_attr(__name__, "_STATE_ATTR").values()
        if d._STATE_ATTR and getattr(d, d._STATE_ATTR)
    ]
