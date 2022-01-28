#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

from types import SimpleNamespace

from .protocol.const import (  # noqa: F401
    _000C_DEVICE,
    _0005_ZONE,
    ATTR_DATETIME,
    ATTR_DEVICES,
    ATTR_HEAT_DEMAND,
    ATTR_LANGUAGE,
    ATTR_NAME,
    ATTR_RELAY_DEMAND,
    ATTR_RELAY_FAILSAFE,
    ATTR_SETPOINT,
    ATTR_SYSTEM_MODE,
    ATTR_TEMP,
    ATTR_WINDOW_OPEN,
    ATTR_ZONE_IDX,
    BOOST_TIMER,
    DEFAULT_MAX_ZONES,
    DEV_KLASS,
    DEVICE_ID_REGEX,
    DEVICE_TYPES,
    DOMAIN_TYPE_MAP,
    FAN_MODE,
    HGI_DEVICE_ID,
    NON_DEVICE_ID,
    NUL_DEVICE_ID,
    SYSTEM_MODE,
    ZONE_MODE,
    ZONE_TYPE_MAP,
    ZONE_TYPE_SLUGS,
    SystemType,
)

__dev_mode__ = False
DEV_MODE = __dev_mode__

Discover = SimpleNamespace(
    NOTHING=0, SCHEMA=1, PARAMS=2, STATUS=4, FAULTS=8, SCHEDS=16, ALL=(1 + 2 + 4)
)

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1
