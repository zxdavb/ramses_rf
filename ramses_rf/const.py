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

# Status codes for Worcester Bosch boilers - OT|OEM diagnostic code
WB_STATUS_CODES = {
    "200": "CH system is being heated.",
    "201": "DHW system is being heated.",
    "202": "Anti rapid cycle mode. The boiler has commenced anti-cycle period for CH.",
    "203": "System stand by",
    "204": "System waiting, appliance waiting for heating system to cool.",
    "208": "Appliance in service Test mode (Min/Max)",
    "265": "EMS controller has forced stand-by-mode due to low heating load (power required is less than the minimum output)",
    "268": "Component test mode (is running the manual component test as activated in the menus).",
    "270": "Power up mode (appliance is powering up).",
    "283": "Burner starting. The fan and the pump are being controlled.",
    "284": "Gas valve(s) opened, flame must be detected within safety time. The gas valve is being controlled.",
    "305": "Anti fast cycle mode (DHW keep warm function). Diverter valve is held in DHW position for a period of time after DHW demand.",
    "357": "Appliance in air purge mode. Primary heat exchanger air venting program active - approximately 100 seconds.",
    "358": "Three way valve kick. If the 3-way valve hasn't moved in within 48 hours, the valve will operate once to prevent seizure",
}
