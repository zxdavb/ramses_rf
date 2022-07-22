#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""
from __future__ import annotations

from types import SimpleNamespace

from .protocol.const import (  # noqa: F401
    DEFAULT_MAX_ZONES,
    DEVICE_ID_REGEX,
    DOMAIN_TYPE_MAP,
    FAN_MODE,
    SYS_MODE_MAP,
    SZ_ACTUATORS,
    SZ_AIR_QUALITY,
    SZ_AIR_QUALITY_BASE,
    SZ_BOOST_TIMER,
    SZ_BYPASS_POSITION,
    SZ_CHANGE_COUNTER,
    SZ_CO2_LEVEL,
    SZ_DATETIME,
    SZ_DEVICE_ID,
    SZ_DEVICE_ROLE,
    SZ_DEVICES,
    SZ_DHW_IDX,
    SZ_DOMAIN_ID,
    SZ_DURATION,
    SZ_EXHAUST_FAN_SPEED,
    SZ_EXHAUST_FLOW,
    SZ_EXHAUST_TEMPERATURE,
    SZ_FAN_INFO,
    SZ_FAN_MODE,
    SZ_FRAG_LENGTH,
    SZ_FRAG_NUMBER,
    SZ_FRAGMENT,
    SZ_HEAT_DEMAND,
    SZ_INDOOR_HUMIDITY,
    SZ_INDOOR_TEMPERATURE,
    SZ_LANGUAGE,
    SZ_MODE,
    SZ_NAME,
    SZ_OUTDOOR_HUMIDITY,
    SZ_OUTDOOR_TEMPERATURE,
    SZ_PAYLOAD,
    SZ_POST_HEAT,
    SZ_PRE_HEAT,
    SZ_PRESSURE,
    SZ_PRIORITY,
    SZ_RELAY_DEMAND,
    SZ_RELAY_FAILSAFE,
    SZ_REMAINING_TIME,
    SZ_RETRIES,
    SZ_SCHEDULE,
    SZ_SENSOR,
    SZ_SETPOINT,
    SZ_SPEED_CAP,
    SZ_SUPPLY_FAN_SPEED,
    SZ_SUPPLY_FLOW,
    SZ_SUPPLY_TEMPERATURE,
    SZ_SYSTEM_MODE,
    SZ_TEMPERATURE,
    SZ_TOTAL_FRAGS,
    SZ_UFH_IDX,
    SZ_UNKNOWN,
    SZ_UNTIL,
    SZ_VALUE,
    SZ_WINDOW_OPEN,
    SZ_ZONE_CLASS,
    SZ_ZONE_IDX,
    SZ_ZONE_MASK,
    SZ_ZONE_TYPE,
    SZ_ZONES,
    ZON_MODE_MAP,
    SystemType,
)

# skipcq: PY-W2000
from .protocol import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    F9,
    FA,
    FC,
    FF,
    DEV_ROLE,
    DEV_ROLE_MAP,
    DEV_TYPE,
    DEV_TYPE_MAP,
    ZON_ROLE,
    ZON_ROLE_MAP,
    Code,
)


__dev_mode__ = False
# DEV_MODE = __dev_mode__

Discover = SimpleNamespace(
    NOTHING=0,
    SCHEMA=1,
    PARAMS=2,
    STATUS=4,
    FAULTS=8,
    SCHEDS=16,
    TRAITS=32,
    DEFAULT=(1 + 2 + 4),
)

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

SCHED_REFRESH_INTERVAL = 3  # minutes

# Status codes for Worcester Bosch boilers - OT|OEM diagnostic code
WB_STATUS_CODES = {
    "200": "CH system is being heated.",
    "201": "DHW system is being heated.",
    "202": "Anti rapid cycle mode. The boiler has commenced anti-cycle period for CH.",
    "203": "System standby mode.",
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
