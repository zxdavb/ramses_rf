#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - Schema processor."""

import logging
import re
from typing import Tuple

import voluptuous as vol

from .const import ALL_DEVICE_ID as DEVICE_ID_REGEX
from .const import (
    ATTR_CONTROLLER,
    ATTR_DEVICES,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE,
    ATTR_DHW_VALVE_HTG,
    ATTR_HTG_CONTROL,
)
from .const import ATTR_STORED_HW as ATTR_DHW_SYSTEM
from .const import ATTR_UFH_HTG as ATTR_UFH_SYSTEM
from .const import ATTR_ZONE_IDX, ATTR_ZONE_SENSOR, ATTR_ZONE_TYPE, ATTR_ZONES
from .const import CTL_DEVICE_ID as CTL_DEVICE_ID_REGEX
from .const import DEFAULT_MAX_ZONES
from .const import DHW_SENSOR_ID as DHW_SENSOR_ID_REGEX
from .const import GWY_DEVICE_ID as GWY_DEVICE_ID_REGEX
from .const import HTG_DEVICE_ID as HTG_DEVICE_ID_REGEX
from .const import RLY_DEVICE_ID as RLY_DEVICE_ID_REGEX
from .const import UFC_DEVICE_ID as UFC_DEVICE_ID_REGEX
from .const import ZON_SENSOR_ID as SENSOR_ID_REGEX
from .const import ZONE_TYPE_SLUGS, __dev_mode__
from .const import id_to_address as addr

# schema attrs
ATTR_HTG_SYSTEM = "system"
ATTR_ORPHANS = "orphans"
ATTR_UFH_CTL = "ufh_controller"

DEVICE_ID = vol.Match(DEVICE_ID_REGEX)
SENSOR_ID = vol.Match(SENSOR_ID_REGEX)
CTL_DEVICE_ID = vol.Match(CTL_DEVICE_ID_REGEX)
DHW_SENSOR_ID = vol.Match(DHW_SENSOR_ID_REGEX)
GWY_DEVICE_ID = vol.Match(GWY_DEVICE_ID_REGEX)
HTG_DEVICE_ID = vol.Match(HTG_DEVICE_ID_REGEX)
UFC_DEVICE_ID = vol.Match(UFC_DEVICE_ID_REGEX)
RLY_DEVICE_ID = vol.Match(RLY_DEVICE_ID_REGEX)

ZONE_TYPE_SLUGS = list(ZONE_TYPE_SLUGS)

DOMAIN_ID = vol.Match(r"^[0-9A-F]{2}$")
UFH_IDX_REGEXP = r"^0[0-8]$"
UFH_IDX = vol.Match(UFH_IDX_REGEXP)
ZONE_IDX = vol.Match(r"^0[0-9AB]$")  # TODO: what if > 12 zones? (e.g. hometronics)

SER2NET_SCHEMA = vol.Schema(
    {vol.Required("enabled"): bool, vol.Optional("socket", default="0.0.0.0:5000"): str}
)

SERIAL_PORT = "serial_port"
INPUT_FILE = "input_file"
# Config parameters
CONFIG = "config"
DISABLE_DISCOVERY = "disable_discovery"
DISABLE_SENDING = "disable_sending"
ENABLE_EAVESDROP = "enable_eavesdrop"
ENFORCE_ALLOWLIST = "enforce_allowlist"
ENFORCE_BLOCKLIST = "enforce_blocklist"
EVOFW_FLAG = "evofw_flag"
LOG_ROTATE_BYTES = "log_rotate_bytes"
LOG_ROTATE_COUNT = "log_rotate_backups"
MAX_ZONES = "max_zones"
PACKET_LOG = "packet_log"  # output
REDUCE_PROCESSING = "reduce_processing"
SERIAL_CONFIG = "serial_config"
# SER2NET_RELAY = "ser2net_relay"
USE_NAMES = "use_names"  # use friendly device names from allow_list
USE_SCHEMA = "use_schema"

# Schema parameters
SCHEMA = "schema"
MAIN_CONTROLLER = "main_controller"

ALLOW_LIST = "allow_list"
BLOCK_LIST = "block_list"

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

SERIAL_CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional("baudrate", default=115200): vol.All(
            vol.Coerce(int), vol.Any(57600, 115200)
        ),  # NB: HGI80 does not work, except at 115200 - so must be default
        vol.Optional("timeout", default=0): vol.Any(None, int),
        vol.Optional("dsrdtr", default=False): bool,
        vol.Optional("rtscts", default=False): bool,
        vol.Optional("xonxoff", default=True): bool,  # set True to remove \x11
    },
)
CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional(DISABLE_DISCOVERY, default=False): vol.Any(None, bool),
        vol.Optional(DISABLE_SENDING, default=False): vol.Any(None, bool),
        vol.Optional(ENABLE_EAVESDROP, default=False): vol.Any(None, bool),
        vol.Optional(ENFORCE_ALLOWLIST, default=False): vol.Any(None, bool),
        vol.Optional(ENFORCE_BLOCKLIST, default=True): vol.Any(None, bool),
        vol.Optional(EVOFW_FLAG, default=None): vol.Any(None, str),
        vol.Optional(LOG_ROTATE_BYTES, default=None): vol.Any(None, int),
        vol.Optional(LOG_ROTATE_COUNT, default=0): vol.Any(None, int),
        vol.Optional(MAX_ZONES, default=DEFAULT_MAX_ZONES): vol.Any(None, int),
        vol.Optional(PACKET_LOG, default=None): vol.Any(None, str),
        vol.Optional(REDUCE_PROCESSING, default=0): vol.Any(None, int),
        # vol.Optional(SER2NET_RELAY): SER2NET_SCHEMA,
        vol.Optional(USE_NAMES, default=True): vol.Any(None, bool),
        vol.Optional(USE_SCHEMA, default=True): vol.Any(None, bool),
    },
    extra=vol.ALLOW_EXTRA,
)
ATTR_SYS_PROFILE = "_profile"
SYSTEM_PROFILES = ("evohome", "hometronics", "sundial")
HTG_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_HTG_CONTROL, default=None): vol.Any(None, HTG_DEVICE_ID),
        vol.Optional(ATTR_SYS_PROFILE, default="evohome"): vol.Any(*SYSTEM_PROFILES),
    },
    extra=vol.ALLOW_EXTRA,  # TODO: remove me
)
DHW_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_DHW_SENSOR, default=None): vol.Any(None, DHW_SENSOR_ID),
        vol.Optional(ATTR_DHW_VALVE, default=None): vol.Any(None, RLY_DEVICE_ID),
        vol.Optional(ATTR_DHW_VALVE_HTG, default=None): vol.Any(None, RLY_DEVICE_ID),
    }
)
UFC_CIRCUIT = vol.Schema(
    {
        vol.Required(UFH_IDX): vol.Any(
            {vol.Optional(ATTR_ZONE_IDX): vol.Any(ZONE_IDX)}
        ),
    }
)
UFH_SCHEMA = vol.Schema(
    {
        vol.Required(DEVICE_ID): vol.Any(
            None,
            {
                vol.Optional("ufh_circuits"): vol.Any(None, dict),
            },
        )
    }
)
UFH_SCHEMA = vol.All(UFH_SCHEMA, vol.Length(min=1, max=3))
ZONE_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_ZONE_TYPE, default=None): vol.Any(None, ZONE_TYPE_SLUGS),
        vol.Optional(ATTR_ZONE_SENSOR, default=None): vol.Any(None, SENSOR_ID),
        vol.Optional(ATTR_DEVICES, default=[]): vol.Any([], [DEVICE_ID]),
    }
)
ZONE_SCHEMA = vol.Schema({vol.Required(ZONE_IDX): ZONE_SCHEMA})
ZONE_SCHEMA = vol.All(ZONE_SCHEMA, vol.Length(min=1, max=DEFAULT_MAX_ZONES))
SYSTEM_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_CONTROLLER): CTL_DEVICE_ID,
        vol.Optional(ATTR_HTG_SYSTEM, default={}): vol.Any({}, HTG_SCHEMA),
        vol.Optional(ATTR_DHW_SYSTEM, default={}): vol.Any({}, DHW_SCHEMA),
        vol.Optional(ATTR_UFH_SYSTEM, default={}): vol.Any({}, UFH_SCHEMA),
        vol.Optional(ATTR_ORPHANS, default=[]): vol.Any([], [DEVICE_ID]),
        vol.Optional(ATTR_ZONES, default={}): vol.Any({}, ZONE_SCHEMA),
    },
    extra=vol.ALLOW_EXTRA,  # TODO: remove me
)
SYSTEM_SCHEMA = vol.Schema(vol.Any({}, SYSTEM_SCHEMA))

# GLOBAL_SCHEMA = vol.Schema(
#     vol.Any(SYSTEM_SCHEMA, vol.Length(min=0)),
#     ORPHAN_SCHEMA,
#     extra=vol.ALLOW_EXTRA
# )
KNOWNS_SCHEMA = vol.Schema(
    {
        vol.Optional(DEVICE_ID): vol.Any(
            None, {vol.Optional("name", default=None): vol.Any(None, str)}
        )  # , extra=vol.ALLOW_EXTRA
    }
)
FILTER_SCHEMA = vol.Schema(
    {
        vol.Optional(ALLOW_LIST): vol.Any(None, vol.All(KNOWNS_SCHEMA)),
        vol.Optional(BLOCK_LIST): vol.Any(None, vol.All(KNOWNS_SCHEMA)),
    }
)
# SCHEMA = vol.Schema(
#     {
#         vol.Optional("configuration"): CONFIG_SCHEMA,
#         vol.Optional("global_schema"): GLOBAL_SCHEMA,
#         vol.Optional("known_devices"): KNOWNS_SCHEMA,
#     }
# )
MONITOR_SCHEMA = vol.Schema(
    {
        vol.Optional("probe_system"): vol.Any(None, str),
        vol.Optional("execute_cmd"): vol.Any(None, str),
        vol.Optional(EVOFW_FLAG): vol.Any(None, str),
        vol.Optional(PACKET_LOG): vol.Any(None, str),
    }
)
PARSE_SCHEMA = vol.Schema({})
CLI_SCHEMA = vol.Schema({})


DEV_MODE = __dev_mode__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def load_config(
    serial_port,
    input_file,
    allow_list=None,
    block_list=None,
    config=None,
    **kwargs,
) -> Tuple[dict, list, list]:
    """Process the schema, and the configuration and return True if it is valid."""

    # assert kwargs == {}  # TODO: remove

    config = CONFIG_SCHEMA(config if config else {})
    config[SERIAL_CONFIG] = SERIAL_CONFIG_SCHEMA(config.get(SERIAL_CONFIG, {}))

    allow_list = KNOWNS_SCHEMA(allow_list if allow_list else {})
    block_list = KNOWNS_SCHEMA(block_list if block_list else {})

    if serial_port and input_file:
        _LOGGER.warning(
            "Serial port was specified (%s), so input file (%s) will be ignored",
            serial_port,
            input_file,
        )
    elif serial_port is None:
        config[DISABLE_SENDING] = True

    if config[DISABLE_SENDING]:
        config[DISABLE_DISCOVERY] = True

    if config[ENFORCE_ALLOWLIST]:
        config[ENFORCE_BLOCKLIST] = False
        if allow_list:
            _LOGGER.debug("An allowlist has been created, len = %s", len(allow_list))
        else:
            _LOGGER.warning("An empty allowlist was configured, so will be ignored")
            config[ENFORCE_ALLOWLIST] = False

    elif config[ENFORCE_BLOCKLIST]:
        if block_list:
            _LOGGER.debug("A blocklist has been created, len = %s", len(block_list))
        else:
            _LOGGER.warning("An empty blocklist was configured, so will be ignored")
            config[ENFORCE_BLOCKLIST] = False

    # if not kwargs.get(ALLOW_LIST, {}):
    #     config[USE_NAMES] = False

    return (config, allow_list, block_list)


def load_schema(gwy, allow_list, block_list, **kwargs) -> dict:
    """Process the schema, and the configuration and return True if it is valid."""
    # TODO: check a sensor is not a device in another zone

    known_devices = allow_list
    known_devices.update(block_list)

    [gwy._get_device(addr(device_id)) for device_id in kwargs.get(ATTR_ORPHANS, [])]

    if SCHEMA in kwargs:
        _load_schema(gwy, kwargs[SCHEMA])
        gwy.evo = gwy.system_by_id[kwargs[SCHEMA][ATTR_CONTROLLER]]
        return known_devices

    elif kwargs.get(MAIN_CONTROLLER):
        [
            _load_schema(gwy, schema)
            for k, schema in kwargs.items()
            if re.match(DEVICE_ID_REGEX, k)
        ]
        gwy.evo = gwy.system_by_id[kwargs[MAIN_CONTROLLER]]

    return known_devices


def _load_schema(gwy, schema) -> Tuple[dict, dict]:
    schema = SYSTEM_SCHEMA(schema)

    ctl_id = schema[ATTR_CONTROLLER]
    profile = schema[ATTR_HTG_SYSTEM].get(ATTR_SYS_PROFILE)
    ctl = gwy._get_device(addr(ctl_id), ctl_addr=addr(ctl_id), profile=profile)

    htg_ctl_id = schema[ATTR_HTG_SYSTEM].get(ATTR_HTG_CONTROL)
    if htg_ctl_id:
        ctl._evo._set_htg_control(gwy._get_device(addr(htg_ctl_id), ctl_addr=ctl))

    dhw = schema.get(ATTR_DHW_SYSTEM, {})
    if dhw:
        ctl._evo._set_dhw(ctl._evo._get_zone("HW"))

        dhw_sensor_id = dhw.get(ATTR_DHW_SENSOR)
        if dhw_sensor_id:
            ctl._evo.dhw._set_sensor(gwy._get_device(addr(dhw_sensor_id), ctl_addr=ctl))

        dhw_valve_id = dhw.get(ATTR_DHW_VALVE)
        if dhw_valve_id:
            ctl._evo.dhw._set_dhw_valve(
                gwy._get_device(addr(dhw_valve_id), ctl_addr=ctl)
            )

        htg_valve_id = dhw.get(ATTR_DHW_VALVE_HTG)
        if htg_valve_id:
            ctl._evo.dhw._set_htg_valve(
                gwy._get_device(addr(htg_valve_id), ctl_addr=ctl)
            )

    for zone_idx, attr in schema[ATTR_ZONES].items():
        zone = ctl._evo._get_zone(zone_idx, zone_type=attr.get(ATTR_ZONE_TYPE))

        sensor_id = attr.get(ATTR_ZONE_SENSOR)
        if sensor_id:
            zone._set_sensor(gwy._get_device(addr(sensor_id), ctl_addr=ctl))

        for device_id in attr.get(ATTR_DEVICES, []):
            gwy._get_device(addr(device_id), ctl_addr=ctl, domain_id=zone_idx)

    orphan_ids = schema.get(ATTR_ORPHANS, [])
    if orphan_ids:
        [gwy._get_device(addr(device_id), ctl_addr=ctl) for device_id in orphan_ids]

    ufh_ctl_ids = schema.get(ATTR_UFH_SYSTEM, {})
    if ufh_ctl_ids:
        for ufc_id, _ in ufh_ctl_ids.items():
            _ = gwy._get_device(addr(ufc_id), ctl_addr=ctl)

    # assert schema == gwy.system_by_id[ctl_id].schema
