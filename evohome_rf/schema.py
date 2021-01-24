#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - Schema processor."""

import logging
from typing import Tuple
import voluptuous as vol

from .const import (
    ATTR_CONTROLLER,
    ATTR_DEVICES,
    ATTR_DHW_SENSOR,
    ATTR_DHW_VALVE_HTG,
    ATTR_DHW_VALVE,
    ATTR_HTG_CONTROL,
    ATTR_ORPHANS,
    ATTR_STORED_HW,
    ATTR_SYSTEM,
    ATTR_UFH_CONTROLLERS,
    ATTR_ZONE_TYPE,
    ATTR_ZONE_SENSOR,
    ATTR_ZONES,
    DEFAULT_MAX_ZONES,
    ZONE_TYPE_SLUGS,
    _dev_mode_,
    id_to_address as addr,
)

DEVICE_ID_REGEXP = r"^[0-9]{2}:[0-9]{6}$"
DEVICE_ID = vol.Match(DEVICE_ID_REGEXP)

DOMAIN_ID_REGEXP = r"^[0-9A-F]{2}$"
DOMAIN_ID = vol.Match(DOMAIN_ID_REGEXP)

ZONE_IDX_REGEXP = r"^0[0-9AB]$"  # TODO: what if > 12 zones? (e.g. hometronics)
ZONE_IDX = vol.Match(ZONE_IDX_REGEXP)

ZONE_SCHEMA = vol.Schema(
    {
        vol.Required(ZONE_IDX): vol.Any(
            None,
            {
                vol.Optional(ATTR_ZONE_TYPE, default=None): vol.Any(
                    None, vol.Any(*list(ZONE_TYPE_SLUGS))
                ),
                vol.Optional(ATTR_ZONE_SENSOR, default=None): vol.Any(None, DEVICE_ID),
                vol.Optional(ATTR_DEVICES, default=[]): vol.Any(None, [DEVICE_ID]),
            },
        )
    }
)
SER2NET_SCHEMA = vol.Schema(
    {vol.Required("enabled"): bool, vol.Optional("socket", default="0.0.0.0:5000"): str}
)

# Config flags
CONFIG = "config"
DISABLE_DISCOVERY = "disable_discovery"
DISABLE_SENDING = "disable_sending"
ENFORCE_ALLOWLIST = "enforce_allowlist"
ENFORCE_BLOCKLIST = "enforce_blocklist"
EVOFW_FLAG = "evofw_flag"
INPUT_FILE = "input_file"
MAX_ZONES = "max_zones"
PACKET_LOG = "packet_log"
REDUCE_PROCESSING = "reduce_processing"
SERIAL_PORT = "serial_port"
SER2NET_RELAY = "ser2net_relay"
USE_NAMES = "use_names"  # use friendly device names from allow_list
USE_SCHEMA = "use_schema"
ALLOW_LIST = "allowlist"
BLOCK_LIST = "blocklist"


DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional(SERIAL_PORT): vol.Any(None, str),
        vol.Optional(DISABLE_SENDING, default=False): vol.Any(None, bool),
        vol.Optional(DISABLE_DISCOVERY, default=False): vol.Any(None, bool),
        vol.Optional(ENFORCE_ALLOWLIST, default=False): vol.Any(None, bool),
        vol.Optional(ENFORCE_BLOCKLIST, default=True): vol.Any(None, bool),
        vol.Optional(EVOFW_FLAG, default=None): vol.Any(None, str),
        vol.Optional(MAX_ZONES, default=DEFAULT_MAX_ZONES): vol.Any(None, int),
        vol.Optional(PACKET_LOG, default=None): vol.Any(None, str),
        vol.Optional(REDUCE_PROCESSING, default=0): vol.Any(None, int),
        # vol.Optional(SER2NET_RELAY): SER2NET_SCHEMA,
        vol.Optional(USE_NAMES, default=True): vol.Any(None, bool),
        vol.Optional(USE_SCHEMA, default=True): vol.Any(None, bool),
    },
    extra=vol.ALLOW_EXTRA,
)
DHW_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_DHW_SENSOR): vol.Any(None, vol.Match(r"^07:[0-9]{6}$")),
        vol.Optional(ATTR_DHW_VALVE): vol.Any(None, vol.Match(r"^13:[0-9]{6}$")),
        vol.Optional(ATTR_DHW_VALVE_HTG): vol.Any(None, vol.Match(r"^13:[0-9]{6}$")),
    }
)
UFH_SCHEMA = vol.Schema({})
ORPHAN_SCHEMA = vol.Schema(
    {vol.Optional(ATTR_ORPHANS): vol.Any(None, vol.All(DEVICE_ID))}
)
SYSTEM_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_CONTROLLER): vol.Match(r"^(01|23):[0-9]{6}$"),
        vol.Optional(ATTR_SYSTEM, default={}): vol.Schema(
            {
                vol.Optional(ATTR_HTG_CONTROL): vol.Any(
                    None, vol.Match(r"^(10|13):[0-9]{6}$")
                ),
                vol.Optional(ATTR_ORPHANS): vol.Any(None, vol.All([DEVICE_ID])),
            }
        ),
        vol.Optional(ATTR_STORED_HW): vol.Any(None, DHW_SCHEMA),
        vol.Optional(ATTR_ZONES): vol.Any(
            None, vol.All(ZONE_SCHEMA, vol.Length(min=1, max=DEFAULT_MAX_ZONES))
        ),
        vol.Optional(ATTR_UFH_CONTROLLERS): vol.Any(None, [UFH_SCHEMA]),
    },
    extra=vol.ALLOW_EXTRA,
)
# GLOBAL_SCHEMA = vol.Schema(
#     vol.Any(SYSTEM_SCHEMA, vol.Length(min=0)), ORPHAN_SCHEMA, extra=vol.ALLOW_EXTRA
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

DEV_MODE = _dev_mode_

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def load_config(serial_port, input_file, **kwargs) -> Tuple[dict, list, list]:
    """Process the schema, and the configuration and return True if it is valid."""

    config = CONFIG_SCHEMA(kwargs.get(CONFIG, {}))
    allows = {}
    blocks = {}

    if config[ENFORCE_ALLOWLIST]:
        allows = KNOWNS_SCHEMA(kwargs.get(ALLOW_LIST, {}))
        config[ENFORCE_BLOCKLIST] = False
        if allows:
            _LOGGER.debug("An allowlist has been created, len = %s", len(allows))
        else:
            _LOGGER.warning("An empty allowlist was configured, so will be ignored")
            config[ENFORCE_ALLOWLIST] = False

    elif config[ENFORCE_BLOCKLIST]:
        blocks = KNOWNS_SCHEMA(kwargs.get(BLOCK_LIST, {}))
        if blocks:
            _LOGGER.debug("A blocklist has been created, len = %s", len(blocks))
        else:
            _LOGGER.debug("An empty blocklist was configured, so will be ignored")
            config[ENFORCE_BLOCKLIST] = False

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

    # if not kwargs.get(ALLOW_LIST, {}):
    #     config[USE_NAMES] = False

    return (config, allows, blocks)


def load_schema(gwy, **kwargs) -> Tuple[dict, dict]:
    """Process the schema, and the configuration and return True if it is valid."""
    # TODO: check a sensor is not a device in another zone

    schema = SYSTEM_SCHEMA(kwargs.get("schema", {})) if kwargs.get("schema") else {}

    device_ids = schema.get(ATTR_ORPHANS, [])  # TODO: clean up
    if device_ids is not None:
        for device_id in device_ids:
            gwy._get_device(addr(device_id))

    if not schema.get(ATTR_CONTROLLER):
        return ({}, KNOWNS_SCHEMA(kwargs.get(ALLOW_LIST, {})))

    schema = SYSTEM_SCHEMA(schema)

    ctl_id = schema[ATTR_CONTROLLER]
    ctl = gwy._get_device(addr(ctl_id), ctl_addr=addr(ctl_id))

    htg_ctl_id = schema[ATTR_SYSTEM].get(ATTR_HTG_CONTROL)
    if htg_ctl_id:
        ctl._evo._set_htg_control(gwy._get_device(addr(htg_ctl_id), ctl_addr=ctl))

    for device_id in schema[ATTR_SYSTEM].get(ATTR_ORPHANS, []):
        gwy._get_device(addr(device_id), ctl_addr=ctl)

    dhw = schema.get(ATTR_STORED_HW)
    if dhw:
        ctl._evo._set_dhw(ctl._evo._get_zone("HW"))

        dhw_sensor_id = dhw.get(ATTR_DHW_SENSOR)
        if dhw_sensor_id:
            ctl._evo._set_dhw_sensor(gwy._get_device(addr(dhw_sensor_id), ctl_addr=ctl))

        dhw_valve_id = dhw.get(ATTR_DHW_VALVE)
        if dhw_valve_id:
            ctl._evo._set_dhw_valve(gwy._get_device(addr(dhw_valve_id), ctl_addr=ctl))

        htg_valve_id = dhw.get(ATTR_DHW_VALVE_HTG)
        if htg_valve_id:
            ctl._evo._set_htg_valve(gwy._get_device(addr(htg_valve_id), ctl_addr=ctl))

    if ATTR_ZONES in schema:
        for zone_idx, attr in schema[ATTR_ZONES].items():
            zone = ctl._evo._get_zone(zone_idx, zone_type=attr.get(ATTR_ZONE_TYPE))

            sensor_id = attr.get(ATTR_ZONE_SENSOR)
            if sensor_id:
                zone._set_sensor(gwy._get_device(addr(sensor_id), ctl_addr=ctl))

            device_ids = attr.get(ATTR_DEVICES)  # TODO: clean up
            if device_ids is not None:
                for device_id in device_ids:
                    gwy._get_device(addr(device_id), ctl_addr=ctl, domain_id=zone_idx)

    # for ufh_ctl, ufh_schema in schema.get(ATTR_UFH_CONTROLLERS, []):
    #     dev = gwy._get_device(addr(ufh_ctl), ctl_addr=ctl)

    known_devices = KNOWNS_SCHEMA(kwargs.get(ALLOW_LIST, {}))
    known_devices.update(KNOWNS_SCHEMA(kwargs.get(BLOCK_LIST, {})))

    return (schema, known_devices)
