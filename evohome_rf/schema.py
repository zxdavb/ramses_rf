#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Schema processor."""

import json
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
    ATTR_STORED_HOTWATER,
    ATTR_SYSTEM,
    ATTR_UFH_CONTROLLERS,
    ATTR_ZONE_TYPE,
    ATTR_ZONE_SENSOR,
    ATTR_ZONES,
    DEFAULT_MAX_ZONES,
    ZONE_TYPE_SLUGS,
    __dev_mode__,
    id_to_address as addr,
)

# false = False; null = None; true = True

# TODO: duplicated in __init__.py
DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

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

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional("disable_sending", default=False): vol.Any(None, bool),
        vol.Optional("disable_discovery", default=False): vol.Any(None, bool),
        vol.Optional("enforce_allowlist", default=False): vol.Any(None, bool),
        vol.Optional("enforce_blocklist", default=True): vol.Any(None, bool),
        vol.Optional("evofw_flag", default=None): vol.Any(None, bool),
        # vol.Optional("input_file"): vol.Any(None, str),
        vol.Optional("max_zones", default=DEFAULT_MAX_ZONES): vol.Any(None, int),
        vol.Optional("packet_log", default=None): vol.Any(None, str),
        vol.Optional("reduce_processing", default=0): vol.Any(None, int),
        vol.Optional("serial_port"): vol.Any(None, str),
        vol.Optional("ser2net_relay"): SER2NET_SCHEMA,
        vol.Optional("use_schema", default=True): vol.Any(None, bool),
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
        vol.Optional(ATTR_STORED_HOTWATER): vol.Any(None, DHW_SCHEMA),
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
            None,
            {
                vol.Optional("name", default=None): vol.Any(None, str),
                vol.Optional("_parent_zone"): vol.Any(None, DOMAIN_ID),
                vol.Optional("_has_battery"): vol.Any(None, bool),
            },
        )  # , extra=vol.ALLOW_EXTRA
    }
)
FILTER_SCHEMA = vol.Schema(
    {
        vol.Optional("allowlist"): vol.Any(None, vol.All(KNOWNS_SCHEMA)),
        vol.Optional("blocklist"): vol.Any(None, vol.All(KNOWNS_SCHEMA)),
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
        vol.Optional("execut_cmd"): vol.Any(None, str),
        vol.Optional("evofw_flag"): vol.Any(None, str),
        vol.Optional("packet_log"): vol.Any(None, str),
    }
)
PARSE_SCHEMA = vol.Schema({})
CLI_SCHEMA = vol.Schema({})

_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)
else:
    _LOGGER.setLevel(logging.WARNING)


def load_config(gwy, **config) -> Tuple[dict, list, list]:
    """Process the schema, and the configuration and return True if it is valid."""

    # def proc_cli(config):
    # self.config["input_file"] = config.get("input_file")
    # config["known_devices"] = config.get("known_devices")
    # self.config["reduce_processing"] = config.get("raw_output", 0)

    # if self.serial_port and self.config["input_file"]:
    #     _LOGGER.warning(
    #         "Serial port specified (%s), so ignoring input file (%s)",
    #         self.serial_port,
    #         self.config["input_file"],
    #     )
    #     self.config["input_file"] = None

    # self.config["disable_sending"] = not config.get("probe_system")
    # if self.config["input_file"]:
    #     self.config["disable_sending"] = True

    # if self.config["reduce_processing"] >= DONT_CREATE_MESSAGES:
    #     config["message_log"] = None
    #     _stream = (None, sys.stdout)
    # else:
    #     _stream = (sys.stdout, None)

    schema_filename = config.get("config_file")

    if schema_filename is None:
        return {}, (), ()

    try:
        with open(schema_filename) as schema_fp:
            config = json.load(schema_fp)
    except FileNotFoundError:  # if it doesn't exist, create it later
        return {}, (), ()

    # config = SCHEMA(config)
    params, schema = config["configuration"], config["global_schema"]
    gwy.known_devices = config["known_devices"]

    allowlist = list(config["known_devices"]["allowlist"])
    blocklist = list(config["known_devices"]["blocklist"])

    if params["use_allowlist"] and allowlist:
        _list = True
    elif params["use_blocklist"] and blocklist:
        _list = False
    elif params["use_allowlist"] is not False and allowlist:
        _list = True
    elif params["use_blocklist"] is not False and blocklist:
        _list = False
    else:
        _list = None

    if params["use_schema"]:  # regardless of filters, & updates known/allow
        (load_schema(gwy, k, v) for k, v in schema.items() if k != ATTR_ORPHANS)

    if _list:
        allowlist += [d for d in gwy.device_by_id if d not in allowlist]
        blocklist = []
    elif _list is False:
        allowlist = []
        blocklist = [d for d in blocklist if d not in gwy.device_by_id]
    else:
        allowlist = blocklist = []  # cheeky, but OK

    return params, tuple(allowlist), tuple(blocklist)


def load_schema(gwy, schema, **kwargs) -> dict:
    """Process the schema, and the configuration and return True if it is valid."""
    # TODO: check a sensor is not a device in another zone

    if schema.get(ATTR_CONTROLLER) is None:
        return {}

    schema = SYSTEM_SCHEMA(schema)

    ctl_id = schema[ATTR_CONTROLLER]
    ctl = gwy.get_device(addr(ctl_id), controller=addr(ctl_id))

    gwy.evo = ctl

    if ATTR_HTG_CONTROL in schema[ATTR_SYSTEM]:
        htg_id = schema[ATTR_SYSTEM][ATTR_HTG_CONTROL]
        if htg_id:
            ctl.boiler_control = gwy.get_device(addr(htg_id), controller=ctl)

    if ATTR_STORED_HOTWATER in schema:
        dhw = schema[ATTR_STORED_HOTWATER]
        if dhw:
            ctl.dhw = ctl.get_zone("FA")

            dhw_sensor_id = dhw.get(ATTR_DHW_SENSOR)
            if dhw_sensor_id is not None:
                ctl.dhw._set_sensor(gwy.get_device(addr(dhw_sensor_id), controller=ctl))

            dhw_id = dhw.get(ATTR_DHW_VALVE)
            if dhw_id is not None:
                ctl.dhw.hotwater_valve = gwy.get_device(addr(dhw_id), controller=ctl)

            htg_id = dhw.get(ATTR_DHW_VALVE_HTG)
            if htg_id is not None:
                ctl.dhw.heating_valve = gwy.get_device(addr(htg_id), controller=ctl)

    if schema.get(ATTR_ZONES):
        for zone_idx, attr in schema[ATTR_ZONES].items():
            zone = ctl.get_zone(zone_idx, zone_type=attr.get(ATTR_ZONE_TYPE))

            sensor_id = attr.get(ATTR_ZONE_SENSOR)
            if sensor_id:
                zone._set_sensor(gwy.get_device(addr(sensor_id), controller=ctl))

            device_list = attr.get(ATTR_DEVICES)
            if device_list:
                for device_id in attr.get(ATTR_DEVICES):
                    gwy.get_device(addr(device_id), controller=ctl, domain_id=zone_idx)

    # for ufh_ctl, ufh_schema in schema[ATTR_UFH_CONTROLLERS]:
    #     dev = gwy.get_device(addr(ufh_ctl), controller=ctl)
