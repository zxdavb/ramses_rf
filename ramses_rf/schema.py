#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Schema processor.
"""

# TODO: move max_zones into system-specific location, ?profile

import logging
import re
from types import SimpleNamespace
from typing import Any, Optional, Tuple

import voluptuous as vol

from .const import (
    ATTR_DEVICES,
    ATTR_ZONE_IDX,
    DEFAULT_MAX_ZONES,
    DEV_KLASS,
    DEVICE_ID_REGEX,
    DONT_CREATE_MESSAGES,
    ZONE_TYPE_SLUGS,
    SystemType,
    __dev_mode__,
)
from .protocol import PACKET_LOG, PACKET_LOG_SCHEMA
from .protocol.transport import SERIAL_CONFIG_SCHEMA

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


# schema strings
SCHEMA = "schema"
SZ_MAIN_CONTROLLER = "main_controller"

SZ_CONTROLLER = "controller"
SZ_HTG_SYSTEM = "system"
SZ_HTG_CONTROL = "heating_control"
SZ_ORPHANS = "orphans"

SZ_DHW_SYSTEM = "stored_hotwater"
SZ_DHW_SENSOR = "hotwater_sensor"
SZ_DHW_VALVE = "hotwater_valve"
SZ_DHW_VALVE_HTG = "heating_valve"

SZ_ZONES = "zones"
SZ_ZONE_TYPE = "zone_type"
SZ_ZONE_SENSOR = "zone_sensor"
SZ_ACTUATORS = "actuators"

SZ_UFH_SYSTEM = "underfloor_heating"
SZ_UFH_CTL = "ufh_controller"

SZ_DEVICE_ID = "device_id"
SZ_ALIAS = "alias"
SZ_CLASS = "class"
SZ_FAKED = "faked"

DEVICE_ID = vol.Match(DEVICE_ID_REGEX.ANY)
SENSOR_ID = vol.Match(DEVICE_ID_REGEX.SEN)
DEV_REGEX_CTL = vol.Match(DEVICE_ID_REGEX.CTL)
DEV_REGEX_DHW = vol.Match(DEVICE_ID_REGEX.DHW)
DEV_REGEX_HGI = vol.Match(DEVICE_ID_REGEX.HGI)
DEV_REGEX_HTG = vol.Match(DEVICE_ID_REGEX.HTG)
DEV_REGEX_BDR = vol.Match(DEVICE_ID_REGEX.BDR)
DEV_REGEX_UFC = vol.Match(DEVICE_ID_REGEX.UFC)

ZONE_TYPE_SLUGS = list(ZONE_TYPE_SLUGS)

DOMAIN_ID = vol.Match(r"^[0-9A-F]{2}$")
UFH_IDX_REGEX = r"^0[0-8]$"
UFH_IDX = vol.Match(UFH_IDX_REGEX)
ZONE_IDX = vol.Match(r"^0[0-9AB]$")  # TODO: what if > 12 zones? (e.g. hometronics)

SERIAL_PORT = "serial_port"
PORT_NAME = "port_name"
INPUT_FILE = "input_file"

# Config parameters
DEBUG_MODE = "debug_mode"

BLOCK_LIST = "block_list"
KNOWN_LIST = "known_list"

CONFIG = "config"
DISABLE_DISCOVERY = "disable_discovery"
DISABLE_SENDING = "disable_sending"
ENABLE_EAVESDROP = "enable_eavesdrop"
ENFORCE_KNOWNLIST = f"enforce_{KNOWN_LIST}"
EVOFW_FLAG = "evofw_flag"
MAX_ZONES = "max_zones"
REDUCE_PROCESSING = "reduce_processing"
SERIAL_CONFIG = "serial_config"
USE_ALIASES = "use_aliases"  # use friendly device names from known_list
USE_SCHEMA = "use_schema"

# 1/3: Schemas for Configuration

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional(DISABLE_DISCOVERY, default=False): bool,
        vol.Optional(DISABLE_SENDING, default=False): bool,
        vol.Optional(ENABLE_EAVESDROP, default=False): bool,
        vol.Optional(REDUCE_PROCESSING, default=0): vol.All(
            int, vol.Range(min=0, max=DONT_CREATE_MESSAGES)
        ),
        vol.Optional(MAX_ZONES, default=DEFAULT_MAX_ZONES): vol.All(
            int, vol.Range(min=1, max=16)
        ),
        vol.Optional(USE_SCHEMA, default=True): vol.Any(None, bool),
        vol.Optional(ENFORCE_KNOWNLIST, default=None): vol.Any(None, bool),
        vol.Optional(USE_ALIASES, default=None): vol.Any(None, bool),
        vol.Optional(EVOFW_FLAG, default=None): vol.Any(None, str),
        vol.Optional("use_regex", default={}): dict(),
    },
    extra=vol.ALLOW_EXTRA,  # TODO: remove for production
)

DEVICE_DICT = vol.Schema(
    {
        vol.Optional(DEVICE_ID): vol.Any(
            {
                vol.Optional(SZ_ALIAS): vol.Any(None, str),
                vol.Optional(SZ_CLASS): vol.Any(None, *vars(DEV_KLASS).keys()),
                vol.Optional(SZ_FAKED): vol.Any(None, bool, list),
            },
        )
    },
    extra=vol.PREVENT_EXTRA,
)

# 2/3: Schemas for Heating systems
SZ_SYS_PROFILE = "_profile"
SYSTEM_PROFILES = (SystemType.EVOHOME, SystemType.HOMETRONICS, SystemType.SUNDIAL)

HTG_SCHEMA = vol.Schema(
    {
        vol.Required(SZ_HTG_CONTROL, default=None): vol.Any(None, DEV_REGEX_HTG),
        vol.Optional(SZ_SYS_PROFILE, default=SystemType.EVOHOME): vol.Any(
            *SYSTEM_PROFILES
        ),
    },
    # extra=vol.ALLOW_EXTRA,  # TODO: remove me
)
DHW_SCHEMA = vol.Schema(
    {
        vol.Optional(SZ_DHW_SENSOR, default=None): vol.Any(None, DEV_REGEX_DHW),
        vol.Optional(SZ_DHW_VALVE, default=None): vol.Any(None, DEV_REGEX_BDR),
        vol.Optional(SZ_DHW_VALVE_HTG, default=None): vol.Any(None, DEV_REGEX_BDR),
    }
)
UFC_CIRCUIT = vol.Schema(
    {
        vol.Required(UFH_IDX): vol.Any(
            {vol.Optional(ATTR_ZONE_IDX): vol.Any(ZONE_IDX)},
        ),
    }
)
UFH_SCHEMA = vol.Schema(
    {
        vol.Required(DEVICE_ID): vol.Any(
            None, {vol.Optional("ufh_circuits"): vol.Any(None, dict)}
        )
    }
)
UFH_SCHEMA = vol.All(UFH_SCHEMA, vol.Length(min=1, max=3))

ZONE_SCHEMA = vol.Schema(
    {
        vol.Optional(SZ_ZONE_TYPE, default=None): vol.Any(None, ZONE_TYPE_SLUGS),
        vol.Optional(SZ_ZONE_SENSOR, default=None): vol.Any(None, SENSOR_ID),
        vol.Optional(ATTR_DEVICES, default=[]): vol.Any([], [DEVICE_ID]),
        # vol.Optional("faked_sensor", default=None): vol.Any(None, bool),
    }
)
ZONES_SCHEMA = vol.All(
    vol.Schema({vol.Required(ZONE_IDX): ZONE_SCHEMA}),
    vol.Length(min=1, max=DEFAULT_MAX_ZONES),
)
SYSTEM_SCHEMA = vol.Schema(
    {
        # vol.Required(SZ_CONTROLLER): DEV_REGEX_CTL,
        vol.Optional(SZ_HTG_SYSTEM, default={}): vol.Any({}, HTG_SCHEMA),
        vol.Optional(SZ_DHW_SYSTEM, default={}): vol.Any({}, DHW_SCHEMA),
        vol.Optional(SZ_UFH_SYSTEM, default={}): vol.Any({}, UFH_SCHEMA),
        vol.Optional(SZ_ORPHANS, default=[]): vol.Any([], [DEVICE_ID]),
        vol.Optional(SZ_ZONES, default={}): vol.Any({}, ZONES_SCHEMA),
    },
    extra=vol.ALLOW_EXTRA,  # TODO: remove me - But: Causes an issue?
)


# 3/3: Global Schemas
GLOBAL_CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required(CONFIG): CONFIG_SCHEMA.extend(
            {
                vol.Optional(SERIAL_CONFIG): SERIAL_CONFIG_SCHEMA,
                vol.Optional(PACKET_LOG, default={}): vol.Any({}, PACKET_LOG_SCHEMA),
            }
        ),
        vol.Optional(KNOWN_LIST, default={}): vol.All(DEVICE_DICT, vol.Length(min=0)),
        vol.Optional(BLOCK_LIST, default={}): vol.All(DEVICE_DICT, vol.Length(min=0)),
    },
    extra=vol.REMOVE_EXTRA,
)


def load_config(
    serial_port, input_file, **kwargs
) -> Tuple[SimpleNamespace, dict, list, list]:
    """Process the configuration, including any filter lists."""

    config = GLOBAL_CONFIG_SCHEMA(kwargs)
    schema = {k: v for k, v in kwargs.items() if k not in config and k[:1] != "_"}

    block_list = config.pop(BLOCK_LIST)
    known_list = config.pop(KNOWN_LIST)

    config = CONFIG_SCHEMA.extend(
        {vol.Optional(SERIAL_CONFIG, default={}): SERIAL_CONFIG_SCHEMA}
    )(config[CONFIG])

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

    if config[ENABLE_EAVESDROP]:
        _LOGGER.warning(
            f"{ENABLE_EAVESDROP} enabled: this is discouraged for routine use"
            " (there be dragons here)"
        )

    update_config(config, known_list, block_list)
    config = SimpleNamespace(**config)

    # # TODO: remove
    # config.use_regex.update(
    #     {
    #         "( 03:.* 03:.* (1060|2389|30C9) 003) ..": "\\1 00",
    #     }
    # )

    return (config, schema, known_list, block_list)


def update_config(config, known_list, block_list) -> dict:
    """Determine which device filter to use, if any: known_list or block_list."""

    if config[ENFORCE_KNOWNLIST] and not known_list:
        _LOGGER.warning(
            f"An empty {KNOWN_LIST} was provided, so it cant be used "
            f"as a whitelist (device_id filter)"
        )
        config[ENFORCE_KNOWNLIST] = False

    if config[ENFORCE_KNOWNLIST]:
        _LOGGER.info(
            f"The {KNOWN_LIST} will be used "
            f"as a whitelist (device_id filter), length = {len(known_list)}"
        )
        _LOGGER.debug(f"known_list = {known_list}")

    elif block_list:
        _LOGGER.info(
            f"The {BLOCK_LIST} will be used "
            f"as a blacklist (device_id filter), length = {len(block_list)}"
        )
        _LOGGER.debug(f"block_list = {block_list}")

    elif known_list:
        _LOGGER.warning(
            f"It is strongly recommended to use the {KNOWN_LIST} "
            f"as a whitelist (device_id filter), configure: {ENFORCE_KNOWNLIST} = True"
        )
        _LOGGER.debug(f"known_list = {known_list}")

    else:
        _LOGGER.warning(
            f"It is strongly recommended to provide a {KNOWN_LIST}, and use it "
            f"as a whitelist (device_id filter), configure: {ENFORCE_KNOWNLIST} = True"
        )


def _get_device(gwy, dev_id, ctl_id=None, **kwargs) -> Optional[Any]:  # -> Device:
    """Get (optionally create) a device only if not filtered out."""

    if "dev_addr" in kwargs or "ctl_addr" in kwargs:
        raise RuntimeError

    if gwy.config.enforce_known_list and dev_id not in gwy._include:
        err_msg = f"{dev_id} is in the {SCHEMA}, but not in the {KNOWN_LIST}"
    elif dev_id in gwy._exclude:
        err_msg = f"{dev_id} is in the {SCHEMA}, but also in the {BLOCK_LIST}"
    else:
        err_msg = None

    if err_msg:
        _LOGGER.error(f"{err_msg}: check the lists and the {SCHEMA} (device ignored)")
        return

    return gwy._get_device(dev_id, ctl_id=ctl_id, **kwargs)
    # **gwy._include keys may have: alias, faked, faked_thm, faked_bdr, faked_ext
    # **kwargs keys may have: profile(systems, e.g. evohome), class(devices, e.g. BDR)
    # return gwy._get_device(dev_id, ctl_id=ctl_id, **gwy._include.get(dev_id), **kwargs)


def load_schema(gwy, **kwargs) -> dict:
    """Process the schema, and the configuration and return True if it is valid."""

    [
        load_system(gwy, ctl_id, schema)
        for ctl_id, schema in kwargs.items()
        if re.match(DEVICE_ID_REGEX.ANY, ctl_id)
    ]
    if kwargs.get(SZ_MAIN_CONTROLLER):
        gwy.evo = gwy.system_by_id.get(kwargs[SZ_MAIN_CONTROLLER])

    [_get_device(gwy, device_id) for device_id in kwargs.pop(SZ_ORPHANS, [])]


def load_system(gwy, ctl_id, schema) -> Tuple[dict, dict]:
    schema = SYSTEM_SCHEMA(schema)

    if (ctl := _get_device(gwy, ctl_id, ctl_id=ctl_id, profile=None)) is None:
        return

    if dev_id := schema[SZ_HTG_SYSTEM].get(SZ_HTG_CONTROL):
        ctl._evo._set_htg_control(_get_device(gwy, dev_id, ctl_id=ctl.id))

    if dhw_schema := schema.get(SZ_DHW_SYSTEM, {}):
        dhw = ctl._evo._get_dhw()  # **dhw_schema)
        if dev_id := dhw_schema.get(SZ_DHW_SENSOR):
            dhw._set_sensor(_get_device(gwy, dev_id, ctl_id=ctl.id))
        if dev_id := dhw_schema.get(SZ_DHW_VALVE):
            dhw._set_dhw_valve(_get_device(gwy, dev_id, ctl_id=ctl.id))
        if dev_id := dhw_schema.get(SZ_DHW_VALVE_HTG):
            dhw._set_htg_valve(_get_device(gwy, dev_id, ctl_id=ctl.id))

    for zone_idx, attrs in schema[SZ_ZONES].items():
        zone = ctl._evo._get_zone(zone_idx)  # , **attrs)

        if dev_id := attrs.get(SZ_ZONE_SENSOR):
            zone._set_sensor(
                _get_device(gwy, dev_id, ctl_id=ctl.id, domain_id=zone_idx)
            )
            if attrs.get("faked_sensor"):
                zone.sensor._make_fake()  # TODO: check device type here?

        for dev_id in attrs.get(ATTR_DEVICES, []):
            _get_device(gwy, dev_id, ctl_id=ctl.id, domain_id=zone_idx)

        if zone_type := attrs.get(SZ_ZONE_TYPE):
            zone._set_zone_type(zone_type)

    for dev_id in schema.get(SZ_UFH_SYSTEM, {}).keys():  # UFH controllers
        _get_device(gwy, dev_id, ctl_id=ctl.id)  # , **_schema)

    for dev_id in schema.get(SZ_ORPHANS, []):
        _get_device(gwy, dev_id, ctl_id=ctl.id)

    if False and DEV_MODE:
        import json

        src = json.dumps(shrink_dict(schema), sort_keys=True)
        dst = json.dumps(shrink_dict(gwy.system_by_id[ctl.id].schema), sort_keys=True)
        # assert dst == src, "They don't match!"
        print(src)
        print(dst)

    return ctl


def shrink_dict(_dict):
    return {
        k: shrink_dict(dict(v)) if isinstance(v, dict) else v
        for k, v in _dict.items()
        if bool(v)
    }
