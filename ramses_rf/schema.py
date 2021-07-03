#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Schema processor."""

import logging
import re
from types import SimpleNamespace
from typing import Any, Optional, Tuple

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
from .const import (
    ATTR_ZONE_IDX,
    ATTR_ZONE_SENSOR,
    ATTR_ZONE_TYPE,
    ATTR_ZONES,
    CTL_DEVICE_ID,
    DEFAULT_MAX_ZONES,
    DHW_SENSOR_ID,
    GWY_DEVICE_ID,
    HTG_DEVICE_ID,
    RLY_DEVICE_ID,
    UFC_DEVICE_ID,
    ZON_SENSOR_ID,
    ZONE_TYPE_SLUGS,
    SystemType,
    __dev_mode__,
)
from .const import id_to_address as addr
from .devices import DEVICE_BY_CLASS_ID

# schema attrs
ATTR_DEVICE_ID = "device_id"
ATTR_HTG_SYSTEM = "system"
ATTR_ORPHANS = "orphans"
ATTR_UFH_CTL = "ufh_controller"

DEVICE_ID = vol.Match(DEVICE_ID_REGEX)
SENSOR_ID = vol.Match(ZON_SENSOR_ID)
CTL_DEVICE_ID = vol.Match(CTL_DEVICE_ID)
DHW_SENSOR_ID = vol.Match(DHW_SENSOR_ID)
GWY_DEVICE_ID = vol.Match(GWY_DEVICE_ID)
HTG_DEVICE_ID = vol.Match(HTG_DEVICE_ID)
RLY_DEVICE_ID = vol.Match(RLY_DEVICE_ID)
UFC_DEVICE_ID = vol.Match(UFC_DEVICE_ID)

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
ALLOW_LIST = "allow_list"
BLOCK_LIST = "block_list"

CONFIG = "config"
DISABLE_DISCOVERY = "disable_discovery"
DISABLE_SENDING = "disable_sending"
ENABLE_EAVESDROP = "enable_eavesdrop"
ENFORCE_ALLOWLIST = f"enforce_{ALLOW_LIST}"
ENFORCE_BLOCKLIST = f"enforce_{BLOCK_LIST}"
EVOFW_FLAG = "evofw_flag"
MAX_ZONES = "max_zones"
REDUCE_PROCESSING = "reduce_processing"
SERIAL_CONFIG = "serial_config"
USE_NAMES = "use_names"  # use friendly device names from allow_list
USE_SCHEMA = "use_schema"

LOG_FILE_NAME = "file_name"
LOG_ROTATE_BYTES = "rotate_bytes"
LOG_ROTATE_COUNT = "rotate_backups"
PACKET_LOG = "packet_log"  # output

# Schema parameters
SCHEMA = "schema"
MAIN_CONTROLLER = "main_controller"

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

# 1/3: Schemas for Configuration
SERIAL_CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional("baudrate", default=115200): vol.All(
            vol.Coerce(int), vol.Any(57600, 115200)
        ),  # NB: HGI80 does not work, except at 115200 - so must be default
        vol.Optional("timeout", default=0): vol.Any(None, int),  # TODO: default None?
        vol.Optional("dsrdtr", default=False): bool,
        vol.Optional("rtscts", default=False): bool,
        vol.Optional("xonxoff", default=True): bool,  # set True to remove \x11
    }
)
SERIAL_PORT_SCHEMA = vol.Schema(
    {
        vol.Required(SERIAL_PORT): vol.Any(
            None,
            str,
            SERIAL_CONFIG_SCHEMA.extend({vol.Required(PORT_NAME): vol.Any(None, str)}),
        )
    }
)

PACKET_LOG_SCHEMA = vol.Schema(
    {
        vol.Required(LOG_FILE_NAME, default=None): vol.Any(None, str),
        vol.Optional(LOG_ROTATE_BYTES, default=None): vol.Any(None, int),
        vol.Optional(LOG_ROTATE_COUNT, default=None): vol.Any(None, int),
    },
    extra=vol.PREVENT_EXTRA,
)

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
        vol.Optional(ENFORCE_ALLOWLIST, default=None): vol.Any(None, bool),
        vol.Optional(ENFORCE_BLOCKLIST, default=None): vol.Any(None, bool),
        vol.Optional(USE_NAMES, default=None): vol.Any(None, bool),
        vol.Optional(EVOFW_FLAG, default=None): vol.Any(None, str),
    },
    extra=vol.ALLOW_EXTRA,  # TODO: remove for production
)

FILTER_SCHEMA = vol.Any([], vol.All(vol.Schema([DEVICE_ID]), vol.Length(min=0)))
KNOWNS_SCHEMA = vol.Schema(
    {
        vol.Optional(DEVICE_ID): vol.Any(
            None,
            {
                vol.Optional("name", default=None): vol.Any(None, str),
                vol.Optional("dev_class"): vol.Any(*DEVICE_BY_CLASS_ID.keys()),
            },  # TODO: override type-by-addr.id with dev_class
        )
    },
    extra=vol.PREVENT_EXTRA,
)

# 2/3: Schemas for Heating systems
ATTR_SYS_PROFILE = "_profile"
SYSTEM_PROFILES = (SystemType.EVOHOME, SystemType.HOMETRONICS, SystemType.SUNDIAL)

HTG_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_HTG_CONTROL, default=None): vol.Any(None, HTG_DEVICE_ID),
        vol.Optional(ATTR_SYS_PROFILE, default=SystemType.EVOHOME): vol.Any(
            *SYSTEM_PROFILES
        ),
    },
    # extra=vol.ALLOW_EXTRA,  # TODO: remove me
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

SENSOR_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_DEVICE_ID): SENSOR_ID,
        vol.Optional("is_faked"): bool,
        # vol.Optional("native_id"): DEVICE_ID,
    }
)
# SENSOR_SCHEMA = vol.Any(None, SENSOR_ID, SENSOR_SCHEMA)
ZONE_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_ZONE_TYPE, default=None): vol.Any(None, ZONE_TYPE_SLUGS),
        vol.Optional(ATTR_ZONE_SENSOR, default=None): vol.Any(
            None, SENSOR_ID, SENSOR_SCHEMA
        ),
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
    extra=vol.ALLOW_EXTRA,  # TODO: remove me - But: Causes an issue?
)
SYSTEM_SCHEMA = vol.Schema(vol.Any({}, SYSTEM_SCHEMA))


# 3/3: Global Schemas
GLOBAL_CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required(CONFIG): CONFIG_SCHEMA.extend(
            {
                vol.Optional(SERIAL_CONFIG): SERIAL_CONFIG_SCHEMA,
                vol.Optional(PACKET_LOG, default={}): vol.Any({}, PACKET_LOG_SCHEMA),
            }
        ),
        vol.Optional(ALLOW_LIST, default={}): vol.All(KNOWNS_SCHEMA, vol.Length(min=0)),
        vol.Optional(BLOCK_LIST, default={}): vol.All(KNOWNS_SCHEMA, vol.Length(min=0)),
    },
    extra=vol.REMOVE_EXTRA,
)


DEV_MODE = __dev_mode__  # or True

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def load_config_schema(
    serial_port, input_file, **kwargs
) -> Tuple[SimpleNamespace, dict, list, list]:
    """Process the configuration, including any filter lists."""

    schema = {
        k: v for k, v in kwargs.items() if k not in (ALLOW_LIST, BLOCK_LIST, CONFIG)
    }
    kwargs = GLOBAL_CONFIG_SCHEMA(kwargs)

    allow_list = kwargs.pop(ALLOW_LIST)
    block_list = kwargs.pop(BLOCK_LIST)

    config = CONFIG_SCHEMA.extend(
        {vol.Optional(SERIAL_CONFIG, default={}): SERIAL_CONFIG_SCHEMA}
    )(kwargs[CONFIG])

    known_devices = {**allow_list, **block_list}
    if config[USE_NAMES] is None:
        config[USE_NAMES] = known_devices and any(
            v.get("name")
            for v in known_devices.values()
            if v is not None  # if isinstance(v, dict)
        )

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
            f"{ENABLE_EAVESDROP} was enabled: not doing so is strongly recommended"
            " (there be dragons here)"
        )

    if config[ENFORCE_ALLOWLIST] is None:
        config[ENFORCE_ALLOWLIST] = (
            False if config[ENFORCE_BLOCKLIST] else bool(allow_list)
        )
    if config[ENFORCE_BLOCKLIST] is None:
        config[ENFORCE_BLOCKLIST] = (
            False if config[ENFORCE_ALLOWLIST] else bool(block_list)
        )

    assert (
        config[ENFORCE_ALLOWLIST] is not None and config[ENFORCE_BLOCKLIST] is not None
    )

    if config[ENFORCE_ALLOWLIST] and not allow_list:
        _LOGGER.warning(f"An empty {ALLOW_LIST} was enabled, so will be ignored")
        config[ENFORCE_ALLOWLIST] = False
    if config[ENFORCE_BLOCKLIST] and not block_list:
        _LOGGER.warning(f"An empty {BLOCK_LIST} was enabled, so will be ignored")
        config[ENFORCE_BLOCKLIST] = False

    if config[ENFORCE_ALLOWLIST] and config[ENFORCE_BLOCKLIST]:
        _LOGGER.warning(
            f"Both an {ALLOW_LIST} and a {BLOCK_LIST} were enabled, "
            f"so the {BLOCK_LIST} will be ignored"
        )
        config[ENFORCE_BLOCKLIST] = False
    elif not config[ENFORCE_ALLOWLIST]:
        _LOGGER.warning(
            f"No {ALLOW_LIST} was configured, but one is strongly recommended"
        )

    if config[ENFORCE_ALLOWLIST]:
        _LOGGER.debug(f"An {ALLOW_LIST} has been created, length = {len(allow_list)}")
    elif config[ENFORCE_BLOCKLIST]:
        _LOGGER.debug(f"A {BLOCK_LIST} has been created, length = {len(block_list)}")

    # TODO: use dict or list? - will need to add 18? when we see it?
    # allow_list = (
    #     list(allow_list.keys()) if config[ENFORCE_ALLOWLIST] else []
    # )
    # block_list = (
    #     list(block_list.keys()) if config[ENFORCE_BLOCKLIST] else []
    # )

    config = SimpleNamespace(**config)

    return (config, schema, allow_list, block_list)


def _get_device(gwy, dev_addr, ctl_addr=None, **kwargs) -> Optional[Any]:
    """A wrapper to enforce device filters."""
    err_msg = None

    if gwy.config.enforce_allow_list:
        if ctl_addr and ctl_addr.id not in gwy._include:
            err_msg = f"{ctl_addr.id} is in the {SCHEMA}, but not in the {ALLOW_LIST}"
        elif dev_addr.id not in gwy._include:
            err_msg = f"{dev_addr.id} is in the {SCHEMA}, but not in the {ALLOW_LIST}"

    elif gwy.config.enforce_block_list:
        if ctl_addr and ctl_addr.id in gwy._exclude:
            err_msg = f"{ctl_addr.id} is in the {SCHEMA}, but also in the {BLOCK_LIST}"
        elif dev_addr.id not in gwy._include:
            err_msg = f"{dev_addr.id} is in the {SCHEMA}, but also in the {BLOCK_LIST}"

    if err_msg:
        _LOGGER.error(f"%s: check the lists and the (cached) {SCHEMA}", err_msg)

    return gwy._get_device(dev_addr, ctl_addr=ctl_addr, **kwargs)


def load_system_schema(gwy, **kwargs) -> dict:
    """Process the schema, and the configuration and return True if it is valid."""
    # TODO: check a sensor is not a device in another zone

    gwy._clear_state()  # TODO: consider need for this (here, or at all)

    known_devices = kwargs.pop(ALLOW_LIST, {})
    known_devices.update(kwargs.pop(BLOCK_LIST, {}))

    [_get_device(gwy, addr(device_id)) for device_id in kwargs.pop(ATTR_ORPHANS, [])]

    if SCHEMA in kwargs:
        # ctl_id = kwargs.pop(ATTR_CONTROLLER)
        _load_system_schema(gwy, schema=kwargs[SCHEMA])
        gwy.evo = gwy.system_by_id.get(kwargs[SCHEMA][ATTR_CONTROLLER])

    elif kwargs.get(MAIN_CONTROLLER):
        [
            _load_system_schema(gwy, schema)
            for k, schema in kwargs.items()
            if re.match(DEVICE_ID_REGEX, k)
        ]
        gwy.evo = gwy.system_by_id.get(kwargs[MAIN_CONTROLLER])

    return {
        **known_devices,
        **{d: None for d in gwy.device_by_id if d not in known_devices},
    }


def shrink_dict(_dict):
    return {
        k: shrink_dict(dict(v)) if isinstance(v, dict) else v
        for k, v in _dict.items()
        if bool(v)
    }


def _load_system_schema(gwy, schema) -> Tuple[dict, dict]:
    # org_schema = schema
    schema = SYSTEM_SCHEMA(schema)

    ctl_id = schema[ATTR_CONTROLLER]
    profile = schema[ATTR_HTG_SYSTEM].get(ATTR_SYS_PROFILE)
    ctl = _get_device(gwy, addr(ctl_id), ctl_addr=addr(ctl_id), profile=profile)

    # if not ctl:
    #     return

    htg_ctl_id = schema[ATTR_HTG_SYSTEM].get(ATTR_HTG_CONTROL)
    if htg_ctl_id:
        ctl._evo._set_htg_control(_get_device(gwy, addr(htg_ctl_id), ctl_addr=ctl))

    dhw = schema.get(ATTR_DHW_SYSTEM, {})
    if dhw:
        ctl._evo._set_dhw(ctl._evo._get_dhw())

        dhw_sensor_id = dhw.get(ATTR_DHW_SENSOR)
        if dhw_sensor_id:
            ctl._evo.dhw._set_sensor(
                _get_device(gwy, addr(dhw_sensor_id), ctl_addr=ctl)
            )

        dhw_valve_id = dhw.get(ATTR_DHW_VALVE)
        if dhw_valve_id:
            ctl._evo.dhw._set_dhw_valve(
                _get_device(gwy, addr(dhw_valve_id), ctl_addr=ctl)
            )

        htg_valve_id = dhw.get(ATTR_DHW_VALVE_HTG)
        if htg_valve_id:
            ctl._evo.dhw._set_htg_valve(
                _get_device(gwy, addr(htg_valve_id), ctl_addr=ctl)
            )

    for zone_idx, attr in schema[ATTR_ZONES].items():
        zone = ctl._evo._get_zone(zone_idx, zone_type=attr.get(ATTR_ZONE_TYPE))

        sensor_id = attr.get(ATTR_ZONE_SENSOR)
        is_faked = None
        if isinstance(sensor_id, dict):
            is_faked = sensor_id.get("is_faked")
            sensor_id = sensor_id[ATTR_DEVICE_ID]

        if sensor_id:
            zone._set_sensor(
                _get_device(gwy, addr(sensor_id), ctl_addr=ctl, domain_id=zone_idx)
            )  # TODO: use domain_id=zone_idx or not
        if is_faked:
            zone.sensor._make_fake()

        for device_id in attr.get(ATTR_DEVICES, []):
            _get_device(gwy, addr(device_id), ctl_addr=ctl, domain_id=zone_idx)

    # TODO: not create orphans by default?
    orphan_ids = schema.get(ATTR_ORPHANS, [])
    if orphan_ids:
        [_get_device(gwy, addr(device_id), ctl_addr=ctl) for device_id in orphan_ids]

    ufh_ctl_ids = schema.get(ATTR_UFH_SYSTEM, {})
    if ufh_ctl_ids:
        for ufc_id, _ in ufh_ctl_ids.items():
            _ = _get_device(gwy, addr(ufc_id), ctl_addr=ctl)

    if False and DEV_MODE:
        import json

        src = json.dumps(shrink_dict(schema), sort_keys=True)
        dst = json.dumps(shrink_dict(gwy.system_by_id[ctl_id].schema), sort_keys=True)
        # assert dst == src, "They don't match!"
        print(src)
        print(dst)

    return ctl
