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
from typing import Any

import voluptuous as vol

from .const import (
    DEFAULT_MAX_ZONES,
    DEV_ROLE,
    DEV_ROLE_MAP,
    DEV_TYPE,
    DEV_TYPE_MAP,
    DEVICE_ID_REGEX,
    DONT_CREATE_MESSAGES,
    SZ_ALIAS,
    SZ_CLASS,
    SZ_FAKED,
    SZ_ZONE_IDX,
    ZON_ROLE_MAP,
    SystemType,
    __dev_mode__,
)
from .helpers import shrink
from .protocol import PACKET_LOG, PACKET_LOG_SCHEMA, SERIAL_CONFIG_SCHEMA
from .protocol.const import (
    SZ_ACTUATORS,
    SZ_DEVICES,
    SZ_INBOUND,
    SZ_NAME,
    SZ_OUTBOUND,
    SZ_SENSOR,
    SZ_ZONE_TYPE,
    SZ_ZONES,
)
from .protocol.transport import DEV_HACK_REGEX, SZ_BLOCK_LIST, SZ_KNOWN_LIST

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

# schema strings
SCHEMA = "schema"
SZ_MAIN_CONTROLLER = "main_controller"

SZ_CONTROLLER = DEV_TYPE_MAP[DEV_TYPE.CTL]
SZ_TCS_SYSTEM = "system"
SZ_APPLIANCE_CONTROL = DEV_ROLE_MAP[DEV_ROLE.APP]
SZ_ORPHANS = "orphans"

SZ_DHW_SYSTEM = "stored_hotwater"
SZ_DHW_SENSOR = DEV_ROLE_MAP[DEV_ROLE.DHW]
SZ_DHW_VALVE = DEV_ROLE_MAP[DEV_ROLE.HTG]
SZ_HTG_VALVE = DEV_ROLE_MAP[DEV_ROLE.HT1]

SZ_SENSOR_FAKED = "sensor_faked"


SZ_UFH_SYSTEM = "underfloor_heating"
SZ_UFH_CTL = DEV_TYPE_MAP[DEV_TYPE.UFC]  # ufh_controller
SZ_CIRCUITS = "circuits"

DEV_REGEX_ANY = vol.Match(DEVICE_ID_REGEX.ANY)
DEV_REGEX_SEN = vol.Match(DEVICE_ID_REGEX.SEN)
DEV_REGEX_CTL = vol.Match(DEVICE_ID_REGEX.CTL)
DEV_REGEX_DHW = vol.Match(DEVICE_ID_REGEX.DHW)
DEV_REGEX_HGI = vol.Match(DEVICE_ID_REGEX.HGI)
DEV_REGEX_APP = vol.Match(DEVICE_ID_REGEX.APP)
DEV_REGEX_BDR = vol.Match(DEVICE_ID_REGEX.BDR)
DEV_REGEX_UFC = vol.Match(DEVICE_ID_REGEX.UFC)

HEAT_ZONES_STRS = tuple(ZON_ROLE_MAP[t] for t in ZON_ROLE_MAP.HEAT_ZONES)

DOMAIN_ID = vol.Match(r"^[0-9A-F]{2}$")
UFH_IDX_REGEX = r"^0[0-8]$"
UFH_IDX = vol.Match(UFH_IDX_REGEX)
ZONE_IDX = vol.Match(r"^0[0-9AB]$")  # TODO: what if > 12 zones? (e.g. hometronics)

INPUT_FILE = "input_file"

# Config parameters
DEBUG_MODE = "debug_mode"

SZ_CONFIG = "config"
DISABLE_DISCOVERY = "disable_discovery"
DISABLE_SENDING = "disable_sending"
ENABLE_EAVESDROP = "enable_eavesdrop"
ENFORCE_KNOWN_LIST = f"enforce_{SZ_KNOWN_LIST}"
EVOFW_FLAG = "evofw_flag"
SZ_MAX_ZONES = "max_zones"
REDUCE_PROCESSING = "reduce_processing"
SERIAL_CONFIG = "serial_config"
USE_ALIASES = "use_aliases"  # use friendly device names from known_list
USE_SCHEMA = "use_schema"
USE_REGEX = "use_regex"


def renamed(new_key):
    def func(value):
        raise vol.Invalid(f"the key name has changed: rename it to '{new_key}'")

    return func


# 1/3: Schemas for Configuration

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional(DISABLE_DISCOVERY, default=False): bool,
        vol.Optional(DISABLE_SENDING, default=False): bool,
        vol.Optional(ENABLE_EAVESDROP, default=False): bool,
        vol.Optional(REDUCE_PROCESSING, default=0): vol.All(
            int, vol.Range(min=0, max=DONT_CREATE_MESSAGES)
        ),
        vol.Optional(SZ_MAX_ZONES, default=DEFAULT_MAX_ZONES): vol.All(
            int, vol.Range(min=1, max=16)
        ),
        vol.Optional(USE_SCHEMA, default=True): vol.Any(None, bool),
        vol.Optional(ENFORCE_KNOWN_LIST, default=None): vol.Any(None, bool),
        vol.Optional(USE_ALIASES, default=None): vol.Any(None, bool),
        vol.Optional(EVOFW_FLAG, default=None): vol.Any(None, str),
        vol.Optional(USE_REGEX, default={}): dict,
    },
    extra=vol.ALLOW_EXTRA,  # TODO: remove for production
)

SCHEMA_DEV = vol.Any(
    {
        vol.Optional(SZ_ALIAS, default=None): vol.Any(None, str),
        vol.Optional(SZ_CLASS, default=None): vol.Any(
            None, *(DEV_TYPE_MAP[s] for s in DEV_TYPE_MAP.slugs())
        ),
        vol.Optional(SZ_FAKED, default=None): vol.Any(None, bool),
        vol.Optional("_note"): str,  # only a convenience, not used
    },
)
_SCHEMA_DEV = vol.Schema(
    {vol.Optional(DEV_REGEX_ANY): SCHEMA_DEV},
    extra=vol.PREVENT_EXTRA,
)

# 2/3: Schemas for Heating systems
SYSTEM_KLASS = (SystemType.EVOHOME, SystemType.HOMETRONICS, SystemType.SUNDIAL)

SCHEMA_TCS = vol.Schema(
    {
        vol.Required(SZ_APPLIANCE_CONTROL, default=None): vol.Any(None, DEV_REGEX_APP),
        vol.Optional("heating_control"): renamed(SZ_APPLIANCE_CONTROL),
        vol.Optional(SZ_CLASS, default=SystemType.EVOHOME): vol.Any(*SYSTEM_KLASS),
    },
    extra=vol.PREVENT_EXTRA,
)
SCHEMA_DHW = vol.Schema(
    {
        vol.Optional(SZ_SENSOR, default=None): vol.Any(None, DEV_REGEX_DHW),
        vol.Optional(SZ_DHW_VALVE, default=None): vol.Any(None, DEV_REGEX_BDR),
        vol.Optional(SZ_HTG_VALVE, default=None): vol.Any(None, DEV_REGEX_BDR),
        vol.Optional(SZ_DHW_SENSOR): renamed(SZ_SENSOR),
    }
)
UFC_CIRCUIT = vol.Schema(
    {
        vol.Required(UFH_IDX): vol.Any(
            {vol.Optional(SZ_ZONE_IDX): vol.Any(ZONE_IDX)},
        ),
    }
)
SCHEMA_UFH = vol.Schema(
    {
        vol.Required(DEV_REGEX_UFC): vol.Any(
            None, {vol.Optional(SZ_CIRCUITS): vol.Any(None, dict)}
        )
    }
)
SCHEMA_UFH = vol.All(SCHEMA_UFH, vol.Length(min=1, max=3))

SCHEMA_ZON = vol.Schema(  # vol.All([DEV_REGEX_ANY], vol.Length(min=0))(['01:123456'])
    {
        vol.Optional(SZ_CLASS, default=None): vol.Any(None, *HEAT_ZONES_STRS),
        vol.Optional(SZ_SENSOR, default=None): vol.Any(None, DEV_REGEX_SEN),
        vol.Optional(SZ_DEVICES): renamed(SZ_ACTUATORS),
        vol.Optional(SZ_ACTUATORS, default=[]): vol.All(
            [DEV_REGEX_ANY], vol.Length(min=0)
        ),
        vol.Optional(SZ_ZONE_TYPE): renamed(SZ_CLASS),
        vol.Optional("zone_sensor"): renamed(SZ_SENSOR),
        # vol.Optional(SZ_SENSOR_FAKED): bool,
        vol.Optional(f"_{SZ_NAME}"): vol.Any(str, None),
    },
    extra=vol.PREVENT_EXTRA,
)
# SCHEMA_ZON({SZ_CLASS: None, SZ_DEVICES: None})  # TODO: remove me
SCHEMA_ZONES = vol.All(
    vol.Schema({vol.Required(ZONE_IDX): SCHEMA_ZON}),
    vol.Length(min=1, max=DEFAULT_MAX_ZONES),
)
SCHEMA_SYS = vol.Schema(
    {
        # vol.Required(SZ_CONTROLLER): DEV_REGEX_CTL,
        vol.Optional(SZ_TCS_SYSTEM, default={}): vol.Any({}, SCHEMA_TCS),
        vol.Optional(SZ_DHW_SYSTEM, default={}): vol.Any({}, SCHEMA_DHW),
        vol.Optional(SZ_UFH_SYSTEM, default={}): vol.Any({}, SCHEMA_UFH),
        vol.Optional(SZ_ORPHANS, default=[]): vol.Any([], [DEV_REGEX_ANY]),
        vol.Optional(SZ_ZONES, default={}): vol.Any({}, SCHEMA_ZONES),
    },
    extra=vol.PREVENT_EXTRA,
)


# 3/3: Global Schemas
SCHEMA_GLOBAL_CONFIG = vol.Schema(
    {
        vol.Required(SZ_CONFIG): CONFIG_SCHEMA.extend(
            {
                vol.Optional(SERIAL_CONFIG): SERIAL_CONFIG_SCHEMA,
                vol.Optional(PACKET_LOG, default={}): vol.Any({}, PACKET_LOG_SCHEMA),
            }
        ),
        vol.Optional(SZ_KNOWN_LIST, default={}): vol.All(
            _SCHEMA_DEV, vol.Length(min=0)
        ),
        vol.Optional(SZ_BLOCK_LIST, default={}): vol.All(
            _SCHEMA_DEV, vol.Length(min=0)
        ),
    },
    extra=vol.REMOVE_EXTRA,
)


def load_config(
    serial_port, input_file, **kwargs
) -> tuple[SimpleNamespace, dict, dict, dict]:
    """Process the configuration, including any filter lists.

    Returns:
     - config (includes config.enforce_known_list)
     - schema (processed further later on)
     - known_list (is a dict)
     - block_list (is a dict)
    """

    config = SCHEMA_GLOBAL_CONFIG(kwargs)
    schema = {k: v for k, v in kwargs.items() if k not in config and k[:1] != "_"}

    block_list = config.pop(SZ_BLOCK_LIST)
    known_list = config.pop(SZ_KNOWN_LIST)

    config = CONFIG_SCHEMA.extend(
        {vol.Optional(SERIAL_CONFIG, default={}): SERIAL_CONFIG_SCHEMA}
    )(config[SZ_CONFIG])

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

    return (config, schema, known_list, block_list)


def update_config(config, known_list, block_list) -> dict:
    """Determine which device filter to use, if any: known_list or block_list."""

    if SZ_INBOUND not in config[USE_REGEX]:  # TODO: move to voluptuous
        config[USE_REGEX][SZ_INBOUND] = {}
    if SZ_OUTBOUND not in config[USE_REGEX]:
        config[USE_REGEX][SZ_OUTBOUND] = {}

    if DEV_HACK_REGEX:  # HACK: for DEV/TEST convenience, not for production
        config[USE_REGEX][SZ_INBOUND].update(
            {
                "( 03:.* 03:.* (1060|2389|30C9) 003) ..": "\\1 00",
                # "02:153425": "20:153425",
            }
        )

    if config[ENFORCE_KNOWN_LIST] and not known_list:
        _LOGGER.warning(
            f"An empty {SZ_KNOWN_LIST} was provided, so it cant be used "
            f"as a whitelist (device_id filter)"
        )
        config[ENFORCE_KNOWN_LIST] = False

    if config[ENFORCE_KNOWN_LIST]:
        _LOGGER.info(
            f"The {SZ_KNOWN_LIST} will be used "
            f"as a whitelist (device_id filter), length = {len(known_list)}"
        )
        _LOGGER.debug(f"known_list = {known_list}")

    elif block_list:
        _LOGGER.info(
            f"The {SZ_BLOCK_LIST} will be used "
            f"as a blacklist (device_id filter), length = {len(block_list)}"
        )
        _LOGGER.debug(f"block_list = {block_list}")

    elif known_list:
        _LOGGER.warning(
            f"It is strongly recommended to use the {SZ_KNOWN_LIST} "
            f"as a whitelist (device_id filter), configure: {ENFORCE_KNOWN_LIST} = True"
        )
        _LOGGER.debug(f"known_list = {known_list}")

    else:
        _LOGGER.warning(
            f"It is strongly recommended to provide a {SZ_KNOWN_LIST}, and use it "
            f"as a whitelist (device_id filter), configure: {ENFORCE_KNOWN_LIST} = True"
        )


def _get_device(gwy, dev_id, **kwargs) -> Any:  # Device
    """Raise an LookupError if a device_id is filtered out by a list.

    The underlying method is wrapped only to provide a better error message.
    """

    def check_filter_lists(dev_id: str) -> None:
        """Raise an LookupError if a device_id is filtered out by a list."""

        err_msg = None
        if gwy.config.enforce_known_list and dev_id not in gwy._include:
            err_msg = f"it is in the {SCHEMA}, but not in the {SZ_KNOWN_LIST}"
        if dev_id in gwy._exclude:
            err_msg = f"it is in the {SCHEMA}, but also in the {SZ_BLOCK_LIST}"

        if err_msg:
            raise LookupError(
                f"Can't create {dev_id}: {err_msg} (check the lists and the {SCHEMA})"
            )

    check_filter_lists(dev_id)

    return gwy.get_device(dev_id, **kwargs)


def load_schema(gwy, **kwargs) -> dict:
    """Process the schema, and the configuration and return True if it is valid."""

    [
        load_system(gwy, ctl_id, schema)
        for ctl_id, schema in kwargs.items()
        if re.match(DEVICE_ID_REGEX.ANY, ctl_id)
    ]
    if kwargs.get(SZ_MAIN_CONTROLLER):
        gwy._tcs = gwy.system_by_id.get(kwargs[SZ_MAIN_CONTROLLER])

    [
        _get_device(gwy, device_id, disable_warning=True)
        for device_id in kwargs.pop(SZ_ORPHANS, [])
    ]


def load_system(gwy, ctl_id, schema) -> Any:  # System
    """Create a system using its schema."""
    # print(schema)
    # schema = SCHEMA_ZON(schema)

    ctl = _get_device(gwy, ctl_id)
    ctl.tcs._update_schema(**schema)  # TODO

    for dev_id in schema.get(SZ_UFH_SYSTEM, {}).keys():  # UFH controllers
        _get_device(gwy, dev_id, parent=ctl)  # , **_schema)

    for dev_id in schema.get(SZ_ORPHANS, []):
        _get_device(gwy, dev_id, parent=ctl)

    if False and DEV_MODE:
        import json

        src = json.dumps(shrink(schema), sort_keys=True)
        dst = json.dumps(shrink(gwy.system_by_id[ctl.id].schema), sort_keys=True)
        # assert dst == src, "They don't match!"
        print(src)
        print(dst)

    return ctl.tcs
