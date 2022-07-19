#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Schema processor.
"""
from __future__ import annotations

import logging
import re
from types import SimpleNamespace
from typing import Any, TextIO

import voluptuous as vol  # type: ignore[import]

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
from .protocol.const import (
    SZ_ACTUATORS,
    SZ_DEVICES,
    SZ_NAME,
    SZ_SENSOR,
    SZ_ZONE_TYPE,
    SZ_ZONES,
)
from .protocol.schemas import (
    SCH_CONFIG_ENGINE,
    SZ_DISABLE_SENDING,
    SZ_ENFORCE_KNOWN_LIST,
)
from .protocol.transport import SZ_BLOCK_LIST, SZ_KNOWN_LIST

# from .systems import _SystemT  # circular import

# TODO: move max_zones into system-specific location, ?profile


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)

# schema strings
SZ_SCHEMA = "schema"
SZ_MAIN_CONTROLLER = "main_controller"

SZ_CONTROLLER = DEV_TYPE_MAP[DEV_TYPE.CTL]
SZ_SYSTEM = "system"
SZ_APPLIANCE_CONTROL = DEV_ROLE_MAP[DEV_ROLE.APP]
SZ_ORPHANS = "orphans"
SZ_ORPHANS_HEAT = "orphans_heat"
SZ_ORPHANS_HVAC = "orphans_hvac"

SZ_DHW_SYSTEM = "stored_hotwater"
SZ_DHW_SENSOR = DEV_ROLE_MAP[DEV_ROLE.DHW]
SZ_DHW_VALVE = DEV_ROLE_MAP[DEV_ROLE.HTG]
SZ_HTG_VALVE = DEV_ROLE_MAP[DEV_ROLE.HT1]

SZ_SENSOR_FAKED = "sensor_faked"


SZ_UFH_SYSTEM = "underfloor_heating"
SZ_UFH_CTL = DEV_TYPE_MAP[DEV_TYPE.UFC]  # ufh_controller
SZ_CIRCUITS = "circuits"

SCH_DEVICE_ANY = vol.Match(DEVICE_ID_REGEX.ANY)
SCH_DEVICE_SEN = vol.Match(DEVICE_ID_REGEX.SEN)
SCH_DEVICE_CTL = vol.Match(DEVICE_ID_REGEX.CTL)
SCH_DEVICE_DHW = vol.Match(DEVICE_ID_REGEX.DHW)
SCH_DEVICE_HGI = vol.Match(DEVICE_ID_REGEX.HGI)
SCH_DEVICE_APP = vol.Match(DEVICE_ID_REGEX.APP)
SCH_DEVICE_BDR = vol.Match(DEVICE_ID_REGEX.BDR)
SCH_DEVICE_UFC = vol.Match(DEVICE_ID_REGEX.UFC)

HEAT_ZONES_STRS = tuple(ZON_ROLE_MAP[t] for t in ZON_ROLE_MAP.HEAT_ZONES)

SCH_DOM_ID = vol.Match(r"^[0-9A-F]{2}$")
SCH_UFH_IDX = vol.Match(r"^0[0-8]$")
SCH_ZON_IDX = vol.Match(r"^0[0-9AB]$")  # TODO: what if > 12 zones? (e.g. hometronics)


# Config parameters
SZ_CONFIG = "config"
SZ_DISABLE_DISCOVERY = "disable_discovery"
SZ_ENABLE_EAVESDROP = "enable_eavesdrop"
SZ_MAX_ZONES = "max_zones"
SZ_REDUCE_PROCESSING = "reduce_processing"
SZ_SERIAL_CONFIG = "serial_config"
SZ_USE_ALIASES = "use_aliases"  # use friendly device names from known_list
SZ_USE_SCHEMA = "use_schema"
SZ_USE_NATIVE_OT = "use_native_ot"  # favour OT (3220s) over RAMSES


SZ_REMOTES = "remotes"
SZ_SENSORS = "sensors"


def renamed(new_key):
    def func(value):
        raise vol.Invalid(f"the key name has changed: rename it to '{new_key}'")

    return func


# 2/5: Schemas for Device traits (known_list, block_list)
SCH_TRAITS_BASE = vol.Schema(
    {
        vol.Optional(SZ_ALIAS, default=None): vol.Any(None, str),
        vol.Optional(SZ_CLASS, default=None): vol.Any(
            *(DEV_TYPE_MAP[s] for s in DEV_TYPE_MAP.slugs()),
            *(s for s in DEV_TYPE_MAP.slugs()),
            None,
        ),
        vol.Optional(SZ_FAKED, default=None): vol.Any(None, bool),
        vol.Optional("_note"): str,  # only a convenience, not used
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_TRAITS_HEAT = SCH_TRAITS_BASE
SCH_TRAITS_HVAC_BRANDS = ("itho", "nuaire", "orcon")
SCH_TRAITS_HVAC = SCH_TRAITS_BASE.extend(
    {
        vol.Optional("style", default="orcon"): vol.Any(None, *SCH_TRAITS_HVAC_BRANDS),
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_TRAITS = vol.Any(SCH_TRAITS_HEAT, SCH_TRAITS_HVAC)
SCH_DEVICE = vol.Schema(
    {vol.Optional(SCH_DEVICE_ANY): SCH_TRAITS},
    extra=vol.PREVENT_EXTRA,
)

# 3/5: Schemas for CH/DHW systems, aka Heat/TCS (temp control systems)
SCH_TCS_SYS_CLASS = (SystemType.EVOHOME, SystemType.HOMETRONICS, SystemType.SUNDIAL)
SCH_TCS_SYS = vol.Schema(
    {
        vol.Required(SZ_APPLIANCE_CONTROL, default=None): vol.Any(None, SCH_DEVICE_APP),
        vol.Optional("heating_control"): renamed(SZ_APPLIANCE_CONTROL),
        vol.Optional(SZ_CLASS, default=SystemType.EVOHOME): vol.Any(*SCH_TCS_SYS_CLASS),
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_TCS_DHW = vol.Schema(
    {
        vol.Optional(SZ_SENSOR, default=None): vol.Any(None, SCH_DEVICE_DHW),
        vol.Optional(SZ_DHW_VALVE, default=None): vol.Any(None, SCH_DEVICE_BDR),
        vol.Optional(SZ_HTG_VALVE, default=None): vol.Any(None, SCH_DEVICE_BDR),
        vol.Optional(SZ_DHW_SENSOR): renamed(SZ_SENSOR),
    },
    extra=vol.PREVENT_EXTRA,
)
_CH_TCS_UFH_CIRCUIT = vol.Schema(
    {
        vol.Required(SCH_UFH_IDX): vol.Any(
            {vol.Optional(SZ_ZONE_IDX): vol.Any(SCH_ZON_IDX)},
        ),
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_TCS_UFH = vol.All(
    vol.Schema(
        {
            vol.Required(SCH_DEVICE_UFC): vol.Any(
                None, {vol.Optional(SZ_CIRCUITS): vol.Any(None, dict)}
            )
        }
    ),
    vol.Length(min=1, max=3),
    extra=vol.PREVENT_EXTRA,
)
SCH_TCS_ZONES_ZON = vol.Schema(
    {
        vol.Optional(SZ_CLASS, default=None): vol.Any(None, *HEAT_ZONES_STRS),
        vol.Optional(SZ_SENSOR, default=None): vol.Any(None, SCH_DEVICE_SEN),
        vol.Optional(SZ_DEVICES): renamed(SZ_ACTUATORS),
        vol.Optional(SZ_ACTUATORS, default=[]): vol.All(
            [SCH_DEVICE_ANY], vol.Length(min=0)
        ),
        vol.Optional(SZ_ZONE_TYPE): renamed(SZ_CLASS),
        vol.Optional("zone_sensor"): renamed(SZ_SENSOR),
        # vol.Optional(SZ_SENSOR_FAKED): bool,
        vol.Optional(f"_{SZ_NAME}"): vol.Any(str, None),
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_TCS_ZONES = vol.All(
    vol.Schema({vol.Required(SCH_ZON_IDX): SCH_TCS_ZONES_ZON}),
    vol.Length(min=1, max=DEFAULT_MAX_ZONES),
    extra=vol.PREVENT_EXTRA,
)
SCH_TCS = vol.Schema(
    {
        vol.Optional(SZ_SYSTEM, default={}): vol.Any({}, SCH_TCS_SYS),
        vol.Optional(SZ_DHW_SYSTEM, default={}): vol.Any({}, SCH_TCS_DHW),
        vol.Optional(SZ_UFH_SYSTEM, default={}): vol.Any({}, SCH_TCS_UFH),
        vol.Optional(SZ_ORPHANS, default=[]): vol.Any([], [SCH_DEVICE_ANY]),
        vol.Optional(SZ_ZONES, default={}): vol.Any({}, SCH_TCS_ZONES),
        vol.Optional("is_tcs"): True,
    },
    extra=vol.PREVENT_EXTRA,
)

# 4/5: Schemas for Ventilation control systems, aka HVAC/VCS
SCH_VCS_DATA = vol.Schema(
    {
        vol.Optional(SZ_REMOTES, default=[]): vol.Any([], [SCH_DEVICE_ANY]),
        vol.Optional(SZ_SENSORS, default=[]): vol.Any([], [SCH_DEVICE_ANY]),
        vol.Optional("is_vcs"): True,
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_VCS_KEYS = vol.Schema(
    {
        vol.Required(
            vol.Any(SZ_REMOTES, SZ_SENSORS),
            msg=(
                "The ventilation control system schema must include at least "
                f"one of [{SZ_REMOTES}, {SZ_SENSORS}]"
            ),
        ): object
    },
    extra=vol.ALLOW_EXTRA,  # must be ALLOW_EXTRA, as is a subset of SCH_VCS_DATA
)
SCH_VCS = vol.All(SCH_VCS_KEYS, SCH_VCS_DATA)

# 1/5: Schema for Configuration of engine/parser
SCH_CONFIG_GWY = SCH_CONFIG_ENGINE.extend(
    {
        vol.Optional(SZ_DISABLE_DISCOVERY, default=False): bool,
        vol.Optional(SZ_ENABLE_EAVESDROP, default=False): bool,
        vol.Optional(SZ_MAX_ZONES, default=DEFAULT_MAX_ZONES): vol.All(
            int, vol.Range(min=1, max=16)
        ),
        vol.Optional(SZ_REDUCE_PROCESSING, default=0): vol.All(
            int, vol.Range(min=0, max=DONT_CREATE_MESSAGES)
        ),
        vol.Optional(SZ_USE_ALIASES, default=False): bool,
        vol.Optional(SZ_USE_NATIVE_OT, default=False): bool,
    },
    extra=vol.PREVENT_EXTRA,
)

# 5/5: the Global Schema
SCH_GLOBAL_CONFIG = vol.Schema(
    {
        vol.Optional(SZ_CONFIG): SCH_CONFIG_GWY,
        vol.Optional(SCH_DEVICE_CTL): vol.All(SCH_TCS, vol.Length(min=0)),
        vol.Optional(SCH_DEVICE_ANY): vol.All(SCH_VCS, vol.Length(min=0)),
        vol.Optional(SZ_KNOWN_LIST, default={}): vol.All(SCH_DEVICE, vol.Length(min=0)),
        vol.Optional(SZ_BLOCK_LIST, default={}): vol.All(SCH_DEVICE, vol.Length(min=0)),
    },
    extra=vol.PREVENT_EXTRA,  # Also TCSs, VCSs, known_list and block_list
)


def load_config(
    serial_port: None | str, input_file: TextIO, **kwargs
) -> tuple[SimpleNamespace, dict, dict, dict]:
    """Process the configuration, including any filter lists.

    Returns:
     - config (includes config.enforce_known_list)
     - schema (processed further later on)
     - known_list (is a dict)
     - block_list (is a dict)
    """

    schema = SCH_GLOBAL_CONFIG({k: v for k, v in kwargs.items() if k[:1] != "_"})
    config = schema.pop(SZ_CONFIG)
    block_list = schema.pop(SZ_BLOCK_LIST)
    known_list = schema.pop(SZ_KNOWN_LIST)

    if serial_port and input_file:
        _LOGGER.warning(
            "Serial port was specified (%s), so input file (%s) will be ignored",
            serial_port,
            input_file,
        )
    elif serial_port is None:
        config[SZ_DISABLE_SENDING] = True

    if config[SZ_DISABLE_SENDING]:
        config[SZ_DISABLE_DISCOVERY] = True

    if config[SZ_ENABLE_EAVESDROP]:
        _LOGGER.warning(
            f"{SZ_ENABLE_EAVESDROP} enabled: this is strongly discouraged"
            " for routine use (there be dragons here)"
        )

    config[SZ_ENFORCE_KNOWN_LIST] = select_filter_mode(
        config[SZ_ENFORCE_KNOWN_LIST], known_list, block_list
    )

    return (SimpleNamespace(**config), schema, known_list, block_list)


def select_filter_mode(
    enforce_known_list: bool, known_list: list, block_list: list
) -> bool:
    """Determine which device filter to use, if any.

    Either:
     - allow if device_id in known_list, or
     - block if device_id in block_list (could be empty)
    """

    if enforce_known_list and not known_list:
        _LOGGER.warning(
            f"An empty {SZ_KNOWN_LIST} was provided, so it cant be used "
            f"as a whitelist (device_id filter)"
        )
        enforce_known_list = False

    if enforce_known_list:
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
            f"as a whitelist (device_id filter), configure: {SZ_ENFORCE_KNOWN_LIST} = True"
        )
        _LOGGER.debug(f"known_list = {known_list}")

    else:
        _LOGGER.warning(
            f"It is strongly recommended to provide a {SZ_KNOWN_LIST}, and use it "
            f"as a whitelist (device_id filter), configure: {SZ_ENFORCE_KNOWN_LIST} = True"
        )

    return enforce_known_list


def _get_device(gwy, dev_id: str, **kwargs) -> Any:  # Device
    """Raise an LookupError if a device_id is filtered out by a list.

    The underlying method is wrapped only to provide a better error message.
    """

    def check_filter_lists(dev_id: str) -> None:
        """Raise an LookupError if a device_id is filtered out by a list."""

        err_msg = None
        if gwy.config.enforce_known_list and dev_id not in gwy._include:
            err_msg = f"it is in the {SZ_SCHEMA}, but not in the {SZ_KNOWN_LIST}"
        if dev_id in gwy._exclude:
            err_msg = f"it is in the {SZ_SCHEMA}, but also in the {SZ_BLOCK_LIST}"

        if err_msg:
            raise LookupError(
                f"Can't create {dev_id}: {err_msg} (check the lists and the {SZ_SCHEMA})"
            )

    check_filter_lists(dev_id)

    return gwy.get_device(dev_id, **kwargs)


def load_schema(gwy, **kwargs) -> None:
    """Process the schema, and the configuration and return True if it is valid."""

    [
        load_tcs(gwy, ctl_id, schema)
        for ctl_id, schema in kwargs.items()
        if re.match(DEVICE_ID_REGEX.ANY, ctl_id) and SZ_REMOTES not in schema
    ]
    if kwargs.get(SZ_MAIN_CONTROLLER):
        gwy._tcs = gwy.system_by_id.get(kwargs[SZ_MAIN_CONTROLLER])
    [
        load_fan(gwy, fan_id, schema)
        for fan_id, schema in kwargs.items()
        if re.match(DEVICE_ID_REGEX.ANY, fan_id) and SZ_REMOTES in schema
    ]
    [
        _get_device(gwy, device_id)
        for key in (SZ_ORPHANS_HEAT, SZ_ORPHANS_HVAC)
        for device_id in kwargs.pop(key, [])
    ]


def load_fan(gwy, fan_id: str, schema: dict) -> Any:  # Device
    """Create a FAN using its schema (i.e. with remotes, sensors)."""

    fan = _get_device(gwy, fan_id)
    # fan._update_schema(**schema)  # TODO

    return fan


def load_tcs(gwy, ctl_id: str, schema: dict) -> Any:  # System
    """Create a TCS using its schema."""
    # print(schema)
    # schema = SCH_TCS_ZONES_ZON(schema)

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
