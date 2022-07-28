#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Schema processor for protocol (lower) layer.
"""
from __future__ import annotations

import logging

import voluptuous as vol  # type: ignore[import]

from .const import DEV_TYPE_MAP, DEVICE_ID_REGEX, __dev_mode__

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


#
# Packet log configuration
def NormalisePacketLog():
    def normalise_packet_log(node_value: str | dict) -> dict:
        if isinstance(node_value, str):
            return {
                SZ_FILE_NAME: node_value,
                SZ_ROTATE_BACKUPS: 0,
                SZ_ROTATE_BYTES: None,
            }
        return node_value

    return normalise_packet_log


SZ_ROTATE_BACKUPS = "rotate_backups"
SZ_ROTATE_BYTES = "rotate_bytes"

SCH_PACKET_LOG_CONFIG_DICT = {
    vol.Optional(SZ_ROTATE_BACKUPS, default=0): vol.Any(None, int),
    vol.Optional(SZ_ROTATE_BYTES): vol.Any(None, int),
}
SCH_PACKET_LOG_CONFIG = vol.Schema(SCH_PACKET_LOG_CONFIG_DICT, extra=vol.PREVENT_EXTRA)

SZ_FILE_NAME = "file_name"
SCH_PACKET_LOG_NAME = str

SZ_PACKET_LOG = "packet_log"
SCH_PACKET_LOG_DICT = {
    vol.Required(SZ_PACKET_LOG, default=None): vol.Any(
        None,
        vol.All(SCH_PACKET_LOG_NAME, NormalisePacketLog()),
        SCH_PACKET_LOG_CONFIG.extend({vol.Required(SZ_FILE_NAME): SCH_PACKET_LOG_NAME}),
    )
}
SCH_PACKET_LOG = vol.Schema(SCH_PACKET_LOG_DICT, extra=vol.PREVENT_EXTRA)


#
# Serial port configuration
def extract_serial_port(ser_config: dict) -> tuple[str, dict]:
    port_name = ser_config.get(SZ_PORT_NAME)
    port_config = {k: v for k, v in ser_config.items() if k != SZ_PORT_NAME}
    return port_name, port_config


SZ_BAUDRATE = "baudrate"
SZ_DSRDTR = "dsrdtr"
SZ_RTSCTS = "rtscts"
SZ_TIMEOUT = "timeout"
SZ_XONXOFF = "xonxoff"

SCH_SERIAL_PORT_CONFIG_DICT = {
    vol.Optional(SZ_BAUDRATE, default=115200): vol.All(
        vol.Coerce(int), vol.Any(57600, 115200)
    ),  # NB: HGI80 does not work, except at 115200 - so must be default
    vol.Optional(SZ_DSRDTR, default=False): bool,
    vol.Optional(SZ_RTSCTS, default=False): bool,
    vol.Optional(SZ_TIMEOUT, default=0): vol.Any(None, int),  # TODO: default None?
    vol.Optional(SZ_XONXOFF, default=True): bool,  # set True to remove \x11
}
SCH_SERIAL_PORT_CONFIG = vol.Schema(
    SCH_SERIAL_PORT_CONFIG_DICT, extra=vol.PREVENT_EXTRA
)

SZ_PORT_NAME = "port_name"
SCH_SERIAL_PORT_NAME = str

SZ_SERIAL_PORT = "serial_port"
SCH_SERIAL_PORT_DICT = {
    vol.Required(SZ_SERIAL_PORT): vol.Any(
        SCH_SERIAL_PORT_NAME,
        SCH_SERIAL_PORT_CONFIG.extend(
            {vol.Required(SZ_PORT_NAME): SCH_SERIAL_PORT_NAME}
        ),
    )
}
SCH_SERIAL_PORT = vol.Schema(SCH_SERIAL_PORT_DICT, extra=vol.PREVENT_EXTRA)


#
# Traits (of devices) configuraion (basic)  # TODO: moving from ..const
def ConvertNullToDict():
    def convert_null_to_dict(node_value) -> dict:
        if node_value is None:
            return {}
        return node_value

    return convert_null_to_dict


SZ_ALIAS = "alias"
SZ_CLASS = "class"
SZ_FAKED = "faked"

SCH_DEVICE_ID_ANY = vol.Match(DEVICE_ID_REGEX.ANY)
SCH_DEVICE_ID_SEN = vol.Match(DEVICE_ID_REGEX.SEN)
SCH_DEVICE_ID_CTL = vol.Match(DEVICE_ID_REGEX.CTL)
SCH_DEVICE_ID_DHW = vol.Match(DEVICE_ID_REGEX.DHW)
SCH_DEVICE_ID_HGI = vol.Match(DEVICE_ID_REGEX.HGI)
SCH_DEVICE_ID_APP = vol.Match(DEVICE_ID_REGEX.APP)
SCH_DEVICE_ID_BDR = vol.Match(DEVICE_ID_REGEX.BDR)
SCH_DEVICE_ID_UFC = vol.Match(DEVICE_ID_REGEX.UFC)

SCH_TRAITS_BASE = vol.Schema(
    {
        vol.Optional(SZ_ALIAS, default=None): vol.Any(None, str),
        vol.Optional(SZ_CLASS, default=None): vol.Any(
            *(DEV_TYPE_MAP[s] for s in DEV_TYPE_MAP.slugs()),
            *(s for s in DEV_TYPE_MAP.slugs()),
            None,
        ),
        vol.Optional(SZ_FAKED, default=None): vol.Any(None, bool),
        vol.Optional(vol.Remove("_note")): str,  # only for convenience, not used
    },
    extra=vol.PREVENT_EXTRA,
)

SCH_TRAITS_HEAT = SCH_TRAITS_BASE

SCH_TRAITS_HVAC_SCHEMES = ("itho", "nuaire", "orcon")
SCH_TRAITS_HVAC = SCH_TRAITS_BASE.extend(
    {
        vol.Optional("scheme", default="orcon"): vol.Any(*SCH_TRAITS_HVAC_SCHEMES),
    },
    extra=vol.PREVENT_EXTRA,
)

SCH_TRAITS = vol.Any(SCH_TRAITS_HEAT, SCH_TRAITS_HVAC)
SCH_DEVICE = vol.Schema(
    {
        vol.Optional(SCH_DEVICE_ID_ANY): vol.Any(
            vol.All(None, ConvertNullToDict()), SCH_TRAITS
        )
    },
    extra=vol.PREVENT_EXTRA,
)


#
# Device lists (Engine configuration)
SZ_BLOCK_LIST = "block_list"
SZ_KNOWN_LIST = "known_list"

SCH_GLOBAL_TRAITS_DICT = {  # Filter lists with Device traits...
    vol.Optional(SZ_KNOWN_LIST, default={}): vol.Any(
        vol.All(None, ConvertNullToDict()),
        vol.All(SCH_DEVICE, vol.Length(min=0)),
    ),
    vol.Optional(SZ_BLOCK_LIST, default={}): vol.Any(
        vol.All(None, ConvertNullToDict()),
        vol.All(SCH_DEVICE, vol.Length(min=0)),
    ),
}
SCH_GLOBAL_TRAITS = vol.Schema(SCH_GLOBAL_TRAITS_DICT, extra=vol.PREVENT_EXTRA)


#
# Engine configuration
SZ_DISABLE_SENDING = "disable_sending"
SZ_ENFORCE_KNOWN_LIST = f"enforce_{SZ_KNOWN_LIST}"
SZ_EVOFW_FLAG = "evofw_flag"
SZ_USE_REGEX = "use_regex"

SCH_ENGINE_DICT = {
    vol.Optional(SZ_DISABLE_SENDING, default=False): bool,
    vol.Optional(SZ_ENFORCE_KNOWN_LIST, default=False): bool,
    vol.Optional(SZ_EVOFW_FLAG): vol.Any(None, str),
    vol.Optional(SZ_USE_REGEX): dict,
}
SCH_ENGINE = vol.Schema(SCH_ENGINE_DICT, extra=vol.PREVENT_EXTRA)

SZ_INBOUND = "inbound"  # for use_regex (intentionally obscured)
SZ_OUTBOUND = "outbound"


#
# Global configuration for upper layer
SZ_CONFIG = "config"
SZ_PORT_CONFIG = "port_config"

SCH_GLOBAL_ENGINE = vol.Schema(
    {
        vol.Optional(SZ_CONFIG, default={}): SCH_ENGINE,
        # packet_log: is optional, serial_port: params only...
        vol.Optional(SZ_PACKET_LOG, default=None): vol.Any(None, SCH_PACKET_LOG),
        vol.Optional(SZ_PORT_CONFIG): SCH_SERIAL_PORT_CONFIG,
    },
    extra=vol.PREVENT_EXTRA,
).extend(SCH_GLOBAL_TRAITS_DICT)


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
