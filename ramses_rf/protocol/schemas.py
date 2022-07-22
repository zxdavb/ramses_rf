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
# Packet logger config
SZ_LOG_ROTATE_BACKUPS = "rotate_backups"
SZ_LOG_ROTATE_BYTES = "rotate_bytes"

SCH_CONFIG_LOGGER = vol.Schema(
    {
        vol.Optional(SZ_LOG_ROTATE_BACKUPS, default=0): vol.Any(None, int),
        vol.Optional(SZ_LOG_ROTATE_BYTES): vol.Any(None, int),
    },
    extra=vol.PREVENT_EXTRA,
)

SZ_LOG_FILE_NAME = "file_name"
SZ_PACKET_LOG = "packet_log"

SCH_PACKET_LOG_NAME = vol.Any(None, str)
SCH_PACKET_LOG = SCH_CONFIG_LOGGER.extend(
    {vol.Required(SZ_LOG_FILE_NAME): SCH_PACKET_LOG_NAME}
)

#
# Serial port config
SZ_BAUDRATE = "baudrate"
SZ_DSRDTR = "dsrdtr"
SZ_RTSCTS = "rtscts"
SZ_TIMEOUT = "timeout"
SZ_XONXOFF = "xonxoff"

SCH_CONFIG_SERIAL = vol.Schema(
    {
        vol.Optional(SZ_BAUDRATE, default=115200): vol.All(
            vol.Coerce(int), vol.Any(57600, 115200)
        ),  # NB: HGI80 does not work, except at 115200 - so must be default
        vol.Optional(SZ_DSRDTR, default=False): bool,
        vol.Optional(SZ_RTSCTS, default=False): bool,
        vol.Optional(SZ_TIMEOUT, default=0): vol.Any(None, int),  # TODO: default None?
        vol.Optional(SZ_XONXOFF, default=True): bool,  # set True to remove \x11
    },
    extra=vol.PREVENT_EXTRA,
)

SZ_SERIAL_PORT = "serial_port"
SZ_SERIAL_PORT_CONFIG = "port_config"

SCH_SERIAL_PORT_CONFIG = vol.Schema(
    {vol.Required(SZ_SERIAL_PORT_CONFIG, default={}): SCH_CONFIG_SERIAL}
)

SZ_PORT_NAME = "port_name"
SCH_SERIAL_PORT_NAME = str
SCH_SERIAL_PORT = vol.Schema(
    {
        vol.Required(SZ_SERIAL_PORT): vol.Any(
            None,
            SCH_SERIAL_PORT_NAME,
            SCH_CONFIG_SERIAL.extend(
                {vol.Required(SZ_PORT_NAME): SCH_SERIAL_PORT_NAME}
            ),
        )
    }
)

#
# Device traits (basic)  # TODO: move from ..const
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
    {vol.Optional(SCH_DEVICE_ID_ANY): SCH_TRAITS},
    extra=vol.PREVENT_EXTRA,
)

#
# Engine configuration
SZ_BLOCK_LIST = "block_list"
SZ_KNOWN_LIST = "known_list"

SZ_DISABLE_SENDING = "disable_sending"
SZ_ENFORCE_KNOWN_LIST = f"enforce_{SZ_KNOWN_LIST}"
SZ_EVOFW_FLAG = "evofw_flag"
SZ_USE_REGEX = "use_regex"

SCH_CONFIG_ENGINE = vol.Schema(
    {
        vol.Optional(SZ_DISABLE_SENDING, default=False): bool,
        vol.Optional(SZ_ENFORCE_KNOWN_LIST, default=False): bool,
        vol.Optional(SZ_EVOFW_FLAG): vol.Any(None, str),
        vol.Optional(SZ_PACKET_LOG, default=None): vol.Any(None, SCH_PACKET_LOG),
        vol.Optional(SZ_SERIAL_PORT): SCH_CONFIG_SERIAL,
        vol.Optional(SZ_USE_REGEX): dict,
    },
    extra=vol.PREVENT_EXTRA,
)  # TODO: add enforce_known_list

SZ_INBOUND = "inbound"  # for use_regex (intentionally obscured)
SZ_OUTBOUND = "outbound"

#
# Global configuration for protocol layer
SZ_CONFIG = "config"

SCH_CONFIG_ENGINE_GLOBAL = vol.Schema(
    {
        # Engine Configuraton, incl. packet_log, serial_port params...
        vol.Optional(SZ_CONFIG, default={}): SCH_CONFIG_ENGINE,
        # Filter lists with Device traits...
        vol.Optional(SZ_KNOWN_LIST, default={}): vol.All(SCH_DEVICE, vol.Length(min=0)),
        vol.Optional(SZ_BLOCK_LIST, default={}): vol.All(SCH_DEVICE, vol.Length(min=0)),
    },
    extra=vol.PREVENT_EXTRA,
)


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


def normalise_packet_log_value(packet_log: None | dict | str) -> dict:
    """Convert a HA/client config dict into the library's own format."""
    if isinstance(packet_log, (type(None), dict)):
        return packet_log  # is None, or dict
    if isinstance(packet_log, str):
        return {SZ_LOG_FILE_NAME: packet_log}
    raise ValueError(f"expected None, dict or str, got: {type(packet_log)}")
