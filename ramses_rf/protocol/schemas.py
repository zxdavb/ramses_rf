#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Schema processor.
"""
from __future__ import annotations

import voluptuous as vol  # type: ignore[import]

# Packet logger config
SZ_LOG_ROTATE_BACKUPS = "rotate_backups"
SZ_LOG_ROTATE_BYTES = "rotate_bytes"

SCH_CONFIG_LOGGER = vol.Schema(
    {
        vol.Optional(SZ_LOG_ROTATE_BACKUPS, default=0): vol.Any(None, int),
        vol.Optional(SZ_LOG_ROTATE_BYTES, default=None): vol.Any(None, int),
    },
    extra=vol.PREVENT_EXTRA,
)

SZ_LOG_FILE_NAME = "file_name"
SZ_PACKET_LOG = "packet_log"

SCH_PACKET_LOG = vol.Schema(
    {
        vol.Required(SZ_PACKET_LOG): vol.Any(
            None,
            str,
            SCH_CONFIG_LOGGER.extend({vol.Required(SZ_LOG_FILE_NAME): str}),
        )
    }
)

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

SZ_PORT_NAME = "port_name"
SZ_SERIAL_PORT = "serial_port"

SCH_SERIAL_PORT = vol.Schema(
    {
        vol.Required(SZ_SERIAL_PORT): vol.Any(
            None,
            str,
            SCH_CONFIG_SERIAL.extend({vol.Required(SZ_PORT_NAME): str}),
        )
    }
)

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
        vol.Optional(SZ_EVOFW_FLAG, default=None): vol.Any(None, str),
        vol.Optional(SZ_PACKET_LOG, default={}): vol.Any({}, SCH_PACKET_LOG),
        vol.Optional(SZ_SERIAL_PORT, default={}): SCH_CONFIG_SERIAL,
        vol.Optional(SZ_USE_REGEX, default={}): dict,
    },
    extra=vol.PREVENT_EXTRA,
)  # TODO: add enforce_known_list

SZ_INBOUND = "inbound"
SZ_OUTBOUND = "outbound"
