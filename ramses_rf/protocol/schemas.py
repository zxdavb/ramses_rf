#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Schema processor.
"""
from __future__ import annotations

import voluptuous as vol  # type: ignore[import]

SZ_LOG_FILE_NAME = "file_name"
SZ_LOG_ROTATE_BYTES = "rotate_bytes"
SZ_LOG_ROTATE_BACKUPS = "rotate_backups"

SZ_PACKET_LOG = "packet_log"  # output
SCH_PACKET_LOG = vol.Schema(
    {
        vol.Required(SZ_LOG_FILE_NAME): str,
        vol.Optional(SZ_LOG_ROTATE_BACKUPS, default=0): vol.Any(None, int),
        vol.Optional(SZ_LOG_ROTATE_BYTES, default=None): vol.Any(None, int),
    },
    extra=vol.PREVENT_EXTRA,
)

SZ_PORT_NAME = "port_name"
SZ_SERIAL_PORT = "serial_port"

SCH_SERIAL_CONFIG = vol.Schema(
    {
        vol.Optional("baudrate", default=115200): vol.All(
            vol.Coerce(int), vol.Any(57600, 115200)
        ),  # NB: HGI80 does not work, except at 115200 - so must be default
        vol.Optional("timeout", default=0): vol.Any(None, int),  # TODO: default None?
        vol.Optional("dsrdtr", default=False): bool,
        vol.Optional("rtscts", default=False): bool,
        vol.Optional("xonxoff", default=True): bool,  # set True to remove \x11
    },
    extra=vol.PREVENT_EXTRA,
)
SCH_SERIAL_PORT = vol.Schema(
    {
        vol.Required(SZ_SERIAL_PORT): vol.Any(
            None,
            str,
            SCH_SERIAL_CONFIG.extend({vol.Required(SZ_PORT_NAME): str}),
        )
    }
)
