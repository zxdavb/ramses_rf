#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Schema processor.
"""

import voluptuous as vol

LOG_FILE_NAME = "file_name"
LOG_ROTATE_BYTES = "rotate_bytes"
LOG_ROTATE_COUNT = "rotate_backups"

PACKET_LOG = "packet_log"  # output
PACKET_LOG_SCHEMA = vol.Schema(
    {
        vol.Required(LOG_FILE_NAME, default=None): vol.Any(None, str),
        vol.Optional(LOG_ROTATE_BYTES, default=None): vol.Any(None, int),
        vol.Optional(LOG_ROTATE_COUNT, default=None): vol.Any(None, int),
    },
    extra=vol.PREVENT_EXTRA,
)

PORT_NAME = "port_name"
SERIAL_PORT = "serial_port"

SERIAL_CONFIG_SCHEMA = vol.Schema(
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
SERIAL_PORT_SCHEMA = vol.Schema(
    {
        vol.Required(SERIAL_PORT): vol.Any(
            None,
            str,
            SERIAL_CONFIG_SCHEMA.extend({vol.Required(PORT_NAME): str}),
        )
    }
)
