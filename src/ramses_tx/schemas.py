#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Schema processor for protocol (lower) layer.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Final

import voluptuous as vol

from .const import DEV_TYPE_MAP, DEVICE_ID_REGEX, DevType

if TYPE_CHECKING:
    from .frame import DeviceIdT


_LOGGER = logging.getLogger(__name__)


#
# 0/5: Packet source configuration
SZ_INPUT_FILE: Final[str] = "input_file"
SZ_PACKET_SOURCE: Final[str] = "packet_source"


#
# 1/5: Packet log configuration
SZ_FILE_NAME: Final[str] = "file_name"
SZ_PACKET_LOG: Final[str] = "packet_log"
SZ_ROTATE_BACKUPS: Final[str] = "rotate_backups"
SZ_ROTATE_BYTES: Final[str] = "rotate_bytes"


def sch_packet_log_dict_factory(default_backups=0) -> dict[vol.Required, vol.Any]:
    """Return a packet log dict with a configurable default rotation policy.

    usage:

    SCH_PACKET_LOG_7 = vol.Schema(
        packet_log_dict_factory(default_backups=7), extra=vol.PREVENT_EXTRA
    )
    """

    SCH_PACKET_LOG_CONFIG = vol.Schema(
        {
            vol.Optional(SZ_ROTATE_BACKUPS, default=default_backups): vol.Any(
                None, int
            ),
            vol.Optional(SZ_ROTATE_BYTES): vol.Any(None, int),
        },
        extra=vol.PREVENT_EXTRA,
    )

    SCH_PACKET_LOG_NAME = str

    def NormalisePacketLog(rotate_backups=0):
        def normalise_packet_log(node_value: str | dict) -> dict:
            if isinstance(node_value, str):
                return {
                    SZ_FILE_NAME: node_value,
                    SZ_ROTATE_BACKUPS: rotate_backups,
                    SZ_ROTATE_BYTES: None,
                }
            return node_value

        return normalise_packet_log

    return {  # SCH_PACKET_LOG_DICT
        vol.Required(SZ_PACKET_LOG, default=None): vol.Any(
            None,
            vol.All(
                SCH_PACKET_LOG_NAME,
                NormalisePacketLog(rotate_backups=default_backups),
            ),
            SCH_PACKET_LOG_CONFIG.extend(
                {vol.Required(SZ_FILE_NAME): SCH_PACKET_LOG_NAME}
            ),
        )
    }


#
# 2/5: Serial port configuration
SZ_PORT_CONFIG: Final[str] = "port_config"
SZ_PORT_NAME: Final[str] = "port_name"
SZ_SERIAL_PORT: Final[str] = "serial_port"

SZ_BAUDRATE: Final[str] = "baudrate"
SZ_DSRDTR: Final[str] = "dsrdtr"
SZ_RTSCTS: Final[str] = "rtscts"
SZ_TIMEOUT: Final[str] = "timeout"
SZ_XONXOFF: Final[str] = "xonxoff"


SCH_SERIAL_PORT_CONFIG = vol.Schema(
    {
        vol.Optional(SZ_BAUDRATE, default=115200): vol.All(
            vol.Coerce(int), vol.Any(57600, 115200)
        ),  # NB: HGI80 does not work, except at 115200 - so must be default
        vol.Optional(SZ_DSRDTR, default=False): bool,
        vol.Optional(SZ_RTSCTS, default=False): bool,
        vol.Optional(SZ_TIMEOUT, default=0): vol.Any(None, int),  # default None?
        vol.Optional(SZ_XONXOFF, default=True): bool,  # set True to remove \x11
    },
    extra=vol.PREVENT_EXTRA,
)


def sch_serial_port_dict_factory() -> dict[vol.Required, vol.Any]:
    """Return a serial port dict.

    usage:

    SCH_SERIAL_PORT = vol.Schema(
        sch_serial_port_dict_factory(), extra=vol.PREVENT_EXTRA
    )
    """

    SCH_SERIAL_PORT_NAME = str

    def NormaliseSerialPort():
        def normalise_serial_port(node_value: str | dict) -> dict:
            if isinstance(node_value, str):
                return {SZ_PORT_NAME: node_value} | SCH_SERIAL_PORT_CONFIG({})  # type: ignore[no-any-return]
            return node_value

        return normalise_serial_port

    return {  # SCH_SERIAL_PORT_DICT
        vol.Required(SZ_SERIAL_PORT): vol.Any(
            vol.All(
                SCH_SERIAL_PORT_NAME,
                NormaliseSerialPort(),
            ),
            SCH_SERIAL_PORT_CONFIG.extend(
                {vol.Required(SZ_PORT_NAME): SCH_SERIAL_PORT_NAME}
            ),
        )
    }


def extract_serial_port(ser_port_dict: dict) -> tuple[str, dict[str, bool | int]]:
    """Extract a serial port, port_config_dict tuple from a sch_serial_port_dict."""
    port_name: str = ser_port_dict.get(SZ_PORT_NAME)  # type: ignore[assignment]
    port_config = {k: v for k, v in ser_port_dict.items() if k != SZ_PORT_NAME}
    return port_name, port_config


#
# 3/5: Traits (of devices) configuraion (basic)
def ConvertNullToDict():
    def convert_null_to_dict(node_value) -> dict:
        if node_value is None:
            return {}
        return node_value  # type: ignore[no-any-return]

    return convert_null_to_dict


SZ_ALIAS: Final[str] = "alias"
SZ_CLASS: Final[str] = "class"
SZ_FAKED: Final[str] = "faked"
SZ_SCHEME: Final[str] = "scheme"

SZ_BLOCK_LIST: Final[str] = "block_list"
SZ_KNOWN_LIST: Final[str] = "known_list"

SCH_DEVICE_ID_ANY = vol.Match(DEVICE_ID_REGEX.ANY)
SCH_DEVICE_ID_SEN = vol.Match(DEVICE_ID_REGEX.SEN)
SCH_DEVICE_ID_CTL = vol.Match(DEVICE_ID_REGEX.CTL)
SCH_DEVICE_ID_DHW = vol.Match(DEVICE_ID_REGEX.DHW)
SCH_DEVICE_ID_HGI = vol.Match(DEVICE_ID_REGEX.HGI)
SCH_DEVICE_ID_APP = vol.Match(DEVICE_ID_REGEX.APP)
SCH_DEVICE_ID_BDR = vol.Match(DEVICE_ID_REGEX.BDR)
SCH_DEVICE_ID_UFC = vol.Match(DEVICE_ID_REGEX.UFC)

_SCH_TRAITS_DOMAINS = ("heat", "hvac")
_SCH_TRAITS_HVAC_SCHEMES = ("itho", "nuaire", "orcon")


def sch_global_traits_dict_factory(
    heat_traits: dict[vol.Optional, vol.Any] | None = None,
    hvac_traits: dict[vol.Optional, vol.Any] | None = None,
) -> tuple[dict[vol.Optional, vol.Any], vol.Schema]:
    """Return a global traits dict with a configurable extra traits.

    usage:

    SCH_GLOBAL_TRAITS = vol.Schema(
        sch_global_traits_dict(heat=traits), extra=vol.PREVENT_EXTRA
    )
    """

    heat_traits = heat_traits or {}
    hvac_traits = hvac_traits or {}

    SCH_TRAITS_BASE = vol.Schema(
        {
            vol.Optional(SZ_ALIAS, default=None): vol.Any(None, str),
            vol.Optional(SZ_FAKED, default=None): vol.Any(None, bool),
            vol.Optional(vol.Remove("_note")): str,  # only for convenience, not used
        },
        extra=vol.PREVENT_EXTRA,
    )

    # NOTE: voluptuous doesn't like StrEnums, hence str(s)
    # TIP: the _domain key can be used to force which traits schema to use
    heat_slugs = list(
        str(s) for s in DEV_TYPE_MAP.slugs() if s not in DEV_TYPE_MAP.HVAC_SLUGS
    )
    SCH_TRAITS_HEAT = SCH_TRAITS_BASE.extend(
        {
            vol.Optional("_domain", default="heat"): "heat",
            vol.Optional(SZ_CLASS): vol.Any(
                None, *heat_slugs, *(str(DEV_TYPE_MAP[s]) for s in heat_slugs)
            ),
        }
    )
    SCH_TRAITS_HEAT = SCH_TRAITS_HEAT.extend(
        heat_traits,
        extra=vol.PREVENT_EXTRA if heat_traits else vol.REMOVE_EXTRA,
    )

    # NOTE: voluptuous doesn't like StrEnums, hence str(s)
    hvac_slugs = list(str(s) for s in DEV_TYPE_MAP.HVAC_SLUGS)
    SCH_TRAITS_HVAC = SCH_TRAITS_BASE.extend(
        {
            vol.Optional("_domain", default="hvac"): "hvac",
            vol.Optional(SZ_CLASS, default="HVC"): vol.Any(
                None, *hvac_slugs, *(str(DEV_TYPE_MAP[s]) for s in hvac_slugs)
            ),  # TODO: consider removing None
        }
    )
    SCH_TRAITS_HVAC = SCH_TRAITS_HVAC.extend(
        {vol.Optional(SZ_SCHEME): vol.Any(*_SCH_TRAITS_HVAC_SCHEMES)}
    )
    SCH_TRAITS_HVAC = SCH_TRAITS_HVAC.extend(
        hvac_traits,
        extra=vol.PREVENT_EXTRA if hvac_traits else vol.REMOVE_EXTRA,
    )

    SCH_TRAITS = vol.Any(
        vol.All(None, ConvertNullToDict()),
        vol.Any(SCH_TRAITS_HEAT, SCH_TRAITS_HVAC),
        extra=vol.PREVENT_EXTRA,
    )
    SCH_DEVICE = vol.Schema(
        {vol.Optional(SCH_DEVICE_ID_ANY): SCH_TRAITS},
        extra=vol.PREVENT_EXTRA,
    )

    global_traits_dict = {  # Filter lists with Device traits...
        vol.Optional(SZ_KNOWN_LIST, default={}): vol.Any(
            vol.All(None, ConvertNullToDict()),
            vol.All(SCH_DEVICE, vol.Length(min=0)),
        ),
        vol.Optional(SZ_BLOCK_LIST, default={}): vol.Any(
            vol.All(None, ConvertNullToDict()),
            vol.All(SCH_DEVICE, vol.Length(min=0)),
        ),
    }

    return global_traits_dict, SCH_TRAITS


SCH_GLOBAL_TRAITS_DICT, SCH_TRAITS = sch_global_traits_dict_factory()

#
# Device lists (Engine configuration)


def select_device_filter_mode(
    enforce_known_list: bool,
    known_list: dict[DeviceIdT, dict],
    block_list: dict[DeviceIdT, dict],
) -> bool:
    """Determine which device filter to use, if any.

    Either:
     - block if device_id in block_list (could be empty), otherwise
     - allow if device_id in known_list, or
    """

    if both := set(known_list) & set(block_list):
        raise ValueError(
            f"There are devices in both the {SZ_KNOWN_LIST} & {SZ_BLOCK_LIST}: {both}"
        )

    hgi_list = [
        k
        for k, v in known_list.items()
        if k[:2] == DEV_TYPE_MAP._hex(DevType.HGI)
        and v.get(SZ_CLASS) in (None, DevType.HGI, DEV_TYPE_MAP[DevType.HGI])
    ]
    if len(hgi_list) != 1:
        _LOGGER.warning(
            f"Best practice is exactly one gateway (HGI) in the {SZ_KNOWN_LIST}: %s",
            hgi_list,
        )

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


#
# 4/5: Gateway (engine) configuration
SZ_DISABLE_SENDING: Final[str] = "disable_sending"
SZ_DISABLE_QOS: Final[str] = "disable_qos"
SZ_ENFORCE_KNOWN_LIST: Final[str] = f"enforce_{SZ_KNOWN_LIST}"
SZ_EVOFW_FLAG: Final[str] = "evofw_flag"
SZ_USE_REGEX: Final[str] = "use_regex"

SCH_ENGINE_DICT = {
    vol.Optional(SZ_DISABLE_SENDING, default=False): bool,
    vol.Optional(SZ_DISABLE_QOS, default=None): vol.Any(
        None,  # None is selective QoS (e.g. QoS only for bindings, schedule, etc.)
        bool,
    ),  # in long term, this default to be True (and no None)
    vol.Optional(SZ_ENFORCE_KNOWN_LIST, default=False): bool,
    vol.Optional(SZ_EVOFW_FLAG): vol.Any(None, str),
    # vol.Optional(SZ_PORT_CONFIG): SCH_SERIAL_PORT_CONFIG,
    vol.Optional(SZ_USE_REGEX): dict,  # vol.All(ConvertNullToDict(), dict),
}
SCH_ENGINE_CONFIG = vol.Schema(SCH_ENGINE_DICT, extra=vol.REMOVE_EXTRA)

SZ_INBOUND: Final[str] = "inbound"  # for use_regex (intentionally obscured)
SZ_OUTBOUND: Final[str] = "outbound"
