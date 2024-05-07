#!/usr/bin/env python3
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .address import (
    ALL_DEV_ADDR,
    ALL_DEVICE_ID,
    NON_DEV_ADDR,
    NON_DEVICE_ID,
    Address,
    is_valid_dev_id,
)
from .command import CODE_API_MAP, Command
from .const import (
    DEV_ROLE_MAP,
    DEV_TYPE_MAP,
    F9,
    FA,
    FC,
    FF,
    SZ_ACTIVE_HGI,
    SZ_DEVICE_ROLE,
    SZ_DOMAIN_ID,
    SZ_ZONE_CLASS,
    SZ_ZONE_IDX,
    SZ_ZONE_MASK,
    SZ_ZONE_TYPE,
    ZON_ROLE_MAP,
    DevRole,
    DevType,
    IndexT,
    Priority,
    ZoneRole,
)
from .gateway import Engine
from .logger import set_pkt_logging
from .message import Message
from .packet import PKT_LOGGER, Packet
from .protocol import PortProtocol, ReadProtocol, protocol_factory
from .ramses import CODES_BY_DEV_SLUG, CODES_SCHEMA
from .schemas import SZ_SERIAL_PORT, DeviceIdT, DeviceListT
from .transport import (
    FileTransport,
    PortTransport,
    RamsesTransportT,
    is_hgi80,
    transport_factory,
)
from .typing import QosParams
from .version import VERSION

from .const import (  # isort: skip
    I_,
    RP,
    RQ,
    W_,
    Code,
)


__all__ = [
    "VERSION",
    "Engine",
    #
    "SZ_ACTIVE_HGI",
    "SZ_DEVICE_ROLE",
    "SZ_DOMAIN_ID",
    "SZ_SERIAL_PORT",
    "SZ_ZONE_CLASS",
    "SZ_ZONE_IDX",
    "SZ_ZONE_MASK",
    "SZ_ZONE_TYPE",
    #
    "ALL_DEV_ADDR",
    "ALL_DEVICE_ID",
    "NON_DEV_ADDR",
    "NON_DEVICE_ID",
    #
    "CODE_API_MAP",
    "CODES_BY_DEV_SLUG",  # shouldn't export this
    "CODES_SCHEMA",
    "DEV_ROLE_MAP",
    "DEV_TYPE_MAP",
    "ZON_ROLE_MAP",
    #
    "I_",
    "RP",
    "RQ",
    "W_",
    "F9",
    "FA",
    "FC",
    "FF",
    #
    "DeviceIdT",
    "DeviceListT",
    "DevRole",
    "DevType",
    "IndexT",
    "ZoneRole",
    #
    "Address",
    "Code",
    "Command",
    "Message",
    "Packet",
    "Priority",
    "QosParams",
    #
    "PortProtocol",
    "ReadProtocol",
    "RamsesProtocolT",
    "extract_known_hgi_id",
    "protocol_factory",
    #
    "FileTransport",
    "PortTransport",
    "RamsesTransportT",
    "is_hgi80",
    "transport_factory",
    #
    "is_valid_dev_id",
    "set_pkt_logging_config",
]


if TYPE_CHECKING:
    from logging import Logger


def set_pkt_logging_config(**config: Any) -> Logger:
    set_pkt_logging(PKT_LOGGER, **config)
    return PKT_LOGGER


def extract_known_hgi_id(
    include_list: DeviceListT,
    /,
    *,
    disable_warnings: bool = False,
    strick_checking: bool = False,
) -> DeviceIdT | None:
    return PortProtocol._extract_known_hgi_id(
        include_list, disable_warnings=disable_warnings, strick_checking=strick_checking
    )
