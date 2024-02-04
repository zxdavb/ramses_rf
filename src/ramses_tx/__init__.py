#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .address import ALL_DEV_ADDR, ALL_DEVICE_ID, Address, is_valid_dev_id  # noqa: F401
from .command import CODE_API_MAP, Command  # noqa: F401
from .const import (  # noqa: F401
    SZ_DEVICE_ROLE,
    SZ_DOMAIN_ID,
    SZ_ZONE_CLASS,
    SZ_ZONE_IDX,
    SZ_ZONE_MASK,
    SZ_ZONE_TYPE,
    Priority,
)
from .gateway import Engine  # noqa: F401
from .logger import set_logger_timesource, set_pkt_logging  # noqa: F401
from .message import Message  # noqa: F401
from .packet import PKT_LOGGER, Packet  # noqa: F401
from .protocol import (  # noqa: F401, pylint: disable=unused-import
    PortProtocol,
    QosProtocol,
    ReadProtocol,
    protocol_factory,
)
from .ramses import CODES_BY_DEV_SLUG, CODES_SCHEMA  # noqa: F401
from .schemas import SZ_SERIAL_PORT  # noqa: F401
from .transport import (  # noqa: F401, pylint: disable=unused-import
    SZ_ACTIVE_HGI,
    FileTransport,
    PortTransport,
    QosTransport,
    is_hgi80,
    transport_factory,
)
from .typing import QosParams  # noqa: F401
from .version import VERSION  # noqa: F401

from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    F9,
    FA,
    FC,
    FF,
    DEV_ROLE_MAP,
    DEV_TYPE_MAP,
    ZON_ROLE_MAP,
    DevRole,
    DevType,
    ZoneRole,
)


from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:
    from logging import Logger


def set_pkt_logging_config(**config) -> Logger:
    set_pkt_logging(PKT_LOGGER, **config)
    return PKT_LOGGER  # type: ignore[no-any-return]
