#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""
from __future__ import annotations

from logging import Logger
from typing import TYPE_CHECKING

from .address import Address, is_valid_dev_id
from .command import CODE_API_MAP, Command, Priority
from .const import (
    SZ_DEVICE_ROLE,
    SZ_DOMAIN_ID,
    SZ_ZONE_CLASS,
    SZ_ZONE_IDX,
    SZ_ZONE_MASK,
    SZ_ZONE_TYPE,
    __dev_mode__,
)
from .exceptions import (
    CorruptStateError,
    ExpiredCallbackError,
    InvalidAddrSetError,
    InvalidPacketError,
)
from .logger import set_logger_timesource, set_pkt_logging
from .message import Message
from .packet import _PKT_LOGGER, Packet
from .protocol import (  # noqa: F401, pylint: disable=unused-import
    PortProtocol,
    QosProtocol,
    ReadProtocol,
    protocol_factory,
)
from .ramses import CODES_BY_DEV_SLUG, CODES_SCHEMA
from .schemas import SZ_SERIAL_PORT
from .transport import (  # noqa: F401, pylint: disable=unused-import
    SZ_ACTIVE_HGI,
    FileTransport,
    PortTransport,
    QosTransport,
    transport_factory,
)

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    F9,
    FA,
    FC,
    FF,
    DEV_ROLE,
    DEV_ROLE_MAP,
    DEV_TYPE,
    DEV_TYPE_MAP,
    ZON_ROLE,
    ZON_ROLE_MAP,
)

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:  # mypy TypeVars and similar (e.g. Index, Verb)
    # skipcq: PY-W2000
    from .const import Index, Verb  # noqa: F401, pylint: disable=unused-import


def set_pkt_logging_config(**config) -> Logger:
    set_pkt_logging(_PKT_LOGGER, **config)
    return _PKT_LOGGER
