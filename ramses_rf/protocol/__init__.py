#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""
from __future__ import annotations

from logging import Logger

from .address import Address, is_valid_dev_id
from .command import CODE_API_MAP, Command, FaultLog, Priority
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
from .protocol import create_msg_stack
from .ramses import CODES_BY_DEV_SLUG, CODES_SCHEMA
from .schemas import SZ_SERIAL_PORT
from .transport import SZ_POLLER_TASK, create_pkt_stack

# noqa: F401, pylint: disable=unused-import


# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
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
    Code,
)


def set_pkt_logging_config(**config) -> Logger:
    set_pkt_logging(_PKT_LOGGER, **config)
    return _PKT_LOGGER
