#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Works with (amongst others):
- evohome (up to 12 zones)
- sundial (up to 2 zones)
- chronotherm (CM60xNG can do 4 zones)
- hometronics (16? zones)
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ramses_tx import Address, Command, Message, Packet  # noqa: F401

from .const import __dev_mode__
from .device import Device  # noqa: F401
from .exceptions import (  # noqa: F401
    ExpiredCallbackError,
    RamsesException,
    SystemSchemaInconsistent,
)
from .gateway import Gateway  # noqa: F401
from .version import VERSION  # noqa: F401

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

# skipcq: PY-W2000
DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class GracefulExit(SystemExit):
    code = 1
