#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""
from __future__ import annotations

import logging

from ..const import __dev_mode__

# skipcq: PY-W2000
from ..const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

# # skipcq: PY-W2000
# from .schedule import (  # noqa: F401, isort: skip, pylint: disable=unused-import
# )

# skipcq: PY-W2000
from .heat import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    System,
    zx_system_factory,
)

# # skipcq: PY-W2000
# from .systems_hvac import (  # noqa: F401, isort: skip, pylint: disable=unused-import
# )

# skipcq: PY-W2000
from .zones import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    DhwZone,
    Zone,
)


DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)
