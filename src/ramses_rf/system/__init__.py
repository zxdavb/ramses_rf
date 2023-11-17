#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Heating devices.
"""
from __future__ import annotations

import logging

from ..const import __dev_mode__

#
# from .schedule import (  # noqa: F401, isort: skip, pylint: disable=unused-import
# )


from .heat import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    System,
    system_factory,
)

#
# from .systems_hvac import (  # noqa: F401, isort: skip, pylint: disable=unused-import
# )


from .zones import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    DhwZone,
    Zone,
)


DEV_MODE = __dev_mode__  # and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)
