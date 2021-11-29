#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

from types import SimpleNamespace

__dev_mode__ = False
DEV_MODE = __dev_mode__

DHW_HACK = True

ATTR_ALIAS = "alias"
ATTR_CLASS = "class"
ATTR_FAKED = "faked"

ATTR_ORPHANS = "orphans"

Discover = SimpleNamespace(
    NOTHING=0, SCHEMA=1, PARAMS=2, STATUS=4, FAULTS=8, SCHEDS=16, ALL=(1 + 2 + 4)
)

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1
