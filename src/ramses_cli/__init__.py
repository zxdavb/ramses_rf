#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""A CLI for the ramses_rf library."""
from __future__ import annotations

_DBG_CLI = False  # HACK: for debugging of CLI (*before* loading library)


if _DBG_CLI:
    from .debug import start_debugging

    start_debugging(True)
