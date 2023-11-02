#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

from ramses_rf import Device
from ramses_rf.device import Fakeable as _Fakeable


def ensure_fakeable(dev: Device) -> None:
    """If a Device is not Fakeable, make it so."""

    class Fakeable(dev.__class__, _Fakeable):
        pass

    if isinstance(dev, _Fakeable):
        # if hasattr(dev, "_make_fake"):  # no need for callable(getattr(...))
        return

    dev.__class__ = Fakeable
    setattr(dev, "_faked", None)
    setattr(dev, "_context", None)
    setattr(dev, "_1fc9_state", {})
