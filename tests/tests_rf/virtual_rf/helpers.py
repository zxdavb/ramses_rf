#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

from ramses_rf import Device
from ramses_rf.device import Fakeable


def ensure_fakeable(dev: Device, make_fake: bool = True) -> None:
    """If a Device is not Fakeable make it so, and optional make it Faked."""

    class _Fakeable(dev.__class__, Fakeable):
        pass

    if isinstance(dev, _Fakeable | Fakeable):
        return

    dev.__class__ = Fakeable
    setattr(dev, "_context", None)

    assert isinstance(dev, Fakeable)
    if make_fake:
        dev._make_fake()
