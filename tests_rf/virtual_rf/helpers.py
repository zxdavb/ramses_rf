#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

from ramses_rf import Device, Gateway
from ramses_rf.device import Fakeable
from ramses_rf.protocol import Address


class FakeableDevice(Address, Fakeable):  # HACK: for mypy typing
    _gwy: Gateway


def make_device_fakeable(dev: Device) -> None:
    """If a Device is not Fakeable, make it so."""

    class FakeableDevice(dev.__class__, Fakeable):
        pass

    if hasattr(dev, "_make_fake"):  # no need for callable(getattr(...))
        return

    dev.__class__ = FakeableDevice
    setattr(dev, "_faked", None)
    setattr(dev, "_context", None)
    setattr(dev, "_1fc9_state", {})
