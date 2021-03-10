#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser."""

import logging
import re

from .const import DEVICE_LOOKUP, DEVICE_TYPES, __dev_mode__

__device_id_regex__ = re.compile(r"^(-{2}:-{6}|\d{2}:\d{6})$")

__hgi_device_id__ = "18:000730"
__non_device_id__ = "--:------"
__nul_device_id__ = "63:262142"

DEV_MODE = __dev_mode__

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Address:
    """The Device Address base class."""

    DEVICE_ID_REGEX = __device_id_regex__

    HGI_DEVICE_ID = __hgi_device_id__
    NON_DEVICE_ID = __non_device_id__
    NUL_DEVICE_ID = __nul_device_id__

    def __init__(self, device_id) -> None:
        if not self.is_valid(device_id):
            raise ValueError

        self.id = None
        self.type = None
        self.hex_id = None

    @classmethod
    def from_hex(cls, hex_id: str):
        """Call as: d = Address.from_hex('06368E')"""
        return cls(cls.convert_from_hex(hex_id))

    def __repr__(self) -> str:
        return self._friendly(self.id).strip()

    def __str__(self) -> str:
        return self._friendly(self.id)

    def __eq__(self, other) -> bool:
        if not hasattr(other, "id"):
            return NotImplemented
        return self.id == other.id

    @property
    def hex_id(self) -> str:
        return self._hex_id

    @property
    def description(self) -> str:
        raise NotImplementedError

    @staticmethod
    def is_valid(value: str) -> bool:

        if not isinstance(value, str):
            return False

        elif not __device_id_regex__.match(value):
            return False

        elif value[:2] not in DEVICE_TYPES:
            return False

        return True

    @classmethod
    def _friendly(cls, device_id: str) -> str:
        """Convert (say) '01:145038' to 'CTL:145038'."""

        if not cls.is_valid(device_id):
            raise TypeError

        _type, _tmp = device_id.split(":")

        return f"{DEVICE_TYPES.get(_type, f'{_type:<3}')}:{_tmp}"

    @classmethod
    def convert_from_hex(cls, device_hex: str, friendly_id=False) -> str:
        """Convert (say) '06368E' to '01:145038' (or 'CTL:145038')."""

        if device_hex == "FFFFFE":  # aka '63:262142'
            return ">null dev<" if friendly_id else __nul_device_id__

        if not device_hex.strip():  # aka '--:------'
            return f"{'':10}" if friendly_id else __non_device_id__

        _tmp = int(device_hex, 16)
        device_id = f"{(_tmp & 0xFC0000) >> 18:02d}:{_tmp & 0x03FFFF:06d}"

        return cls._friendly(device_id) if friendly_id else device_id

    @classmethod
    def convert_to_hex(cls, device_id: str) -> str:
        """Convert (say) '01:145038' (or 'CTL:145038') to '06368E'."""

        if not cls.is_valid(device_id):
            raise TypeError

        if len(device_id) == 9:  # e.g. '01:123456'
            dev_type = device_id[:2]

        else:  # len(device_id) == 10, e.g. 'CTL:123456', or ' 63:262142'
            dev_type = DEVICE_LOOKUP.get(device_id[:3], device_id[1:3])

        return f"{(int(dev_type) << 18) + int(device_id[-6:]):0>6X}"  # no preceding 0x
