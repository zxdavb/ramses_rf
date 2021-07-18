#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import re
from collections import namedtuple
from functools import lru_cache
from random import randint
from typing import List, Tuple

from .const import DEVICE_ID_REGEX, DEVICE_LOOKUP, DEVICE_TYPES, __dev_mode__
from .exceptions import CorruptAddrSetError

DEV_MODE = __dev_mode__

__device_id_regex__ = re.compile(r"^(-{2}:-{6}|\d{2}:\d{6})$")

__hgi_device_id__ = "18:000730"
__non_device_id__ = "--:------"
__nul_device_id__ = "63:262142"


Address = namedtuple("DeviceAddress", "id, type")


@lru_cache(maxsize=128)
def id_to_address(device_id) -> Address:
    return Address(id=device_id, type=device_id[:2])


HGI_DEVICE_ID = __hgi_device_id__  # default type and address of HGI, 18:013393
NON_DEVICE_ID = __non_device_id__
NUL_DEVICE_ID = __nul_device_id__  # 7FFFFF - send here if not bound?

HGI_DEV_ADDR = id_to_address(HGI_DEVICE_ID)
NON_DEV_ADDR = id_to_address(NON_DEVICE_ID)
NUL_DEV_ADDR = id_to_address(NUL_DEVICE_ID)


class AddressNew:
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


def create_dev_id(dev_type, known_devices=None) -> str:
    """Create a unique device_id (i.e. one that is not already known)."""

    # TODO: assert inputs

    counter = 0
    while counter < 128:
        device_id = f"{dev_type}:{randint(256000, 256031):06d}"
        if not known_devices or device_id not in known_devices:
            return device_id
        counter += 1
    else:
        raise IndexError("Unable to generate a unique device id of type '{dev_type}'")


def dev_id_to_hex(device_id: str) -> str:
    """Convert (say) '01:145038' (or 'CTL:145038') to '06368E'."""

    if len(device_id) == 9:  # e.g. '01:123456'
        dev_type = device_id[:2]

    else:  # len(device_id) == 10, e.g. 'CTL:123456', or ' 63:262142'
        dev_type = DEVICE_LOOKUP.get(device_id[:3], device_id[1:3])

    return f"{(int(dev_type) << 18) + int(device_id[-6:]):0>6X}"  # no preceding 0x


def hex_id_to_dec(device_hex: str, friendly_id=False) -> str:
    """Convert (say) '06368E' to '01:145038' (or 'CTL:145038')."""

    if device_hex == "FFFFFE":  # aka '63:262142'
        return ">null dev<" if friendly_id else NUL_DEV_ADDR.id

    if not device_hex.strip():  # aka '--:------'
        return f"{'':10}" if friendly_id else NON_DEV_ADDR.id

    _tmp = int(device_hex, 16)
    dev_type = f"{(_tmp & 0xFC0000) >> 18:02d}"
    if friendly_id:
        dev_type = DEVICE_TYPES.get(dev_type, f"{dev_type:<3}")

    return f"{dev_type}:{_tmp & 0x03FFFF:06d}"


@lru_cache(maxsize=128)
def is_valid_dev_id(value, dev_type=None) -> bool:
    """Return True if a device_id is valid."""

    if not isinstance(value, str):
        return False

    elif not DEVICE_ID_REGEX.match(value):
        return False

    # elif value != hex_id_to_dec(dev_id_to_hex(value)):
    #     return False

    elif value.split(":", 1)[0] not in DEVICE_TYPES:
        return False

    elif dev_type is not None and dev_type != value.split(":", 1)[0]:
        raise TypeError(f"The device type does not match '{dev_type}'")

    return True


@lru_cache(maxsize=256)  # there is definite benefit in caching this
def pkt_addrs(pkt_fragment: str) -> Tuple[Address, Address, List[Address]]:
    """Return the address fields from (e.g): '01:078710 --:------ 01:144246 '."""

    addrs = [id_to_address(pkt_fragment[i : i + 9]) for i in range(0, 30, 10)]

    # TODO: remove all .id: addrs[2] not in (NON_DEV_ADDR, NUL_DEV_ADDR)

    # This check will invalidate these esoteric pkts (which are never transmitted)
    # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF02FF
    # ---  I --- --:------ --:------ --:------ 0001 005 00FFFF0200
    if not all(
        (
            addrs[0] not in (NON_DEV_ADDR.id, NUL_DEV_ADDR.id),
            (addrs[1].id, addrs[2].id).count(NON_DEV_ADDR.id) == 1,
        )
    ) and not all(
        (
            addrs[2].id not in (NON_DEV_ADDR.id, NUL_DEV_ADDR.id),
            addrs[0].id == addrs[1].id == NON_DEV_ADDR.id,
        )
    ):
        raise CorruptAddrSetError(f"Invalid addr set: {pkt_fragment}")

    device_addrs = list(filter(lambda x: x.type != "--", addrs))
    if len(device_addrs) > 2:
        raise CorruptAddrSetError(f"Invalid addr set (i.e. 3 addrs): {pkt_fragment}")

    src_addr = device_addrs[0]
    dst_addr = device_addrs[1] if len(device_addrs) > 1 else NON_DEV_ADDR

    if src_addr.id == dst_addr.id:
        src_addr = dst_addr
    elif src_addr.type == "18" and dst_addr.id == HGI_DEV_ADDR.id:
        # 000  I --- 18:013393 18:000730 --:------ 0001 005 00FFFF0200 (valid, ex HGI80)
        raise CorruptAddrSetError(f"Invalid src/dst addr pair: {pkt_fragment}")
        # pass
    elif dst_addr.type == "18" and src_addr.id == HGI_DEV_ADDR.id:
        raise CorruptAddrSetError(f"Invalid src/dst addr pair: {pkt_fragment}")
        # pass
    elif {src_addr.type, dst_addr.type}.issubset({"01", "23"}):
        raise CorruptAddrSetError(f"Invalid src/dst addr pair: {pkt_fragment}")
    elif src_addr.type == dst_addr.type:
        # 064  I --- 01:078710 --:------ 01:144246 1F09 003 FF04B5 (invalid)
        raise CorruptAddrSetError(f"Invalid src/dst addr pair: {pkt_fragment}")

    return src_addr, dst_addr, addrs
