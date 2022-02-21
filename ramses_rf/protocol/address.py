#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import re
from functools import lru_cache

from .const import (
    DEVICE_LOOKUP,
    DEVICE_TYPES,
    HGI_DEVICE_ID,
    NON_DEVICE_ID,
    NUL_DEVICE_ID,
    __dev_mode__,
)
from .exceptions import InvalidAddrSetError
from .helpers import typechecked

DEV_MODE = __dev_mode__ and False
DEV_HVAC = True

__device_id_regex__ = re.compile(r"^(-{2}:-{6}|\d{2}:\d{6})$")


class Address:
    """The device Address class."""

    DEVICE_ID_REGEX = __device_id_regex__

    # HGI_DEVICE_ID = __hgi_device_id__
    # NON_DEVICE_ID = __non_device_id__
    # NUL_DEVICE_ID = __nul_device_id__

    def __init__(self, id) -> None:
        """Create an address from a valid device id."""

        self.id = id  # TODO: check is a valid id...
        self.type = id[:2]  # dex, NOTE: remove last
        self._hex_id = None

        if not self.is_valid(id):
            raise ValueError(f"Invalid device_id: {id}")

    def __repr__(self) -> str:
        return self._friendly(self.id).strip()

    def __str__(self) -> str:
        return str(self.id)

    def __eq__(self, other) -> bool:
        if not hasattr(other, "id"):  # can compare Address with Device
            return NotImplemented
        return self.id == other.id

    @property
    def hex_id(self) -> str:
        if self._hex_id is not None:
            return self._hex_id
        self._hex_id = self.convert_to_hex(self.id)
        return self._hex_id

    # @property
    # def description(self) -> str:
    #     raise NotImplementedError

    # @property
    # def schema(self) -> dict:
    #     return {}

    @staticmethod
    def is_valid(value: str) -> bool:

        # if value[:2] not in DEVICE_TYPES:
        #     return False

        return isinstance(value, str) and __device_id_regex__.match(value)

    @classmethod
    def _friendly(cls, device_id: str) -> str:
        """Convert (say) '01:145038' to 'CTL:145038'."""

        if not cls.is_valid(device_id):
            raise TypeError

        _type, _tmp = device_id.split(":")

        return f"{DEVICE_TYPES.get(_type, f'{_type:>3}')}:{_tmp}"

    @classmethod
    def convert_from_hex(cls, device_hex: str, friendly_id=False) -> str:
        """Convert (say) '06368E' to '01:145038' (or 'CTL:145038')."""

        if device_hex == "FFFFFE":  # aka '63:262142'
            return ">null dev<" if friendly_id else NUL_DEVICE_ID

        if not device_hex.strip():  # aka '--:------'
            return f"{'':10}" if friendly_id else NON_DEVICE_ID

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

    # @classmethod
    # def from_hex(cls, hex_id: str):
    #     """Call as: d = Address.from_hex('06368E')."""

    #     return cls(cls.convert_from_hex(hex_id))


@lru_cache(maxsize=256)
def id_to_address(device_id) -> Address:
    return Address(id=device_id)


HGI_DEV_ADDR = id_to_address(HGI_DEVICE_ID)
NON_DEV_ADDR = id_to_address(NON_DEVICE_ID)
NUL_DEV_ADDR = id_to_address(NUL_DEVICE_ID)


@typechecked
def dev_id_to_hex_id(device_id: str) -> str:
    """Convert (say) '01:145038' (or 'CTL:145038') to '06368E'."""

    if len(device_id) == 9:  # e.g. '01:123456'
        dev_type = device_id[:2]

    elif len(device_id) == 10:  # e.g. '01:123456'
        dev_type = DEVICE_LOOKUP.get(device_id[:3], device_id[1:3])

    else:  # len(device_id) == 10, e.g. 'CTL:123456', or ' 63:262142'
        raise ValueError(f"Invalid value: {device_id}, is not 9-10 characters long")

    return f"{(int(dev_type) << 18) + int(device_id[-6:]):0>6X}"


@typechecked
def hex_id_to_dev_id(device_hex: str, friendly_id: bool = False) -> str:
    """Convert (say) '06368E' to '01:145038' (or 'CTL:145038')."""
    if device_hex == "FFFFFE":  # aka '63:262142'
        return "NUL:262142" if friendly_id else NUL_DEVICE_ID

    if not device_hex.strip():  # aka '--:------'
        return f"{'':10}" if friendly_id else NON_DEVICE_ID

    _tmp = int(device_hex, 16)
    dev_type = f"{(_tmp & 0xFC0000) >> 18:02d}"

    if friendly_id:
        dev_type = DEVICE_TYPES.get(dev_type, f"{dev_type:<3}")

    return f"{dev_type}:{_tmp & 0x03FFFF:06d}"


@lru_cache(maxsize=128)
@typechecked
def is_valid_dev_id(value: str, dev_class: str = None) -> bool:
    """Return True if a device_id is valid."""

    if not isinstance(value, str) or not __device_id_regex__.match(value):
        return False

    if not DEV_HVAC and value.split(":", 1)[0] not in DEVICE_TYPES:
        return False

    # TODO: specify device klass (for HVAC)
    # elif dev_class is not None and dev_class != value.split(":", 1)[0]:
    #     raise TypeError(f"The device type does not match '{dev_class}'")

    # assert value == hex_id_to_dev_id(dev_id_to_hex_id(value))
    return True


@lru_cache(maxsize=256)  # there is definite benefit in caching this
@typechecked
def pkt_addrs(pkt_fragment: str) -> tuple[Address, Address, list[Address]]:
    """Return the address fields from (e.g): '01:078710 --:------ 01:144246'.

    Will raise an InvalidAddrSetError is the address fields are not valid.
    """
    # for debug: print(pkt_addrs.cache_info())

    try:
        addrs = [id_to_address(pkt_fragment[i : i + 9]) for i in range(0, 30, 10)]
    except ValueError as exc:
        raise InvalidAddrSetError(f"Invalid addr set: {pkt_fragment}: {exc}")

    if (
        not (
            # .I --- 01:145038 --:------ 01:145038 1F09 003 FF073F # valid
            # .I --- 04:108173 --:------ 01:155341 2309 003 0001F4 # valid
            addrs[0] not in (NON_DEV_ADDR, NUL_DEV_ADDR)
            and addrs[1] == NON_DEV_ADDR
            and addrs[2] != NON_DEV_ADDR
        )
        and not (
            # .I --- 32:206250 30:082155 --:------ 22F1 003 00020A # valid
            # .I --- 29:151550 29:237552 --:------ 22F3 007 00023C03040000 # valid?
            addrs[0] not in (NON_DEV_ADDR, NUL_DEV_ADDR)
            and addrs[1] not in (NON_DEV_ADDR, addrs[0])
            and addrs[2] == NON_DEV_ADDR
        )
        and not (
            # .I --- --:------ --:------ 10:105624 1FD4 003 00AAD4 # valid
            addrs[2] not in (NON_DEV_ADDR, NUL_DEV_ADDR)
            and addrs[0] == NON_DEV_ADDR
            and addrs[1] == NON_DEV_ADDR
        )
    ):
        raise InvalidAddrSetError(f"Invalid addr set: {pkt_fragment}")

    device_addrs = list(filter(lambda a: a.type != "--", addrs))  # dex
    src_addr = device_addrs[0]
    dst_addr = device_addrs[1] if len(device_addrs) > 1 else NON_DEV_ADDR

    if src_addr.id == dst_addr.id:  # incl. HGI_DEV_ADDR == HGI_DEV_ADDR
        src_addr = dst_addr

    return src_addr, dst_addr, addrs
