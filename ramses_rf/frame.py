#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Provide the base class for commands (constructed/sent packets) and packets.
"""

import logging
from typing import Optional, Union

from .const import NON_DEVICE_ID, NUL_DEVICE_ID
from .ramses import (
    CODE_IDX_COMPLEX,
    CODE_IDX_DOMAIN,
    CODE_IDX_NONE,
    CODE_IDX_SIMPLE,
    CODE_ONLY_FROM_CTL,
    CODES_WITH_ARRAYS,
    RAMSES_CODES,
)

from .const import I_, RP, RQ, W_, __dev_mode__  # noqa: F401, isort: skip
from .const import (  # noqa: F401, isort: skip
    _0001,
    _0002,
    _0004,
    _0005,
    _0006,
    _0008,
    _0009,
    _000A,
    _000C,
    _000E,
    _0016,
    _0100,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _1030,
    _1060,
    _1090,
    _10A0,
    _10E0,
    _1100,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _1F09,
    _1F41,
    _1FC9,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2D49,
    _2E04,
    _30C9,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3220,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class PacketBase:
    """The packet base - used by Command and Packet classes."""

    def __init__(self) -> None:

        self.__has_array = None
        self.__has_ctl = None
        self._ctx_ = None
        self._idx_ = None
        self._hdr_ = None

    # def __repr__(self) -> str:
    #     """Return an unambiguous string representation of this object."""
    #     return self.raw_frame or self.packet

    # def __str__(self) -> str:
    #     """Return an string representation of this object."""
    #     return self._hdr

    @property
    def _has_array(self) -> Optional[bool]:
        """Return the True if the packet payload is an array, False if not.

        May return false negatives (e.g. arrays of length 1), and None if undetermined.

        An example of a false negative is evohome with only one zone (i.e. the periodic
        2309/30C9/000A packets).
        """

        if self.__has_array is not None:
            return self.__has_array

        # False -ves (array length is 1) are an acceptable compromise to extensive checking

        #  W --- 01:145038 34:092243 --:------ 1FC9 006 07230906368E
        #  I --- 01:145038 --:------ 01:145038 1FC9 018 07000806368E-FC3B0006368E-071FC906368E
        #  I --- 01:145038 --:------ 01:145038 1FC9 018 FA000806368E-FC3B0006368E-FA1FC906368E
        #  I --- 34:092243 --:------ 34:092243 1FC9 030 0030C9896853-002309896853-001060896853-0010E0896853-001FC9896853
        if self.code == _1FC9:
            self.__has_array = self.verb != RQ  # safe to treat all as array, even len=1

        elif self.verb != I_ or self.code not in CODES_WITH_ARRAYS:
            self.__has_array = False

        elif self.len == CODES_WITH_ARRAYS[self.code][0]:  # NOTE: can be false -ves
            self.__has_array = False

        else:
            _len = CODES_WITH_ARRAYS[self.code][0]
            assert (
                self.len % _len == 0
            ), f"{self} << array has length ({self.len}) that is not multiple of {_len}"
            assert (
                self.src.type in ("12", "22") or self.src == self.dst
            ), f"{self} << array is from a non-controller (01)"
            assert (
                self.src.type not in ("12", "22") or self.dst.id == NON_DEVICE_ID
            ), f"{self} << array is from a non-controller (02)"
            self.__has_array = True

        #  I --- 10:040239 01:223036 --:------ 0009 003 000000        # not array
        #  I --- 01:102458 --:------ 01:102458 0009 006 FC01FF-F901FF
        #  I --- 01:145038 --:------ 01:145038 0009 006 FC00FF-F900FF
        #  I 034 --:------ --:------ 12:126457 2309 006 017EFF-027EFF
        #  I --- 01:223036 --:------ 01:223036 000A 012 081001F40DAC-091001F40DAC  # 2nd fragment
        #  I 024 --:------ --:------ 12:126457 000A 012 010001F40BB8-020001F40BB8
        #  I --- 02:044328 --:------ 02:044328 22C9 018 0001F40A2801-0101F40A2801-0201F40A2801
        #  I --- 23:100224 --:------ 23:100224 2249 007 007EFF7EFFFFFF  # can have 2 zones
        #  I --- 02:044328 --:------ 02:044328 22C9 018 0001F40A2801-0101F40A2801-0201F40A2801
        #  I --- 02:001107 --:------ 02:001107 3150 010 007A-017A-027A-036A-046A

        return self.__has_array

    @property
    def _has_ctl(self) -> Optional[bool]:
        """Return True if the packet is to/from a controller."""

        if self.__has_ctl is not None:
            return self.__has_ctl

        # TODO: handle RQ/RP to/from HGI/RFG, handle HVAC

        # TODO: Not needed? Relies upon MSG layer in any case
        # if getattr(self.src, "_is_controller", False):
        #     # _LOGGER.info("HAS Controller (00)")
        #     return True
        # if getattr(self.dst, "_is_controller", False):
        #     # _LOGGER.info("HAS controller (01)")
        #     return True

        if {self.src.type, self.dst.type} & {"01", "02", "23"}:
            _LOGGER.debug(f"{self} # HAS controller (10)")
            self.__has_ctl = True

        #  I --- 12:010740 --:------ 12:010740 30C9 003 0008D9 # not ctl
        elif self.dst is self.src:  # (not needed?) & self.code == I_:
            _LOGGER.debug(
                f"{self} << "
                + ("HAS" if self.code in CODE_ONLY_FROM_CTL + [_31D9, _31DA] else "no")
                + " controller (20)"
            )
            self.__has_ctl = any(
                (
                    self.code == _3B00 and self.payload[:2] == "FC",
                    self.code in CODE_ONLY_FROM_CTL + [_31D9, _31DA],
                )
            )

        #  I --- --:------ --:------ 10:050360 1FD4 003 002ABE # no ctl
        #  I 095 --:------ --:------ 12:126457 1F09 003 000BC2 # HAS ctl
        #  I --- --:------ --:------ 20:001473 31D9 003 000001 # ctl? (HVAC)
        elif self.dst.id == NON_DEVICE_ID:
            _LOGGER.debug(f"{self} # HAS controller (21)")
            self.__has_ctl = self.src.type != "10"

        #  I --- 10:037879 --:------ 12:228610 3150 002 0000   # HAS ctl
        #  I --- 04:029390 --:------ 12:126457 1060 003 01FF01 # HAS ctl
        elif self.dst.type in ("12", "22"):
            _LOGGER.debug(f"{self} # HAS controller (22)")
            self.__has_ctl = True

        # RQ --- 30:258720 10:050360 --:------ 3EF0 001 00           # UNKNOWN (99)
        # RP --- 10:050360 30:258720 --:------ 3EF0 006 000011010A1C # UNKNOWN (99)

        # RQ --- 18:006402 13:049798 --:------ 1FC9 001 00
        # RP --- 13:049798 18:006402 --:------ 1FC9 006 003EF034C286
        # RQ --- 30:258720 10:050360 --:------ 22D9 001 00
        # RP --- 10:050360 30:258720 --:------ 22D9 003 0003E8
        # RQ --- 30:258720 10:050360 --:------ 3220 005 0000120000
        # RP --- 10:050360 30:258720 --:------ 3220 005 0040120166
        # RQ --- 30:258720 10:050360 --:------ 3EF0 001 00
        # RP --- 10:050360 30:258720 --:------ 3EF0 006 000011010A1C

        #  I --- 34:021943 63:262142 --:------ 10E0 038 000001C8380A01... # unknown
        #  I --- 32:168090 30:082155 --:------ 31E0 004 0000C800          # unknown
        if self.__has_ctl is None:
            if DEV_MODE and "18" not in (self.src.type, self.dst.type):
                _LOGGER.warning(f"{self} # has_ctl - undetermined (99)")
            self.__has_ctl = False

        return self.__has_ctl

    @property
    def _idx(self) -> Union[str, bool]:
        """Return the payload's index, if any (e.g. zone_idx, domain_id, or log_idx).

        Used to route a packet to the correct entity's (i.e. zone/domain) msg handler.
        """

        if self._idx_ is None:
            self._idx_ = _pkt_idx(self) or False
        return self._idx_

    @property
    def _ctx(self) -> Union[str, bool]:
        """Return the payload's full context, if any (e.g. for 0404: zone_idx/frag_idx).

        Used to store packets in the entity's message DB. It is a superset of _idx.
        """

        if self._ctx_ is None:
            if self.code in (_0005, _000C):  # zone_idx, zone_type (device_class)
                self._ctx_ = self.payload[:4]
            elif self.code == _0404:  # zone_idx, frag_idx
                self._ctx_ = self.payload[:2] + self.payload[10:12]
            else:
                self._ctx_ = self._idx
        return self._ctx_

    @property
    def _hdr(self) -> str:
        """Return the QoS header (fingerprint) of this packet (i.e. device_id/code/hdr).

        Used for QoS (timeouts, retries), callbacks, etc.
        """

        if self._hdr_ is None:
            self._hdr_ = pkt_header(self)
        return self._hdr_


def _pkt_idx(pkt) -> Union[str, bool, None]:  # _has_array, _has_ctl
    """Return the payload's 2-byte context (e.g. zone_idx, log_idx, domain_id).

    May return a 2-byte string (usu. pkt.payload[:2]), or:
    - False if there is no context at all
    - True if the payload is an array
    - None if it is indeterminable
    """
    # The three iterables (none, simple, complex) are mutex

    # FIXME: 0016 is broken

    # mutex 2/4, CODE_IDX_COMPLEX: are not payload[:2]
    if pkt.code == _0005:
        return pkt._has_array

    #  I --- 10:040239 01:223036 --:------ 0009 003 000000
    if pkt.code == _0009 and pkt.src.type == "10":
        return False

    if pkt.code == _000C:  # zone_idx/domain_id (complex, payload[0:4])
        if pkt.payload[2:4] in ("0D", "0E"):  # ("000D", _000E, "010E")
            return "FA"
        if pkt.payload[2:4] == "0F":  # ("000F", )
            return "FC"
        return pkt.payload[:2]

    # if pkt.code == _0404:  # TODO: is entry needed here, esp. for DHW?

    if pkt.code == _0418:  # log_idx (payload[4:6])
        return pkt.payload[4:6]

    if pkt.code == _1100:  # TODO; can do in parser
        return pkt.payload[:2] if pkt.payload[:1] == "F" else False  # only FC

    if pkt.code == _3220:  # msg_id/data_id (payload[4:6])
        return pkt.payload[4:6]

    if pkt.code in CODE_IDX_COMPLEX:
        raise NotImplementedError(f"{pkt} # CODE_IDX_COMPLEX")  # a coding error

    # mutex 1/4, CODE_IDX_NONE: always returns False
    if pkt.code in CODE_IDX_NONE:  # returns False
        assert (
            RAMSES_CODES[pkt.code].get(pkt.verb, "")[:3] != "^00"
            or pkt.payload[:2] == "00"
        ), f"{pkt} # index is {pkt.payload[:2]}, expecting 00"
        return False

    # mutex 3/4, CODE_IDX_SIMPLE: potentially some false -ves?
    if pkt._has_array:
        return True  # excludes len==1 for 000A, 2309, 30C9

    # TODO: is this needed?: exceptions to CODE_IDX_SIMPLE
    if pkt.payload[:2] in ("F8", "F9", "FA", "FC"):  # TODO: FB, FD
        assert (
            pkt.code in CODE_IDX_DOMAIN
        ), f"Payload index is {pkt.payload[:2]}, not expecting a domain_id"
        return pkt.payload[:2]

    if pkt._has_ctl:  # risk of false -ves, TODO: pkt.src.type == "18" too?
        # 02:    22C9: would be picked up as an array, if len==1 counted
        # 03:    #  I 028 03:094242 --:------ 03:094242 30C9 003 010B22  # ctl
        # 12/22: 000A|1030|2309|30C9 from (addr0 --:), 1060|3150 (addr0 04:)
        # 23:    0009|10A0
        return pkt.payload[:2]  # pkt._gwy.config.max_zones checked elsewhere

    if pkt.payload[:2] != "00":
        _LOGGER.warning(f"{pkt} # Expecting payload index to be 00")  # return None?
        return pkt.payload[:2]

    if pkt.code in CODE_IDX_SIMPLE:
        return  # False  # TODO: return None (less precise) or risk false -ves?

    # mutex 4/4, CODE_IDX_UNKNOWN: an unknown code
    _LOGGER.warning(f"{pkt} # Unable to determine payload index")  # and: return None


def pkt_header(pkt, rx_header=None) -> Optional[str]:  # NOTE: used in command.py
    """Return the QoS header of a packet (all packets have a header).

    For rx_header=True, return the header of the response packet, if one is expected.
    """

    if pkt.code == _1FC9:
        #  I --- 34:021943 --:------ 34:021943 1FC9 024 00-2309-8855B7 00-1FC9-8855B7
        #  W --- 01:145038 34:021943 --:------ 1FC9 006 00-2309-06368E  # wont know src until it arrives
        #  I --- 34:021943 01:145038 --:------ 1FC9 006 00-2309-8855B7
        if not rx_header:
            device_id = NUL_DEVICE_ID if pkt.src == pkt.dst else pkt.dst.id
            return "|".join((pkt.code, pkt.verb, device_id))
        if pkt.src == pkt.dst:  # and pkt.verb == I_:
            return "|".join((pkt.code, W_, pkt.src.id))
        if pkt.verb == W_:  # and pkt.src != pkt.dst:
            return "|".join((pkt.code, I_, pkt.src.id))
        return

    addr = pkt.dst if pkt.src.type == "18" else pkt.src
    if not rx_header:
        header = "|".join((pkt.code, pkt.verb, addr.id))

    elif pkt.verb in (I_, RP) or pkt.src == pkt.dst:  # announcements, etc.: no response
        return

    else:  # RQ/RP, or W/I
        header = "|".join((pkt.code, RP if pkt.verb == RQ else I_, addr.id))

    try:
        return f"{header}|{pkt._ctx}" if isinstance(pkt._ctx, str) else header
    except AssertionError:
        return header
