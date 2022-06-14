#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Provide the base class for commands (constructed/sent packets) and packets.
"""

# TODO: add _has_idx (ass func return only one type, or raise)

import logging
from typing import Optional, Union

from .address import NON_DEV_ADDR, NUL_DEV_ADDR, Address, pkt_addrs
from .const import COMMAND_REGEX, DEV_ROLE_MAP, DEV_TYPE_MAP, __dev_mode__
from .exceptions import InvalidPacketError, InvalidPayloadError
from .ramses import (
    CODE_IDX_COMPLEX,
    CODE_IDX_DOMAIN,
    CODE_IDX_NONE,
    CODE_IDX_SIMPLE,
    CODES_ONLY_FROM_CTL,
    CODES_SCHEMA,
    CODES_WITH_ARRAYS,
    RQ_NO_PAYLOAD,
)

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    F8,
    F9,
    FA,
    FC,
    FF,
)

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
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
    _0150,
    _01D0,
    _01E9,
    _0404,
    _0418,
    _042F,
    _0B04,
    _1030,
    _1060,
    _1081,
    _1090,
    _1098,
    _10A0,
    _10B0,
    _10E0,
    _10E1,
    _1100,
    _11F0,
    _1260,
    _1280,
    _1290,
    _1298,
    _12A0,
    _12B0,
    _12C0,
    _12C8,
    _12F0,
    _1300,
    _1F09,
    _1F41,
    _1FC9,
    _1FCA,
    _1FD0,
    _1FD4,
    _2249,
    _22C9,
    _22D0,
    _22D9,
    _22F1,
    _22F3,
    _2309,
    _2349,
    _2389,
    _2400,
    _2401,
    _2410,
    _2420,
    _2D49,
    _2E04,
    _2E10,
    _30C9,
    _3110,
    _3120,
    _313F,
    _3150,
    _31D9,
    _31DA,
    _31E0,
    _3200,
    _3210,
    _3220,
    _3221,
    _3223,
    _3B00,
    _3EF0,
    _3EF1,
    _PUZZ,
)

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class Frame:
    """The packet base - used by Command and Packet classes."""

    _frame: str

    verb: str
    seqn: str  # TODO: or, better as int?
    code: str
    _len: str
    payload: str

    src: Address
    dst: Address
    _addrs: tuple[Address, Address, Address]

    def __init__(self, frame: str) -> None:
        """Create a frame.

        Frames do not have dtm, RSSI fields (i.e. they were never Tx/Rx).

        \# RQ --- 01:078710 10:067219 --:------ 3220 005 0000050000
        """  # noqa: W605

        if not isinstance(frame, str):
            raise InvalidPacketError(f"invalid frame (not a string): {type(frame)}")

        self._frame = frame

        self.verb = frame[:2]
        self.seqn = frame[3:6]
        self.code = frame[37:41]
        self._len = frame[42:45]
        self.payload = frame[46:].split(" ")[0]

        self.src, self.dst, *self._addrs = pkt_addrs(frame[7:36])  # ?InvalidPacketError

        self._ctx_: Union[str, bool] = None  # type: ignore[assignment]
        self._hdr_: str = None  # type: ignore[assignment]
        self._idx_: Union[str, bool] = None  # type: ignore[assignment]

        self._has_array_: bool = None  # type: ignore[assignment]
        self._has_ctl_: bool = None  # type: ignore[assignment]  # TODO: remove
        self._has_payload_: bool = None  # type: ignore[assignment]

        # self._validate(strict_checking=False)  # must be done in Command, Packet

    def _validate(self, *, strict_checking: bool = None) -> None:
        """Validate the frame: it may be a cmd or a (response) pkt.

        Raise an exception InvalidPacketError (InvalidAddrSetError) if it is not valid.
        """

        if not COMMAND_REGEX.match(self._frame):
            raise InvalidPacketError("Invalid frame structure")

        if int(self.len) * 2 != (len_ := len(self.payload)):
            raise InvalidPacketError(f"Invalid len: {self.len} (should be {len_})")

        if not strict_checking:
            return

        if self.seqn == "...":
            raise InvalidPacketError(f"Invalid seqn: {self.seqn} ('...' deprecated)")

        if self.code not in CODES_SCHEMA:
            raise InvalidPacketError(f"Unknown code: {self.code}")

    @classmethod  # constructor for internal use only
    def _from_vars(
        cls,
        verb,
        code,
        payload,
        addr0=NUL_DEV_ADDR,
        addr1=NUL_DEV_ADDR,
        addr2=NUL_DEV_ADDR,
        seqn="---",
    ):
        """Create a command from a frame (a raw string) (NB: no RSSI).

        \# RQ --- 01:078710 10:067219 --:------ 3220 005 0000050000
        """  # noqa: W605

        varz = (verb, seqn, addr0, addr1, addr2, code, int(len(payload) / 2), payload)
        return cls(" ".join(varz))

    def __repr__(self) -> str:
        """Return a unambiguous string representation of this object."""
        return self._frame

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""
        return self._hdr  # code|ver|device_id|context

    @property
    def len(self) -> int:
        """Return the payload length in two-byte chunks."""
        return int(self._len)  # == len(payload) / 2

    @property
    def _has_array(self) -> Optional[bool]:
        """Return the True if the packet payload is an array, False if not.

        May return false negatives (e.g. arrays of length 1), and None if undetermined.

        An example of a false negative is evohome with only one zone (i.e. the periodic
        2309/30C9/000A packets).
        """

        if self._has_array_ is not None:  # HACK: overriden by detect_array(msg, prev)
            return self._has_array_

        # False -ves (array length is 1) are an acceptable compromise to extensive checking

        #  W --- 01:145038 34:092243 --:------ 1FC9 006 07230906368E
        #  I --- 01:145038 --:------ 01:145038 1FC9 018 07000806368E-FC3B0006368E-071FC906368E
        #  I --- 01:145038 --:------ 01:145038 1FC9 018 FA000806368E-FC3B0006368E-FA1FC906368E
        #  I --- 34:092243 --:------ 34:092243 1FC9 030 0030C9896853-002309896853-001060896853-0010E0896853-001FC9896853
        if self.code == _1FC9:
            self._has_array_ = self.verb != RQ  # safe to treat all as array, even len=1

        elif self.verb != I_ or self.code not in CODES_WITH_ARRAYS:
            self._has_array_ = False

        elif self.len == CODES_WITH_ARRAYS[self.code][0]:  # NOTE: can be false -ves
            self._has_array_ = False
            if (
                self.code in (_22C9, _3150)  # only time 22C9 is seen
                and self.src.type == DEV_TYPE_MAP.UFC
                and self.dst is self.src
                and self.payload[:1] != "F"
            ):
                self._has_array_ = True

        else:
            len_ = CODES_WITH_ARRAYS[self.code][0]
            assert (
                self.len % len_ == 0
            ), f"{self} < array has length ({self.len}) that is not multiple of {len_}"
            assert (
                self.src.type in (DEV_TYPE_MAP.DTS, DEV_TYPE_MAP.DT2)
                or self.src == self.dst  # DEX
            ), f"{self} < array is from a non-controller (01)"
            assert (
                self.src.type not in (DEV_TYPE_MAP.DTS, DEV_TYPE_MAP.DT2)
                or self.dst.id == NON_DEV_ADDR.id  # DEX
            ), f"{self} < array is from a non-controller (02)"
            self._has_array_ = True

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

        return self._has_array_

    @property
    def _has_ctl(self) -> Optional[bool]:
        """Return True if the packet is to/from a controller."""

        if self._has_ctl_ is not None:
            return self._has_ctl_

        # TODO: handle RQ/RP to/from HGI/RFG, handle HVAC

        if {self.src.type, self.dst.type} & {
            DEV_TYPE_MAP.CTL,
            DEV_TYPE_MAP.UFC,
            DEV_TYPE_MAP.PRG,
        }:  # DEX
            _LOGGER.debug(f"{self} # HAS controller (10)")
            self._has_ctl_ = True

        #  I --- 12:010740 --:------ 12:010740 30C9 003 0008D9 # not ctl
        elif self.dst is self.src:  # (not needed?) & self.code == I_:
            _LOGGER.debug(
                f"{self} < "
                + ("HAS" if self.code in CODES_ONLY_FROM_CTL + [_31D9, _31DA] else "no")
                + " controller (20)"
            )
            self._has_ctl_ = any(
                (
                    self.code == _3B00 and self.payload[:2] == FC,
                    self.code in CODES_ONLY_FROM_CTL + [_31D9, _31DA],
                )
            )

        #  I --- --:------ --:------ 10:050360 1FD4 003 002ABE # no ctl
        #  I 095 --:------ --:------ 12:126457 1F09 003 000BC2 # HAS ctl
        #  I --- --:------ --:------ 20:001473 31D9 003 000001 # ctl? (HVAC)
        elif self.dst.id == NON_DEV_ADDR.id:
            _LOGGER.debug(f"{self} # HAS controller (21)")
            self._has_ctl_ = self.src.type != DEV_TYPE_MAP.OTB  # DEX

        #  I --- 10:037879 --:------ 12:228610 3150 002 0000   # HAS ctl
        #  I --- 04:029390 --:------ 12:126457 1060 003 01FF01 # HAS ctl
        elif self.dst.type in (DEV_TYPE_MAP.DTS, DEV_TYPE_MAP.DT2):  # DEX
            _LOGGER.debug(f"{self} # HAS controller (22)")
            self._has_ctl_ = True

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
        if self._has_ctl_ is None:
            if DEV_MODE and DEV_TYPE_MAP.HGI not in (
                self.src.type,
                self.dst.type,
            ):  # DEX
                _LOGGER.warning(f"{self} # has_ctl - undetermined (99)")
            self._has_ctl_ = False

        return self._has_ctl_

    @property
    def _has_payload(self) -> bool:
        """Return True if the packet has a non-null payload, and False otherwise.

        May return false positives. The payload may still have an idx.
        """

        if self._has_payload_ is not None:
            return self._has_payload_

        self._has_payload_ = not any(
            (
                self.len == 1,
                self.verb == RQ and self.code in RQ_NO_PAYLOAD,
                self.verb == RQ and self.len == 2 and self.code != _0016,
                # self.verb == RQ and self.len == 2 and self.code in (
                #   _2309, _2349, _3EF1
                # ),
            )
        )

        return self._has_payload_

    def _force_has_array(self) -> None:
        self._has_array_ = True
        self._ctx_ = None  # type: ignore[assignment]
        self._hdr_ = None  # type: ignore[assignment]
        self._idx_ = None  # type: ignore[assignment]

    @property
    def _ctx(self) -> Union[str, bool]:  # incl. self._idx
        """Return the payload's full context, if any (e.g. for 0404: zone_idx/frag_idx).

        Used to store packets in the entity's message DB. It is a superset of _idx.
        """

        if self._ctx_ is None:
            if self.code in (_0005, _000C):  # zone_idx, zone_type (device_role)
                self._ctx_ = self.payload[:4]
            elif self.code == _0404:  # zone_idx, frag_idx
                self._ctx_ = self._idx + self.payload[10:12]
            else:
                self._ctx_ = self._idx
        return self._ctx_

    @property
    def _hdr(self) -> str:  # incl. self._ctx
        """Return the QoS header (fingerprint) of this packet (i.e. device_id/code/hdr).

        Used for QoS (timeouts, retries), callbacks, etc.
        """

        if self._hdr_ is None:
            self._hdr_ = "|".join((self.code, self.verb))  # HACK: RecursionError
            self._hdr_ = pkt_header(self)
        return self._hdr_

    @property
    def _idx(self) -> Union[str, bool]:
        """Return the payload's index, if any (e.g. zone_idx, domain_id  or log_idx).

        Used to route a packet to the correct entity's (i.e. zone/domain) msg handler.
        """

        if self._idx_ is None:
            self._idx_ = _pkt_idx(self) or False
        return self._idx_


def _pkt_idx(pkt) -> Union[str, bool, None]:  # _has_array, _has_ctl
    """Return the payload's 2-byte context (e.g. zone_idx, domain_id or log_idx).

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
    if pkt.code == _0009 and pkt.src.type == DEV_TYPE_MAP.OTB:  # DEX
        return False

    if pkt.code == _000C:  # zone_idx/domain_id (complex, payload[0:4])
        if pkt.payload[2:4] == DEV_ROLE_MAP.APP:  # "000F"
            return FC
        if pkt.payload[0:4] == f"01{DEV_ROLE_MAP.HTG}":  # "010E"
            return F9
        if pkt.payload[2:4] in (
            DEV_ROLE_MAP.DHW,
            DEV_ROLE_MAP.HTG,
        ):  # "000D", "000E"
            return FA
        return pkt.payload[:2]

    if pkt.code == _0404:
        return FA if pkt.payload[2:4] == "23" else pkt.payload[:2]

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
        if CODES_SCHEMA[pkt.code].get(pkt.verb, "")[:3] == "^00" and (
            pkt.payload[:2] != "00"
        ):
            raise InvalidPayloadError(
                f"Packet idx is {pkt.payload[:2]}, but expecting no idx (00) (0xAA)"
            )
        return False

    # mutex 3/4, CODE_IDX_SIMPLE: potentially some false -ves?
    if pkt._has_array:
        return True  # excludes len==1 for 000A, 2309, 30C9

    # TODO: is this needed?: exceptions to CODE_IDX_SIMPLE
    if pkt.payload[:2] in (F8, F9, FA, FC):  # TODO: FB, FD
        if pkt.code not in CODE_IDX_DOMAIN:
            raise InvalidPayloadError(
                f"Packet idx is {pkt.payload[:2]}, but not expecting a domain id"
            )
        return pkt.payload[:2]

    if (
        pkt._has_ctl
    ):  # risk of false -ves, TODO: pkt.src.type == DEV_TYPE_MAP.HGI too?  # DEX
        # 02:    22C9: would be picked up as an array, if len==1 counted
        # 03:    #  I 028 03:094242 --:------ 03:094242 30C9 003 010B22  # ctl
        # 12/22: 000A|1030|2309|30C9 from (addr0 --:), 1060|3150 (addr0 04:)
        # 23:    0009|10A0
        return pkt.payload[:2]  # pkt._gwy.config.max_zones checked elsewhere

    if pkt.payload[:2] != "00":
        raise InvalidPayloadError(
            f"Packet idx is {pkt.payload[:2]}, but expecting no idx (00) (0xAB)"
        )  # TODO: add a test for this

    if pkt.code in CODE_IDX_SIMPLE:
        return None  # False  # TODO: return None (less precise) or risk false -ves?

    # mutex 4/4, CODE_IDX_UNKNOWN: an unknown code
    _LOGGER.info(f"{pkt} # Unable to determine payload index (is probably OK)")
    return None


def pkt_header(pkt, rx_header=None) -> Optional[str]:  # NOTE: used in command.py
    """Return the QoS header of a packet (all packets have a header).

    For rx_header=True, return the header of the response packet, if one is expected.
    """

    if pkt.code == _1FC9:
        #  I --- 34:021943 --:------ 34:021943 1FC9 024 00-2309-8855B7 00-1FC9-8855B7
        #  W --- 01:145038 34:021943 --:------ 1FC9 006 00-2309-06368E  # wont know src until it arrives
        #  I --- 34:021943 01:145038 --:------ 1FC9 006 00-2309-8855B7
        if not rx_header:
            device_id = NUL_DEV_ADDR.id if pkt.src == pkt.dst else pkt.dst.id
            return "|".join((pkt.code, pkt.verb, device_id))
        if pkt.src == pkt.dst:  # and pkt.verb == I_:
            return "|".join((pkt.code, W_, pkt.src.id))
        if pkt.verb == W_:  # and pkt.src != pkt.dst:
            return "|".join((pkt.code, I_, pkt.src.id))  # TODO: why not pkt.dst?
        # if pkt.verb == RQ:  # and pkt.src != pkt.dst:  # TODO: this breaks things
        #     return "|".join((pkt.code, RP, pkt.dst.id))
        return None

    addr = pkt.dst if pkt.src.type == DEV_TYPE_MAP.HGI else pkt.src  # DEX
    if not rx_header:
        header = "|".join((pkt.code, pkt.verb, addr.id))

    elif pkt.verb in (I_, RP) or pkt.src == pkt.dst:  # announcements, etc.: no response
        return None

    else:  # RQ/RP, or W/I
        header = "|".join((pkt.code, RP if pkt.verb == RQ else I_, addr.id))

    try:
        return f"{header}|{pkt._ctx}" if isinstance(pkt._ctx, str) else header
    except AssertionError:
        return header
