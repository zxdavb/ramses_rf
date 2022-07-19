#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Construct a command (packet that is to be sent).
"""
from __future__ import annotations

import asyncio
import functools
import json
import logging
from datetime import datetime as dt
from datetime import timedelta as td
from typing import (  # typeguard doesn't support PEP604 on 3.9.x
    Any,
    Iterable,
    Optional,
    TypeVar,
    Union,
)

from .address import HGI_DEV_ADDR, NON_DEV_ADDR, NUL_DEV_ADDR, Address, pkt_addrs
from .const import (
    DEV_TYPE_MAP,
    DEVICE_ID_REGEX,
    SYS_MODE_MAP,
    SZ_BACKOFF,
    SZ_DAEMON,
    SZ_DHW_IDX,
    SZ_DOMAIN_ID,
    SZ_FUNC,
    SZ_PRIORITY,
    SZ_RETRIES,
    SZ_TIMEOUT,
    SZ_ZONE_IDX,
    ZON_MODE_MAP,
    Priority,
    __dev_mode__,
)
from .exceptions import ExpiredCallbackError
from .frame import Frame, _CodeT, _DeviceIdT, _HeaderT, _PayloadT, _VerbT, pkt_header
from .helpers import (
    bool_from_hex,
    double_to_hex,
    dt_now,
    dtm_to_hex,
    str_to_hex,
    temp_to_hex,
    timestamp,
    typechecked,
)
from .opentherm import parity
from .parsers import LOOKUP_PUZZ
from .ramses import _2411_PARAMS_SCHEMA
from .version import VERSION

# skipcq: PY-W2000
from .const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    F9,
    FA,
    FC,
    FF,
    Code,
)


COMMAND_FORMAT = "{:<2} {} {} {} {} {} {:03d} {}"

TIMER_SHORT_SLEEP = 0.05
TIMER_LONG_TIMEOUT = td(seconds=60)


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


_ZoneIdxT = TypeVar("_ZoneIdxT", int, str)


class Qos:
    """The QoS class.

    This is a mess - it is the first step in cleaning up QoS.
    """

    POLL_INTERVAL = 0.002

    # tx (from sent to gwy, to get back from gwy) seems to takes appDEFAULT_KEYSrox. 0.025s
    DEFAULT_TX_TIMEOUT = td(seconds=0.2)  # 0.20 OK, but too high?
    DEFAULT_TX_RETRIES = 2
    RETRY_LIMIT_MAX = 5

    DEFAULT_RX_TIMEOUT = td(seconds=0.50)  # 0.20 seems OK, 0.10 too low sometimes
    MAX_BACKOFF_FACTOR = 2  # i.e. tx_timeout 2 ** MAX_BACKOFF

    QOS_KEYS = (SZ_PRIORITY, SZ_RETRIES, SZ_TIMEOUT, SZ_BACKOFF)

    DEFAULT_QOS = (Priority.DEFAULT, DEFAULT_TX_RETRIES, DEFAULT_TX_TIMEOUT, True)
    DEFAULT_QOS_TABLE = (
        {  # priority, retries, timeout, (enable_)backoff, c.f. DEFAULT_QOS
            f"{RQ}|{Code._0016}": (Priority.HIGH, 5, None, True),
            f"{RQ}|{Code._0006}": (Priority.HIGH, 5, None, True),
            f"{I_}|{Code._0404}": (
                Priority.HIGH,
                3,
                td(seconds=0.30),
                True,
            ),  # short Tx
            f"{RQ}|{Code._0404}": (Priority.HIGH, 3, td(seconds=1.00), True),
            f"{W_}|{Code._0404}": (
                Priority.HIGH,
                3,
                td(seconds=1.00),
                True,
            ),  # but long Rx
            f"{RQ}|{Code._0418}": (Priority.LOW, 3, None, None),
            f"{RQ}|{Code._1F09}": (Priority.HIGH, 5, None, True),
            f"{I_}|{Code._1FC9}": (Priority.HIGH, 2, td(seconds=1), False),
            f"{RQ}|{Code._3220}": (Priority.DEFAULT, 1, td(seconds=1.2), False),
            f"{W_}|{Code._3220}": (Priority.HIGH, 3, td(seconds=1.2), False),
        }
    )  # The long timeout for the OTB is for total RTT to slave (boiler)

    def __init__(
        self,
        *,
        priority=None,
        retries=None,
        timeout=None,
        backoff=None,
    ) -> None:

        self.priority = priority if priority is not None else self.DEFAULT_QOS[0]
        self.retry_limit = retries if retries is not None else self.DEFAULT_QOS[1]
        self.tx_timeout = self.DEFAULT_TX_TIMEOUT
        self.rx_timeout = timeout if timeout is not None else self.DEFAULT_QOS[2]
        self.disable_backoff = not (
            backoff if backoff is not None else self.DEFAULT_QOS[3]
        )

    @classmethod  # constructor from verb|code pair
    def verb_code(cls, verb, code, **kwargs) -> Qos:
        """Constructor to create a QoS based upon the defaults for a verb|code pair."""

        default_qos = cls.DEFAULT_QOS_TABLE.get(f"{verb}|{code}", cls.DEFAULT_QOS)
        return cls(
            **{k: kwargs.get(k, default_qos[i]) for i, k in enumerate(cls.QOS_KEYS)}
        )


def validate_api_params(*, has_zone: bool = None):
    """Decorator to protect the engine from any invalid command constructors.

    Additionally, validate/normalise some command arguments (e.g. 'HW' becomes 0xFA).
    NB: The zone_idx (domain_id) is converted to an integer, but payloads use strings
    such as f"{zone_idx}:02X".
    """

    def _wrapper(fcn, cls, *args, **kwargs):
        _LOGGER.debug(f"Calling: {fcn.__name__}({args}, {kwargs})")
        return fcn(cls, *args, **kwargs)

    def validate_zone_idx(zone_idx) -> int:
        # if zone_idx is None:
        #     return "00"  # TODO: I suspect a bad idea
        if isinstance(zone_idx, str):
            zone_idx = FA if zone_idx == "HW" else zone_idx
        zone_idx = zone_idx if isinstance(zone_idx, int) else int(zone_idx, 16)
        if 0 > zone_idx > 15 and zone_idx != 0xFA:
            raise ValueError("Invalid value for zone_idx")
        return zone_idx

    def device_decorator(fcn):
        @functools.wraps(fcn)
        def wrapper(cls, dst_id, *args, **kwargs):

            if SZ_ZONE_IDX in kwargs:  # Cmd.get_relay_demand()
                kwargs[SZ_ZONE_IDX] = validate_zone_idx(kwargs[SZ_ZONE_IDX])
            if SZ_DOMAIN_ID in kwargs:
                kwargs[SZ_DOMAIN_ID] = validate_zone_idx(kwargs[SZ_DOMAIN_ID])
            if SZ_DHW_IDX in kwargs:
                kwargs[SZ_DHW_IDX] = validate_zone_idx(kwargs[SZ_DHW_IDX])

            return _wrapper(fcn, cls, dst_id, *args, **kwargs)

        return wrapper

    def zone_decorator(fcn):
        @functools.wraps(fcn)
        def wrapper(cls, ctl_id, zone_idx, *args, **kwargs):

            zone_idx = validate_zone_idx(zone_idx)
            if SZ_DOMAIN_ID in kwargs:
                kwargs[SZ_DOMAIN_ID] = validate_zone_idx(kwargs[SZ_DOMAIN_ID])

            return _wrapper(fcn, cls, ctl_id, zone_idx, *args, **kwargs)

        return wrapper

    return zone_decorator if has_zone else device_decorator


def _normalise_mode(mode, target, until, duration) -> str:
    """Validate the zone_mode, and return a it as a normalised 2-byte code.

    Used by set_dhw_mode (target=active) and set_zone_mode (target=setpoint). May raise
    KeyError or ValueError.
    """

    if mode is None and target is None:
        raise ValueError("Invalid args: One of mode or setpoint/active cant be None")
    if until and duration:
        raise ValueError("Invalid args: At least one of until or duration must be None")

    if mode is None:
        if until:
            mode = ZON_MODE_MAP.TEMPORARY
        elif duration:
            mode = ZON_MODE_MAP.COUNTDOWN
        else:
            mode = ZON_MODE_MAP.PERMANENT  # TODO: advanced_override?
    elif mode not in ZON_MODE_MAP:  # may raise KeyError
        mode = ZON_MODE_MAP._hex(f"{mode:02X}" if isinstance(mode, int) else mode)

    if mode != ZON_MODE_MAP.FOLLOW_SCHEDULE and target is None:
        raise ValueError(
            f"Invalid args: For {ZON_MODE_MAP[mode]}, setpoint/active cant be None"
        )

    return mode


def _normalise_until(mode, _, until, duration) -> tuple[Any, Any]:
    """Validate until and duration, and return a normalised xxx.

    Used by set_dhw_mode and set_zone_mode. May raise KeyError or ValueError.
    """
    # if until and duration:
    #     raise ValueError("Invalid args: Only one of until or duration can be set")

    if mode == ZON_MODE_MAP.TEMPORARY:
        if duration is not None:
            raise ValueError(
                f"Invalid args: For {ZON_MODE_MAP[mode]}, duration must be None"
            )
        if until is None:
            mode = ZON_MODE_MAP.ADVANCED  # or: until = dt.now() + td(hour=1)

    elif mode in ZON_MODE_MAP.COUNTDOWN:
        if duration is None:
            raise ValueError(
                f"Invalid args: For {ZON_MODE_MAP[mode]}, duration cant be None"
            )
        if until is not None:
            raise ValueError(
                f"Invalid args: For {ZON_MODE_MAP[mode]}, until must be None"
            )

    elif until is not None or duration is not None:
        raise ValueError(
            f"Invalid args: For {ZON_MODE_MAP[mode]},"
            " until and duration must both be None"
        )

    return until, duration


def _qos_params(verb: _VerbT, code: _CodeT, qos: dict) -> Qos:
    """Class constrcutor wrapped to prevent cyclic reference."""
    return Qos.verb_code(verb, code, **qos)


@functools.total_ordering
class Command(Frame):
    """The Command class (packets to be transmitted).

    They have QoS and/or callbacks (but no RSSI).
    """

    def __init__(self, frame: str, qos: dict = None, callback: dict = None) -> None:
        """Create a command from a string (and its meta-attrs).

        Will raise InvalidPacketError if it is invalid.
        """

        super().__init__(frame)  # may raise InvalidPacketError if it is invalid

        # used by app layer: callback (protocol.py: func, args, daemon, timeout)
        self._cbk = callback or {}
        # used by pkt layer: qos (transport.py: backoff, priority, retries, timeout)
        self._qos = _qos_params(self.verb, self.code, qos or {})

        # used for by msg layer (for which cmd to send next)
        self._priority = self._qos.priority  # TODO: should only be a QoS attr
        self._dtm = dt_now()

        self._rx_header: None | str = None
        self._source_entity = None

        self._validate(strict_checking=False)

    @classmethod  # convenience constructor
    def from_attrs(
        cls,
        verb: _VerbT,
        dest_id,
        code: _CodeT,
        payload: _PayloadT,
        *,
        from_id=None,
        seqn=None,
        **kwargs,
    ):
        """Create a command from its attrs using a destination device_id."""

        from_id = from_id or HGI_DEV_ADDR.id

        if dest_id == from_id:
            addrs = (from_id, NON_DEV_ADDR.id, dest_id)
        else:
            addrs = (from_id, dest_id, NON_DEV_ADDR.id)

        return cls._from_attrs(
            verb,
            code,
            payload,
            addr0=addrs[0],
            addr1=addrs[1],
            addr2=addrs[2],
            seqn=seqn,
            **kwargs,
        )

    @classmethod  # generic constructor
    def _from_attrs(
        cls,
        verb: _VerbT,
        code: _CodeT,
        payload: _PayloadT,
        *,
        addr0=None,
        addr1=None,
        addr2=None,
        seqn=None,
        **kwargs,
    ):
        """Create a command from its attrs using an address set."""

        verb = I_ if verb == "I" else W_ if verb == "W" else verb

        addr0 = addr0 or NON_DEV_ADDR.id
        addr1 = addr1 or NON_DEV_ADDR.id
        addr2 = addr2 or NON_DEV_ADDR.id

        _, _, *addrs = pkt_addrs(" ".join((addr0, addr1, addr2)))
        # print(pkt_addrs(" ".join((addr0, addr1, addr2))))

        if seqn in (None, "", "-", "--", "---"):
            seqn = "---"
        else:
            seqn = f"{int(seqn):03d}"

        len_ = f"{int(len(payload) / 2):03d}"

        frame = " ".join(
            (
                verb,
                seqn,
                *(a.id for a in addrs),
                code,
                len_,
                payload,
            )
        )

        return cls(frame, **kwargs)

    @classmethod  # used by CLI for -x switch
    def from_cli(cls, cmd_str: str, **kwargs):
        """Create a command from a CLI string (the -x switch).

        Examples include (whitespace for readability):
            'RQ     01:123456               1F09 00'
            'RQ     01:123456     13:123456 3EF0 00'
            'RQ     07:045960     01:054173 10A0 00137400031C'
            ' W 123 30:045960 -:- 32:054173 22F1 001374'
        """

        cmd = cmd_str.upper().split()
        if len(cmd) < 4:
            raise ValueError(
                f"Command string is not parseable: '{cmd_str}'"
                ", format is: verb [seqn] addr0 [addr1 [addr2]] code payload"
            )

        verb = cmd.pop(0)
        seqn = "---" if DEVICE_ID_REGEX.ANY.match(cmd[0]) else cmd.pop(0)
        payload = cmd.pop()[:48]
        code = cmd.pop()

        if not 0 < len(cmd) < 4:
            raise ValueError(f"Command is invalid: '{cmd_str}'")
        elif len(cmd) == 1 and verb == I_:
            # drs = (cmd[0],          NON_DEV_ADDR.id, cmd[0])
            addrs = (NON_DEV_ADDR.id, NON_DEV_ADDR.id, cmd[0])
        elif len(cmd) == 1:
            addrs = (HGI_DEV_ADDR.id, cmd[0], NON_DEV_ADDR.id)
        elif len(cmd) == 2 and cmd[0] == cmd[1]:
            addrs = (cmd[0], NON_DEV_ADDR.id, cmd[1])
        elif len(cmd) == 2:
            addrs = (cmd[0], cmd[1], NON_DEV_ADDR.id)
        else:
            addrs = (cmd[0], cmd[1], cmd[2])

        return cls._from_attrs(
            verb,
            code,
            payload,
            **{f"addr{k}": v for k, v in enumerate(addrs)},
            seqn=seqn,
            **kwargs,
        )

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        hdr = f' # {self._hdr}{f" ({self._ctx})" if self._ctx else ""}'
        return f"... {self}{hdr}"

    def __str__(self) -> str:
        """Return an brief readable string representation of this object."""
        return super().__repr__()

    def __eq__(self, other: Any) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self._priority, self._dtm) == (other._priority, other._dtm)

    def __lt__(self, other: Any) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self._priority, self._dtm) < (other._priority, other._dtm)

    @staticmethod
    def _is_valid_operand(other: Any) -> bool:
        return hasattr(other, "_priority") and hasattr(other, "_dtm")

    @property
    def tx_header(self) -> _HeaderT:
        """Return the QoS header of this (request) packet."""

        return self._hdr

    @property
    def rx_header(self) -> None | _HeaderT:
        """Return the QoS header of a corresponding response packet (if any)."""

        if self.tx_header and self._rx_header is None:
            self._rx_header = pkt_header(self, rx_header=True)
        return self._rx_header

    @classmethod  # constructor for I|22F7
    @typechecked
    @validate_api_params()
    def set_bypass_position(
        cls,
        fan_id: _DeviceIdT,
        *,
        bypass_position: float = None,
        src_id: _DeviceIdT = None,
        **kwargs,
    ):
        """Constructor to set the position of the bypass valve (c.f. parser_22f7).

        bypass_position: a % from fully open (1.0) to fully closed (0.0).
        None is a sentinel value for auto.

        bypass_mode: is a proxy for bypass_position (they should be mutex)
        """

        # RQ --- 37:155617 32:155617 --:------ 22F7 002 0064  # offically: 00C8EF
        # RP --- 32:155617 37:155617 --:------ 22F7 003 00C8C8

        src_id = src_id or fan_id  # TODO: src_id should be an arg?

        if (bypass_mode := kwargs.pop("bypass_mode", None)) and (
            bypass_position is not None
        ):
            raise ValueError(
                "bypass_mode and bypass_position are mutally exclusive, "
                "both cannot be provided, and neither is OK"
            )
        elif bypass_position is not None:
            pos = f"{int(bypass_position * 200):02X}"
        elif bypass_mode:
            pos = {"auto": "FF", "off": "00", "on": "C8"}[bypass_mode]
        else:
            pos = "FF"  # auto

        return cls._from_attrs(
            W_, Code._22F7, f"00{pos}", addr0=src_id, addr1=fan_id, **kwargs
        )  # trailing EF not required

    @classmethod  # constructor for W|2411
    @typechecked
    @validate_api_params()
    def set_fan_param(
        cls,
        fan_id: _DeviceIdT,
        param_id: str,
        value: str,
        *,
        src_id: _DeviceIdT = None,
        **kwargs,
    ):
        """Constructor to set a configurable fan parameter (c.f. parser_2411)."""

        src_id = src_id or fan_id  # TODO: src_id should be an arg?

        if not _2411_PARAMS_SCHEMA.get(param_id):  # TODO: not exlude unknowns?
            raise ValueError(f"Unknown parameter: {param_id}")

        payload = f"0000{param_id}0000{value:08X}"  # TODO: needs work

        return cls._from_attrs(
            W_, Code._2411, payload, addr0=src_id, addr1=fan_id, **kwargs
        )

    @classmethod  # constructor for I|22F1
    @typechecked
    @validate_api_params()
    def set_fan_mode(
        cls,
        fan_id: _DeviceIdT,
        fan_mode,
        *,
        seqn: int = None,
        src_id: _DeviceIdT = None,
        idx: str = "00",  # could be e.g. "63"
        **kwargs,
    ):
        """Constructor to get the fan speed (and heater?) (c.f. parser_22f1).

        There are two types of this packet seen (with seqn, or with src_id):
         - I 018 --:------ --:------ 39:159057 22F1 003 000204
         - I --- 21:039407 28:126495 --:------ 22F1 003 000407
        """

        # Scheme 1: I 218 --:------ --:------ 39:159057
        #  - are cast as a triplet, 0.1s apart?, with a seqn (000-255) and no src_id
        #  - triplet has same seqn, increased monotonically mod 256 after every triplet
        #  - only payloads seen: '(00|63)0[234]04', may accept '000.'
        # .I 218 --:------ --:------ 39:159057 22F1 003 000204  # low

        # Scheme 1a: I --- --:------ --:------ 21:038634 (less common)
        #  - some systems that accept scheme 2 will accept this scheme

        # Scheme 2: I --- 21:038634 18:126620 --:------ (less common)
        #  - are cast as a triplet, 0.085s apart, without a seqn (i.e. is ---)
        #  - only payloads seen: '000.0[47A]', may accept '000.'
        # .I --- 21:038634 18:126620 --:------ 22F1 003 000507

        from .ramses import _22F1_MODE_ORCON

        _22F1_MODE_ORCON_MAP = {v: k for k, v in _22F1_MODE_ORCON.items()}

        if fan_mode is None:
            mode = "00"
        elif isinstance(fan_mode, int):
            mode = f"{fan_mode:02X}"
        else:
            mode = fan_mode

        if mode in _22F1_MODE_ORCON:
            payload = f"{idx}{mode}"
        elif mode in _22F1_MODE_ORCON_MAP:
            payload = f"{idx}{_22F1_MODE_ORCON_MAP[mode]}"
        else:
            raise TypeError(f"fan_mode is not valid: {fan_mode}")

        if src_id and seqn:
            raise TypeError(
                "seqn and src_id are mutally exclusive (you can have neither)"
            )

        if seqn:
            return cls._from_attrs(
                I_, Code._22F1, payload, addr2=fan_id, seqn=seqn, **kwargs
            )
        return cls._from_attrs(
            I_, Code._22F1, payload, addr0=src_id, addr1=fan_id, **kwargs
        )

    @classmethod  # constructor for RQ|1F41
    @typechecked
    @validate_api_params()
    def get_dhw_mode(cls, ctl_id: _DeviceIdT, **kwargs):
        """Constructor to get the mode of the DHW (c.f. parser_1f41)."""

        dhw_idx = f"{kwargs.pop(SZ_DHW_IDX, 0):02X}"  # only 00 or 01 (rare)
        return cls.from_attrs(RQ, ctl_id, Code._1F41, dhw_idx, **kwargs)

    @classmethod  # constructor for W|1F41
    @typechecked
    @validate_api_params()
    def set_dhw_mode(
        cls,
        ctl_id: _DeviceIdT,
        *,
        mode: Union[None, int, str] = None,
        active: bool = None,
        until: Union[None, dt, str] = None,
        duration: int = None,
        **kwargs,
    ):
        """Constructor to set/reset the mode of the DHW (c.f. parser_1f41)."""

        dhw_idx = f"{kwargs.pop(SZ_DHW_IDX, 0):02X}"  # only 00 or 01 (rare)

        mode = mode or 0
        mode = f"{mode:02X}" if isinstance(mode, int) else mode
        mode = _normalise_mode(mode, active, until, duration)

        if mode == ZON_MODE_MAP.FOLLOW:
            active = None

        if active is not None and not isinstance(active, (bool, int)):
            raise TypeError(f"Invalid args: active={active}, but must be an bool")

        until, duration = _normalise_until(mode, active, until, duration)

        payload = "".join(
            (
                dhw_idx,
                "FF" if active is None else "01" if bool(active) else "00",
                mode,
                "FFFFFF" if duration is None else f"{duration:06X}",
                "" if until is None else dtm_to_hex(until),
            )
        )

        return cls.from_attrs(W_, ctl_id, Code._1F41, payload, **kwargs)

    @classmethod  # constructor for RQ|10A0
    @typechecked
    @validate_api_params()
    def get_dhw_params(cls, ctl_id: _DeviceIdT, **kwargs):
        """Constructor to get the params of the DHW (c.f. parser_10a0)."""

        dhw_idx = f"{kwargs.pop(SZ_DHW_IDX, 0):02X}"  # only 00 or 01 (rare)
        return cls.from_attrs(RQ, ctl_id, Code._10A0, dhw_idx, **kwargs)

    @classmethod  # constructor for W|10A0
    @validate_api_params()
    @typechecked
    def set_dhw_params(
        cls,
        ctl_id: _DeviceIdT,
        *,
        setpoint: float = 50.0,
        overrun: int = 5,
        differential: float = 1,
        **kwargs,
    ):
        """Constructor to set the params of the DHW (c.f. parser_10a0)."""
        # Defaults for newer evohome colour:
        # Defaults for older evohome colour: ?? (30-85) C, ? (0-10) min, ? (1-10) C
        # Defaults for evohome monochrome:

        # 14:34:26.734 022  W --- 18:013393 01:145038 --:------ 10A0 006 000F6E050064
        # 14:34:26.751 073  I --- 01:145038 --:------ 01:145038 10A0 006 000F6E0003E8
        # 14:34:26.764 074  I --- 01:145038 18:013393 --:------ 10A0 006 000F6E0003E8

        dhw_idx = f"{kwargs.pop(SZ_DHW_IDX, 0):02X}"  # only 00 or 01 (rare)

        setpoint = 50.0 if setpoint is None else setpoint
        overrun = 5 if overrun is None else overrun
        differential = 1.0 if differential is None else differential

        if not (30.0 <= setpoint <= 85.0):
            raise ValueError(f"Out of range, setpoint: {setpoint}")
        if not (0 <= overrun <= 10):
            raise ValueError(f"Out of range, overrun: {overrun}")
        if not (1 <= differential <= 10):
            raise ValueError(f"Out of range, differential: {differential}")

        payload = (
            f"{dhw_idx}{temp_to_hex(setpoint)}{overrun:02X}{temp_to_hex(differential)}"
        )

        return cls.from_attrs(W_, ctl_id, Code._10A0, payload, **kwargs)

    @classmethod  # constructor for RQ|1260
    @typechecked
    @validate_api_params()
    def get_dhw_temp(cls, ctl_id: _DeviceIdT, **kwargs):
        """Constructor to get the temperature of the DHW sensor (c.f. parser_10a0)."""

        dhw_idx = f"{kwargs.pop(SZ_DHW_IDX, 0):02X}"  # only 00 or 01 (rare)
        return cls.from_attrs(RQ, ctl_id, Code._1260, dhw_idx, **kwargs)

    @classmethod  # constructor for RQ|1030
    @typechecked
    @validate_api_params(has_zone=True)
    def get_mix_valve_params(cls, ctl_id: _DeviceIdT, zone_idx: _ZoneIdxT, **kwargs):
        """Constructor to get the mix valve params of a zone (c.f. parser_1030)."""

        return cls.from_attrs(
            RQ, ctl_id, Code._1030, f"{zone_idx:02X}00", **kwargs
        )  # TODO: needs 00?

    @classmethod  # constructor for W|1030
    @typechecked
    @validate_api_params(has_zone=True)
    def set_mix_valve_params(
        cls,
        ctl_id: _DeviceIdT,
        zone_idx: _ZoneIdxT,
        *,
        max_flow_setpoint=55,
        min_flow_setpoint=15,
        valve_run_time=150,
        pump_run_time=15,
        **kwargs,
    ):
        """Constructor to set the mix valve params of a zone (c.f. parser_1030)."""

        boolean_cc = kwargs.pop("boolean_cc", 1)
        kwargs.get("unknown_20", None)  # HVAC
        kwargs.get("unknown_21", None)  # HVAC

        if not (0 <= max_flow_setpoint <= 99):
            raise ValueError(f"Out of range, max_flow_setpoint: {max_flow_setpoint}")
        if not (0 <= min_flow_setpoint <= 50):
            raise ValueError(f"Out of range, min_flow_setpoint: {min_flow_setpoint}")
        if not (0 <= valve_run_time <= 240):
            raise ValueError(f"Out of range, valve_run_time: {valve_run_time}")
        if not (0 <= pump_run_time <= 99):
            raise ValueError(f"Out of range, pump_run_time: {pump_run_time}")

        payload = "".join(
            (
                f"{zone_idx:02X}",
                f"C801{max_flow_setpoint:02X}",
                f"C901{min_flow_setpoint:02X}",
                f"CA01{valve_run_time:02X}",
                f"CB01{pump_run_time:02X}",
                f"CC01{boolean_cc:02X}",
            )
        )

        return cls.from_attrs(W_, ctl_id, Code._1030, payload, **kwargs)

    @classmethod  # constructor for RQ|3220
    @typechecked
    @validate_api_params()
    def get_opentherm_data(cls, otb_id: _DeviceIdT, msg_id: Union[int, str], **kwargs):
        """Constructor to get (Read-Data) opentherm msg value (c.f. parser_3220)."""

        msg_id = msg_id if isinstance(msg_id, int) else int(msg_id, 16)
        payload = f"0080{msg_id:02X}0000" if parity(msg_id) else f"0000{msg_id:02X}0000"
        return cls.from_attrs(RQ, otb_id, Code._3220, payload, **kwargs)

    @classmethod  # constructor for RQ|0008
    @typechecked
    @validate_api_params()  # has_zone is optional
    def get_relay_demand(cls, dev_id: _DeviceIdT, zone_idx: _ZoneIdxT = None, **kwargs):
        """Constructor to get the demand of a relay/zone (c.f. parser_0008)."""

        payload = "00" if zone_idx is None else f"{zone_idx:02X}"
        return cls.from_attrs(RQ, dev_id, Code._0008, payload, **kwargs)

    @classmethod  # constructor for RQ|0006
    @typechecked
    @validate_api_params()
    def get_schedule_version(cls, ctl_id: _DeviceIdT, **kwargs):
        """Constructor to get the current version (change counter) of the schedules.

        This number is increased whenever any zone's schedule is changed (incl. the DHW
        zone), and is used to avoid the relatively large expense of downloading a
        schedule, only to see that it hasn't changed.
        """

        return cls.from_attrs(RQ, ctl_id, Code._0006, "00", **kwargs)

    @classmethod  # constructor for RQ|0404
    @typechecked
    @validate_api_params(has_zone=True)
    def get_schedule_fragment(
        cls,
        ctl_id: _DeviceIdT,
        zone_idx: _ZoneIdxT,
        frag_number: int,
        total_frags: Optional[int],
        **kwargs,
    ):
        """Constructor to get a schedule fragment (c.f. parser_0404).

        Usually a zone, but will be the DHW schedule if zone_idx == 0xFA, 'FA', or 'HW'.
        """

        if total_frags is None:
            total_frags = 0

        kwargs.pop("frag_length", None)
        frag_length = "00"

        # TODO: check the following rules
        if frag_number == 0:
            raise ValueError(f"frag_number={frag_number}, but it is 1-indexed")
        elif frag_number == 1 and total_frags != 0:
            raise ValueError(
                f"total_frags={total_frags}, but must be 0 when frag_number=1"
            )
        elif frag_number > total_frags and total_frags != 0:
            raise ValueError(
                f"frag_number={frag_number}, but must be <= total_frags={total_frags}"
            )

        header = "00230008" if zone_idx == 0xFA else f"{zone_idx:02X}200008"

        payload = f"{header}{frag_length}{frag_number:02X}{total_frags:02X}"
        return cls.from_attrs(RQ, ctl_id, Code._0404, payload, **kwargs)

    @classmethod  # constructor for W|0404
    @typechecked
    @validate_api_params(has_zone=True)
    def set_schedule_fragment(
        cls,
        ctl_id: _DeviceIdT,
        zone_idx: _ZoneIdxT,
        frag_num: int,
        frag_cnt: int,
        fragment: str,
        **kwargs,
    ):
        """Constructor to set a zone schedule fragment (c.f. parser_0404).

        Usually a zone, but will be the DHW schedule if zone_idx == 0xFA, 'FA', or 'HW'.
        """

        # TODO: check the following rules
        if frag_num == 0:
            raise ValueError(f"frag_num={frag_num}, but it is 1-indexed")
        elif frag_num > frag_cnt:
            raise ValueError(f"frag_num={frag_num}, but must be <= frag_cnt={frag_cnt}")

        header = "00230008" if zone_idx == 0xFA else f"{zone_idx:02X}200008"
        frag_length = int(len(fragment) / 2)

        payload = f"{header}{frag_length:02X}{frag_num:02X}{frag_cnt:02X}{fragment}"
        return cls.from_attrs(W_, ctl_id, Code._0404, payload, **kwargs)

    @classmethod  # constructor for RQ|0100
    @typechecked
    @validate_api_params()
    def get_system_language(cls, ctl_id: _DeviceIdT, **kwargs):
        """Constructor to get the language of a system (c.f. parser_0100)."""

        return cls.from_attrs(RQ, ctl_id, Code._0100, "00", **kwargs)

    @classmethod  # constructor for RQ|0418
    @typechecked
    @validate_api_params()
    def get_system_log_entry(
        cls, ctl_id: _DeviceIdT, log_idx: Union[int, str], **kwargs
    ):
        """Constructor to get a log entry from a system (c.f. parser_0418)."""

        log_idx = log_idx if isinstance(log_idx, int) else int(log_idx, 16)
        return cls.from_attrs(RQ, ctl_id, Code._0418, f"{log_idx:06X}", **kwargs)

    @classmethod  # constructor for RQ|2E04
    @typechecked
    @validate_api_params()
    def get_system_mode(cls, ctl_id: _DeviceIdT, **kwargs):
        """Constructor to get the mode of a system (c.f. parser_2e04)."""

        return cls.from_attrs(RQ, ctl_id, Code._2E04, FF, **kwargs)

    @classmethod  # constructor for W|2E04
    @typechecked
    @validate_api_params()
    def set_system_mode(
        cls,
        ctl_id: _DeviceIdT,
        system_mode,
        *,
        until: Union[None, dt, str] = None,
        **kwargs,
    ):
        """Constructor to set/reset the mode of a system (c.f. parser_2e04)."""

        if system_mode is None:
            raise ValueError("Invalid args: system_mode cant be None")

        system_mode = SYS_MODE_MAP._hex(
            f"{system_mode:02X}" if isinstance(system_mode, int) else system_mode
        )  # may raise KeyError

        if until is not None and system_mode in (
            SYS_MODE_MAP.AUTO,
            SYS_MODE_MAP.AUTO_WITH_RESET,
            SYS_MODE_MAP.HEAT_OFF,
        ):
            raise ValueError(
                f"Invalid args: For system_mode={SYS_MODE_MAP[system_mode]},"
                " until must be None"
            )

        payload = "".join(
            (
                system_mode,
                dtm_to_hex(until),
                "00" if until is None else "01",
            )
        )

        return cls.from_attrs(W_, ctl_id, Code._2E04, payload, **kwargs)

    @classmethod  # constructor for RQ|313F
    @typechecked
    @validate_api_params()
    def get_system_time(cls, ctl_id: _DeviceIdT, **kwargs):
        """Constructor to get the datetime of a system (c.f. parser_313f)."""

        return cls.from_attrs(RQ, ctl_id, Code._313F, "00", **kwargs)

    @classmethod  # constructor for W|313F
    @typechecked
    @validate_api_params()
    def set_system_time(
        cls,
        ctl_id: _DeviceIdT,
        datetime: Union[dt, str],
        is_dst: Optional[bool] = False,
        **kwargs,
    ):
        """Constructor to set the datetime of a system (c.f. parser_313f)."""
        # .W --- 30:185469 01:037519 --:------ 313F 009 0060003A0C1B0107E5

        dt_str = dtm_to_hex(datetime, is_dst=is_dst, incl_seconds=True)
        return cls.from_attrs(W_, ctl_id, Code._313F, f"0060{dt_str}", **kwargs)

    @classmethod  # constructor for RQ|1100
    @typechecked
    @validate_api_params()
    def get_tpi_params(cls, dev_id: _DeviceIdT, *, domain_id=None, **kwargs):
        """Constructor to get the TPI params of a system (c.f. parser_1100)."""

        if domain_id is None:
            domain_id = "00" if dev_id[:2] == DEV_TYPE_MAP.BDR else FC
        return cls.from_attrs(RQ, dev_id, Code._1100, domain_id, **kwargs)

    @classmethod  # constructor for W|1100
    # @typechecked  # TODO
    @validate_api_params()
    def set_tpi_params(
        cls,
        ctl_id: _DeviceIdT,
        domain_id: Optional[str],
        *,
        cycle_rate: int = 3,  # TODO: check
        min_on_time: int = 5,  # TODO: check
        min_off_time: int = 5,  # TODO: check
        proportional_band_width: Optional[float] = None,  # TODO: check
        **kwargs,
    ):
        """Constructor to set the TPI params of a system (c.f. parser_1100)."""

        if domain_id is None:
            domain_id = "00"

        # assert cycle_rate is None or cycle_rate in (3, 6, 9, 12), cycle_rate
        # assert min_on_time is None or 1 <= min_on_time <= 5, min_on_time
        # assert min_off_time is None or 1 <= min_off_time <= 5, min_off_time
        # assert (
        #     proportional_band_width is None or 1.5 <= proportional_band_width <= 3.0
        # ), proportional_band_width

        payload = "".join(
            (
                f"{domain_id:02X}" if isinstance(domain_id, int) else domain_id,
                f"{cycle_rate * 4:02X}",
                f"{int(min_on_time * 4):02X}",
                f"{int(min_off_time * 4):02X}00",  # or: ...FF",
                f"{temp_to_hex(proportional_band_width)}01",
            )
        )

        return cls.from_attrs(W_, ctl_id, Code._1100, payload, **kwargs)

    @classmethod  # constructor for RQ|000A
    @typechecked
    @validate_api_params(has_zone=True)
    def get_zone_config(cls, ctl_id: _DeviceIdT, zone_idx: _ZoneIdxT, **kwargs):
        """Constructor to get the config of a zone (c.f. parser_000a)."""

        return cls.from_attrs(
            RQ, ctl_id, Code._000A, f"{zone_idx:02X}00", **kwargs
        )  # TODO: needs 00?

    @classmethod  # constructor for W|000A
    @typechecked
    @validate_api_params(has_zone=True)
    def set_zone_config(
        cls,
        ctl_id: _DeviceIdT,
        zone_idx: _ZoneIdxT,
        *,
        min_temp: float = 5,
        max_temp: float = 35,
        local_override: bool = False,
        openwindow_function: bool = False,
        multiroom_mode: bool = False,
        **kwargs,
    ):
        """Constructor to set the config of a zone (c.f. parser_000a)."""

        if not (5 <= min_temp <= 21):
            raise ValueError(f"Out of range, min_temp: {min_temp}")
        if not (21 <= max_temp <= 35):
            raise ValueError(f"Out of range, max_temp: {max_temp}")
        if not isinstance(local_override, bool):
            raise ValueError(f"Invalid arg, local_override: {local_override}")
        if not isinstance(openwindow_function, bool):
            raise ValueError(f"Invalid arg, openwindow_function: {openwindow_function}")
        if not isinstance(multiroom_mode, bool):
            raise ValueError(f"Invalid arg, multiroom_mode: {multiroom_mode}")

        bitmap = 0 if local_override else 1
        bitmap |= 0 if openwindow_function else 2
        bitmap |= 0 if multiroom_mode else 16

        payload = "".join(
            (
                f"{zone_idx:02X}",
                f"{bitmap:02X}",
                temp_to_hex(min_temp),
                temp_to_hex(max_temp),
            )
        )

        return cls.from_attrs(W_, ctl_id, Code._000A, payload, **kwargs)

    @classmethod  # constructor for RQ|2349
    @typechecked
    @validate_api_params(has_zone=True)
    def get_zone_mode(cls, ctl_id: _DeviceIdT, zone_idx: _ZoneIdxT, **kwargs):
        """Constructor to get the mode of a zone (c.f. parser_2349)."""

        return cls.from_attrs(
            RQ, ctl_id, Code._2349, f"{zone_idx:02X}00", **kwargs
        )  # TODO: needs 00?

    @classmethod  # constructor for W|2349
    @typechecked
    @validate_api_params(has_zone=True)
    def set_zone_mode(
        cls,
        ctl_id: _DeviceIdT,
        zone_idx: _ZoneIdxT,
        *,
        mode: str = None,
        setpoint: float = None,
        until: Union[None, dt, str] = None,
        duration: int = None,
        **kwargs,
    ):
        """Constructor to set/reset the mode of a zone (c.f. parser_2349).

        The setpoint has a resolution of 0.1 C. If a setpoint temperature is required,
        but none is provided, evohome will use the maximum possible value.

        The until has a resolution of 1 min.

        Incompatible combinations:
        - mode == Follow & setpoint not None (will silently ignore setpoint)
        - mode == Temporary & until is None (will silently ignore ???)
        - until and duration are mutually exclusive
        """
        # .W --- 18:013393 01:145038 --:------ 2349 013 0004E201FFFFFF330B1A0607E4
        # .W --- 22:017139 01:140959 --:------ 2349 007 0801F400FFFFFF

        mode = _normalise_mode(mode, setpoint, until, duration)

        if setpoint is not None and not isinstance(setpoint, (float, int)):
            raise TypeError(f"Invalid args: setpoint={setpoint}, but must be a float")

        until, duration = _normalise_until(mode, setpoint, until, duration)

        payload = "".join(
            (
                f"{zone_idx:02X}",
                temp_to_hex(setpoint),  # None means max, if a temp is required
                mode,
                "FFFFFF" if duration is None else f"{duration:06X}",
                "" if until is None else dtm_to_hex(until),
            )
        )

        return cls.from_attrs(W_, ctl_id, Code._2349, payload, **kwargs)

    @classmethod  # constructor for RQ|0004
    @typechecked
    @validate_api_params(has_zone=True)
    def get_zone_name(cls, ctl_id: _DeviceIdT, zone_idx: _ZoneIdxT, **kwargs):
        """Constructor to get the name of a zone (c.f. parser_0004)."""

        return cls.from_attrs(
            RQ, ctl_id, Code._0004, f"{zone_idx:02X}00", **kwargs
        )  # TODO: needs 00?

    @classmethod  # constructor for W|0004
    @typechecked
    @validate_api_params(has_zone=True)
    def set_zone_name(
        cls, ctl_id: _DeviceIdT, zone_idx: _ZoneIdxT, name: str, **kwargs
    ):
        """Constructor to set the name of a zone (c.f. parser_0004)."""

        payload = f"{zone_idx:02X}00{str_to_hex(name)[:40]:0<40}"
        return cls.from_attrs(W_, ctl_id, Code._0004, payload, **kwargs)

    @classmethod  # constructor for W|2309
    @typechecked
    @validate_api_params(has_zone=True)
    def set_zone_setpoint(
        cls, ctl_id: _DeviceIdT, zone_idx: _ZoneIdxT, setpoint: float, **kwargs
    ):
        """Constructor to set the setpoint of a zone (c.f. parser_2309)."""
        # .W --- 34:092243 01:145038 --:------ 2309 003 0107D0

        payload = f"{zone_idx:02X}{temp_to_hex(setpoint)}"
        return cls.from_attrs(W_, ctl_id, Code._2309, payload, **kwargs)

    @classmethod  # constructor for RQ|30C9
    @typechecked
    @validate_api_params(has_zone=True)
    def get_zone_temp(cls, ctl_id: _DeviceIdT, zone_idx: _ZoneIdxT, **kwargs):
        """Constructor to get the current temperature of a zone (c.f. parser_30c9)."""

        return cls.from_attrs(RQ, ctl_id, Code._30C9, f"{zone_idx:02X}", **kwargs)

    @classmethod  # constructor for RQ|12B0
    @typechecked
    @validate_api_params(has_zone=True)
    def get_zone_window_state(cls, ctl_id: _DeviceIdT, zone_idx: _ZoneIdxT, **kwargs):
        """Constructor to get the openwindow state of a zone (c.f. parser_12b0)."""

        return cls.from_attrs(RQ, ctl_id, Code._12B0, f"{zone_idx:02X}", **kwargs)

    @classmethod  # constructor for RP|3EF1 (I|3EF1?)  # TODO: trap corrupt values?
    @typechecked
    @validate_api_params()
    def put_actuator_cycle(
        cls,
        src_id: _DeviceIdT,
        dst_id: _DeviceIdT,
        modulation_level: float,
        actuator_countdown: int,
        *,
        cycle_countdown: int = None,
        **kwargs,
    ):
        """Constructor to announce the internal state of an actuator (3EF1).

        This is for use by a faked BDR91A or similar.
        """
        # RP --- 13:049798 18:006402 --:------ 3EF1 007 00-0126-0126-00-FF

        if src_id[:2] != DEV_TYPE_MAP.BDR:
            raise TypeError(
                f"Faked device {src_id} has an unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.BDR}:xxxxxx"
            )

        payload = "00"
        payload += f"{cycle_countdown:04X}" if cycle_countdown is not None else "7FFF"
        payload += f"{actuator_countdown:04X}"
        payload += f"{int(modulation_level * 200):02X}FF"  # percent_to_hex
        return cls._from_attrs(
            RP, Code._3EF1, payload, addr0=src_id, addr1=dst_id, **kwargs
        )

    @classmethod  # constructor for I|3EF0  # TODO: trap corrupt states?
    @typechecked
    @validate_api_params()
    def put_actuator_state(cls, dev_id: _DeviceIdT, modulation_level: float, **kwargs):
        """Constructor to announce the modulation level of an actuator (3EF0).

        This is for use by a faked BDR91A or similar.
        """
        # .I --- 13:049798 --:------ 13:049798 3EF0 003 00C8FF
        # .I --- 13:106039 --:------ 13:106039 3EF0 003 0000FF

        if dev_id[:2] != DEV_TYPE_MAP.BDR:
            raise TypeError(
                f"Faked device {dev_id} has an unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.BDR}:xxxxxx"
            )

        payload = (
            "007FFF"
            if modulation_level is None
            else f"00{int(modulation_level * 200):02X}FF"
        )
        return cls._from_attrs(
            I_, Code._3EF0, payload, addr0=dev_id, addr2=dev_id, **kwargs
        )

    @classmethod  # constructor for 1FC9 (rf_bind) 3-way handshake
    @typechecked
    def put_bind(
        cls,
        verb: _VerbT,
        codes: _CodeT | Iterable[_CodeT],
        src_id: _DeviceIdT,
        *,
        idx="00",
        dst_id: None | _DeviceIdT = None,
        **kwargs,
    ):
        """Constructor for RF bind commands (1FC9), for use by faked devices."""

        # .I --- 34:021943 --:------ 34:021943 1FC9 024 00-2309-8855B7 00-1FC9-8855B7
        # .W --- 01:145038 34:021943 --:------ 1FC9 006 00-2309-06368E
        # .I --- 34:021943 01:145038 --:------ 1FC9 006 00-2309-8855B7

        hex_id = Address.convert_to_hex(src_id)
        codes = ([codes] if isinstance(codes, _CodeT) else list(codes)) + [Code._1FC9]

        if dst_id is None and verb == I_:
            payload = "".join(f"{idx}{c}{hex_id}" for c in codes)
            addr2 = src_id

        elif dst_id and verb in (I_, W_):
            payload = f"00{codes[0]}{hex_id}"
            addr2 = NON_DEV_ADDR.id

        else:
            raise ValueError("Invalid parameters")

        kwargs["qos"] = {"priority": Priority.HIGH, "retries": 3}
        return cls._from_attrs(
            verb, Code._1FC9, payload, addr0=src_id, addr1=dst_id, addr2=addr2, **kwargs
        )

    @classmethod  # constructor for I|1260  # TODO: trap corrupt temps?
    @typechecked
    @validate_api_params()
    def put_dhw_temp(cls, dev_id: _DeviceIdT, temperature: float, **kwargs):
        """Constructor to announce the current temperature of an DHW sensor (1260).

        This is for use by a faked CS92A or similar.
        """

        dhw_idx = f"{kwargs.pop(SZ_DHW_IDX, 0):02X}"  # only 00 or 01 (rare)

        if dev_id[:2] != DEV_TYPE_MAP.DHW:
            raise TypeError(
                f"Faked device {dev_id} has an unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.DHW}:xxxxxx"
            )

        payload = f"{dhw_idx}{temp_to_hex(temperature)}"
        return cls._from_attrs(
            I_, Code._1260, payload, addr0=dev_id, addr2=dev_id, **kwargs
        )

    @classmethod  # constructor for I|0002  # TODO: trap corrupt temps?
    @typechecked
    @validate_api_params()
    def put_outdoor_temp(cls, dev_id: _DeviceIdT, temperature: float, **kwargs):
        """Constructor to announce the current temperature of an outdoor sensor (0002).

        This is for use by a faked HB85 or similar.
        """

        if dev_id[:2] != DEV_TYPE_MAP.OUT:
            raise TypeError(
                f"Faked device {dev_id} has an unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.OUT}:xxxxxx"
            )

        payload = f"00{temp_to_hex(temperature)}01"
        return cls._from_attrs(
            I_, Code._0002, payload, addr0=dev_id, addr2=dev_id, **kwargs
        )

    @classmethod  # constructor for I|30C9  # TODO: trap corrupt temps?
    @typechecked
    @validate_api_params()
    def put_sensor_temp(
        cls, dev_id: _DeviceIdT, temperature: Union[None, float, int], **kwargs
    ):
        """Constructor to announce the current temperature of a thermostat (3C09).

        This is for use by a faked DTS92(E) or similar.
        """
        # .I --- 34:021943 --:------ 34:021943 30C9 003 000C0D

        if dev_id[:2] != DEV_TYPE_MAP.HCW:
            raise TypeError(
                f"Faked device {dev_id} has an unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.HCW}:xxxxxx"
            )

        payload = f"00{temp_to_hex(temperature)}"
        return cls._from_attrs(
            I_, Code._30C9, payload, addr0=dev_id, addr2=dev_id, **kwargs
        )

    @classmethod  # constructor for I|1298
    @typechecked
    @validate_api_params()
    def put_co2_level(
        cls, dev_id: _DeviceIdT, co2_level: Union[None, float, int], /, **kwargs
    ):
        """Constructor to announce the current co2 level of a sensor (1298)."""
        # .I --- 37:039266 --:------ 37:039266 1298 003 000316

        payload = f"00{double_to_hex(co2_level)}"
        return cls._from_attrs(
            I_, Code._1298, payload, addr0=dev_id, addr2=dev_id, **kwargs
        )

    @classmethod  # constructor for I|12A0
    @typechecked
    @validate_api_params()
    def put_indoor_humidity(
        cls, dev_id: _DeviceIdT, indoor_humidity: Union[None, float, int], /, **kwargs
    ):
        """Constructor to announce the current humidity of a sensor (12A0)."""
        # .I --- 37:039266 --:------ 37:039266 1298 003 000316

        payload = f"00{int(indoor_humidity * 100):02X}"  # percent_to_hex
        return cls._from_attrs(
            I_, Code._12A0, payload, addr0=dev_id, addr2=dev_id, **kwargs
        )

    @classmethod  # constructor for I|2E10
    @typechecked
    @validate_api_params()
    def put_presence_detected(
        cls, dev_id: _DeviceIdT, presence_detected: Union[None, bool], /, **kwargs
    ):
        """Constructor to announce the current presence state of a sensor (2E10)."""
        # .I --- ...

        payload = f"00{bool_from_hex(presence_detected)}"
        return cls._from_attrs(
            I_, Code._2E10, payload, addr0=dev_id, addr2=dev_id, **kwargs
        )

    @classmethod  # constructor for internal use only
    @typechecked
    def _puzzle(cls, msg_type: str = Optional[str], message: str = "", **kwargs):

        if msg_type is None:
            msg_type = "12" if message else "10"

        assert msg_type in LOOKUP_PUZZ, "Invalid/deprecated Puzzle type"

        qos = kwargs.get("qos", {})
        qos["priority"] = qos.get("priority", Priority.HIGHEST)
        if msg_type == "10":
            qos["disable_backoff"] = qos.get("disable_backoff", True)
            qos["retries"] = qos.get("retries", 12)
        kwargs["qos"] = qos

        payload = f"00{msg_type}"

        if msg_type != "13":
            payload += f"{int(timestamp() * 1000):012X}"

        if msg_type == "10":
            payload += str_to_hex(f"v{VERSION}")
        elif msg_type == "11":
            payload += str_to_hex(message[:4] + message[5:7] + message[8:])
        else:
            payload += str_to_hex(message)

        return cls.from_attrs(I_, NUL_DEV_ADDR.id, Code._PUZZ, payload[:48], **kwargs)


def _mk_cmd(
    verb: _VerbT, code: _CodeT, payload: _PayloadT, dest_id, **kwargs
) -> Command:
    """A convenience function, to cope with a change to the Command class."""
    return Command.from_attrs(verb, dest_id, code, payload, **kwargs)


# A convenience dict
CODE_API_MAP = {
    f"{I_}|{Code._0002}": Command.put_outdoor_temp,
    f"{RQ}|{Code._0004}": Command.get_zone_name,
    f"{W_}|{Code._0004}": Command.set_zone_name,
    f"{RQ}|{Code._0008}": Command.get_relay_demand,
    f"{RQ}|{Code._000A}": Command.get_zone_config,
    f"{W_}|{Code._000A}": Command.set_zone_config,
    f"{RQ}|{Code._0100}": Command.get_system_language,
    f"{RQ}|{Code._0404}": Command.get_schedule_fragment,
    f"{W_}|{Code._0404}": Command.set_schedule_fragment,
    f"{RQ}|{Code._0418}": Command.get_system_log_entry,
    f"{RQ}|{Code._1030}": Command.get_mix_valve_params,
    f"{W_}|{Code._1030}": Command.set_mix_valve_params,
    f"{RQ}|{Code._10A0}": Command.get_dhw_params,
    f"{W_}|{Code._10A0}": Command.set_dhw_params,
    f"{RQ}|{Code._1100}": Command.get_tpi_params,
    f"{W_}|{Code._1100}": Command.set_tpi_params,
    f"{RQ}|{Code._1260}": Command.get_dhw_temp,
    f"{I_}|{Code._1260}": Command.put_dhw_temp,
    f"{I_}|{Code._1298}": Command.put_co2_level,
    f"{I_}|{Code._12A0}": Command.put_indoor_humidity,
    f"{RQ}|{Code._12B0}": Command.get_zone_window_state,
    f"{RQ}|{Code._1F41}": Command.get_dhw_mode,
    f"{W_}|{Code._1F41}": Command.set_dhw_mode,
    f"{I_}|{Code._22F1}": Command.set_fan_mode,
    f"{W_}|{Code._22F7}": Command.set_bypass_position,
    f"{RQ}|{Code._2349}": Command.get_zone_mode,
    f"{W_}|{Code._2349}": Command.set_zone_mode,
    f"{W_}|{Code._2411}": Command.set_fan_param,
    f"{RQ}|{Code._2E04}": Command.get_system_mode,
    f"{W_}|{Code._2E04}": Command.set_system_mode,
    f"{I_}|{Code._2E10}": Command.put_presence_detected,
    f"{I_}|{Code._30C9}": Command.put_sensor_temp,
    f"{RQ}|{Code._30C9}": Command.get_zone_temp,
    f"{RQ}|{Code._313F}": Command.get_system_time,
    f"{W_}|{Code._313F}": Command.set_system_time,
    f"{RQ}|{Code._3220}": Command.get_opentherm_data,
}  # TODO: RQ|0404 (Zone & DHW)


class FaultLog:  # 0418  # TODO: used a NamedTuple
    """The fault log of a system."""

    def __init__(self, ctl, **kwargs) -> None:
        _LOGGER.debug("FaultLog(ctl=%s).__init__()", ctl)

        self._loop = ctl._gwy._loop

        self.id = ctl.id
        self.ctl = ctl
        # self.tcs = ctl.tcs
        self._gwy = ctl._gwy

        self._faultlog: dict = {}
        self._faultlog_done: None | bool = None

        self._START = 0x00  # max 0x3E
        self._limit = 0x06

    def __repr__(self) -> str:
        return json.dumps(self._faultlog) if self._faultlog_done else "{}"  # TODO:

    def __str__(self) -> str:
        return f"{self.ctl} (fault log)"

    # @staticmethod
    # def _is_valid_operand(other) -> bool:
    #     return hasattr(other, "verb") and hasattr(other, "_pkt")

    # def __eq__(self, other) -> bool:
    #     if not self._is_valid_operand(other):
    #         return NotImplemented
    #     return (self.verb, self._pkt.payload) == (other.verb, self._pkt.payload)

    async def get_faultlog(self, start=0, limit=6, force_refresh=None) -> None | dict:
        """Get the fault log of a system."""
        _LOGGER.debug("FaultLog(%s).get_faultlog()", self)

        if self._gwy.config.disable_sending:
            raise RuntimeError("Sending is disabled")

        self._START = 0 if start is None else start
        self._limit = 6 if limit is None else limit

        self._faultlog = {}  # TODO: = namedtuple("Fault", "timestamp fault_state ...")
        self._faultlog_done = None

        self._rq_log_entry(log_idx=self._START)  # calls loop.create_task()

        time_start = dt.now()
        while not self._faultlog_done:
            await asyncio.sleep(TIMER_SHORT_SLEEP)
            if dt.now() > time_start + TIMER_LONG_TIMEOUT * 2:
                raise ExpiredCallbackError("failed to obtain log entry (long)")

        return self.faultlog

    def _rq_log_entry(self, log_idx=0):
        """Request the next log entry."""
        _LOGGER.debug("FaultLog(%s)._rq_log_entry(%s)", self, log_idx)

        def rq_callback(msg) -> None:
            _LOGGER.debug("FaultLog(%s)._proc_log_entry(%s)", self.id, msg)

            if not msg:
                self._faultlog_done = True
                # raise ExpiredCallbackError("failed to obtain log entry (short)")
                return

            log = dict(msg.payload)
            log_idx = int(log.pop("log_idx", "00"), 16)
            if not log:  # null response (no payload)
                # TODO: delete other callbacks rather than waiting for them to expire
                self._faultlog_done = True
                return

            self._faultlog[log_idx] = log  # TODO: make a named tuple
            if log_idx < self._limit:
                self._rq_log_entry(log_idx + 1)
            else:
                self._faultlog_done = True

        # TODO: (make method) register callback for null response (no payload)
        null_header = "|".join((RP, self.id, Code._0418))
        if null_header not in self._gwy.msg_transport._callbacks:
            self._gwy.msg_transport._callbacks[null_header] = {
                SZ_FUNC: rq_callback,
                SZ_DAEMON: True,
            }

        rq_callback = {SZ_FUNC: rq_callback, SZ_TIMEOUT: 10}
        self._gwy.send_cmd(
            Command.get_system_log_entry(self.ctl.id, log_idx, callback=rq_callback)
        )

    @property
    def faultlog(self) -> None | dict:
        """Return the fault log of a system."""
        if not self._faultlog_done:
            return None

        result = {
            x: {k: v for k, v in y.items() if k[:1] != "_"}
            for x, y in self._faultlog.items()
        }

        return {k: list(v.values()) for k, v in result.items()}

    @property
    def _faultlog_outdated(self) -> bool:
        return bool(self._faultlog_done and len(self._faultlog))
