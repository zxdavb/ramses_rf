#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Construct a command (packet that is to be sent).
"""

import asyncio
import functools
import json
import logging
from datetime import datetime as dt
from datetime import timedelta as td
from typing import Any, Optional, Union

from .address import HGI_DEV_ADDR, NON_DEV_ADDR, NUL_DEV_ADDR, Address, pkt_addrs
from .const import (
    DEV_TYPE_MAP,
    DEVICE_ID_REGEX,
    SYS_MODE_MAP,
    SZ_DAEMON,
    SZ_DHW_IDX,
    SZ_DOMAIN_ID,
    SZ_FUNC,
    SZ_TIMEOUT,
    SZ_ZONE_IDX,
    ZON_MODE_MAP,
    Priority,
    __dev_mode__,
)
from .exceptions import ExpiredCallbackError, InvalidPacketError
from .frame import Frame, pkt_header
from .helpers import dt_now, dtm_to_hex, str_to_hex, temp_to_hex, timestamp
from .opentherm import parity
from .parsers import LOOKUP_PUZZ
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

COMMAND_FORMAT = "{:<2} {} {} {} {} {} {:03d} {}"

TIMER_SHORT_SLEEP = 0.05
TIMER_LONG_TIMEOUT = td(seconds=60)


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def validate_api_params(*, has_zone=None):
    """Decorator to protect the engine from any invalid command constructors.

    Additionally, validate/normalise some command arguments (e.g. 'HW' becomes 0xFA).
    NB: The zone_idx (domain_id) is converted to an integer, but payloads use strings
    such as f"{zone_idx}:02X".
    """

    def _wrapper(fcn, cls, *args, **kwargs):
        _LOGGER.debug(f"Calling: {fcn.__name__}({args}, {kwargs})")
        try:
            return fcn(cls, *args, **kwargs)
        except (
            # ArithmeticError,  # incl. ZeroDivisionError,
            AssertionError,
            # AttributeError,
            # IndexError,
            # LookupError,  # incl. IndexError, KeyError
            # NameError,  # incl. UnboundLocalError
            # RuntimeError,  # incl. RecursionError
            TypeError,
            # ValueError,
        ) as exc:
            _LOGGER.exception(f"{fcn.__name__}{tuple(list(args) + [kwargs])}: {exc}")

    def validate_zone_idx(zone_idx) -> int:
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
            if SZ_DOMAIN_ID in kwargs:
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
    else:  # may raise KeyError
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


def _qos_params(verb, code, qos: dict) -> dict:
    """Class constrcutor wrapped to prevent cyclic reference."""
    from .transport import Qos

    return Qos.verb_code(verb, code, **qos)


@functools.total_ordering
class Command(Frame):
    """The command class."""

    def __init__(
        self,
        verb: str,
        code: str,
        payload: str,
        dest_id: str,
        *,
        from_id: str = HGI_DEV_ADDR.id,
        qos=None,
        cbk=None,
    ) -> None:
        """Create a command.

        Will raise InvalidPacketError (or InvalidAddrSetError) if it is invalid.
        """

        if dest_id == from_id:
            addr_set = " ".join((from_id, NON_DEV_ADDR.id, dest_id))
        else:
            addr_set = " ".join((from_id, dest_id, NON_DEV_ADDR.id))

        frame = " ".join(
            (verb, "---", addr_set, code, f"{int(len(payload) / 2):03d}", payload)
        )

        super().__init__(frame)  # incl. self._validate(addr_set)

        # used by app layer: callback (protocol.py: func, args, daemon, timeout)
        self._cbk = cbk or {}

        # used by pkt layer: qos (transport.py: backoff, priority, retries, timeout)
        self._qos = _qos_params(verb, code, qos or {})

        # used by msg layer: priority (protocol.py,: for which cmd to send next)
        self._priority = self._qos.priority  # TODO: should only be a QoS attr
        self._dtm = dt_now()

        self._rx_header: Optional[str] = None
        self._source_entity = None

        self._validate(strict_checking=False)

    def __repr__(self) -> str:
        """Return an unambiguous string representation of this object."""
        hdr = f' # {self._hdr}{f" ({self._ctx})" if self._ctx else ""}'
        return f"... {self}{hdr}"

    def __str__(self) -> str:
        """Return an brief readable string representation of this object."""
        return super().__repr__()

    def __eq__(self, other) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self._priority, self._dtm) == (other._priority, other._dtm)

    def __lt__(self, other) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self._priority, self._dtm) < (other._priority, other._dtm)

    @staticmethod
    def _is_valid_operand(other) -> bool:
        return hasattr(other, "_priority") and hasattr(other, "_dtm")

    @property
    def tx_header(self) -> str:
        """Return the QoS header of this (request) packet."""

        return self._hdr

    @property
    def rx_header(self) -> Optional[str]:
        """Return the QoS header of a corresponding response packet (if any)."""

        if self.tx_header and self._rx_header is None:
            self._rx_header = pkt_header(self, rx_header=True)
        return self._rx_header

    @classmethod  # constructor for I/22F1
    @validate_api_params()
    def set_fan_rate(
        cls,
        fan_id: str,
        step_idx: int,
        step_max: int,
        *,
        seqn: int = None,
        src_id: str = None,
        idx: str = "00",
        **kwargs,
    ):
        """Constructor to get the fan speed (c.f. parser_22f1).

        There are two types of this packet (with seqn, with src_id):
         - I 018 --:------ --:------ 39:159057 22F1 003 000204 # low
         - I --- 21:039407 28:126495 --:------ 22F1 003 000407
        """

        # Type 1: --:------ --:------ 39:159057
        #  - are cast as a triplet, 0.1s apart?, with a seqn (000-255) and no src_id
        #  - triplet has same seqn, increased monotonically mod 256 after every triplet
        #  - only payloads seen: '(00|63)0[234]04'
        #  I 218 --:------ --:------ 39:159057 22F1 003 000204  # low

        # Type 2: 21:038634 18:126620 --:------ (less common)
        #  - are cast as a triplet, 0.085s apart, without a seqn (---)
        #  - only payloads seen: '000.0[47A]'
        #  I --- 21:038634 18:126620 --:------ 22F1 003 000507

        step_idx &= 0b00001111
        step_max &= 0b00001111
        if step_idx > step_max or step_max < 4:
            raise ValueError(
                f"step_idx ({step_idx}) must not exceed step_max {step_max}"
            )

        payload = f"{idx}{step_idx:02X}{step_max:02X}"
        if seqn and not src_id:
            cmd = cls.packet(
                I_, _22F1, payload, fan_id, addr2=fan_id, seqn=seqn, **kwargs
            )
        elif src_id and not seqn:
            cmd = cls.packet(
                I_, _22F1, payload, fan_id, addr0=src_id, addr1=fan_id, **kwargs
            )
        else:
            raise TypeError("seqn and src_id are mutally exclusive, one is required")

        return cmd

    @classmethod  # constructor for RQ/1F41
    @validate_api_params()
    def get_dhw_mode(cls, ctl_id: str, **kwargs):
        """Constructor to get the mode of the DHW (c.f. parser_1f41)."""

        dhw_idx = kwargs.pop(SZ_DHW_IDX, "00")  # only 00 or 01 (rare)
        return cls(RQ, _1F41, dhw_idx, ctl_id, **kwargs)

    @classmethod  # constructor for W_/1F41
    @validate_api_params()
    def set_dhw_mode(
        cls,
        ctl_id: str,
        *,
        mode=None,
        active: bool = None,
        until=None,
        duration: int = None,
        **kwargs,
    ):
        """Constructor to set/reset the mode of the DHW (c.f. parser_1f41)."""

        dhw_idx = kwargs.pop(SZ_DHW_IDX, "00")  # only 00 or 01 (rare)

        mode = _normalise_mode(
            int(mode) if isinstance(mode, bool) else mode, active, until, duration
        )

        if active is not None and not isinstance(active, (bool, int)):
            raise TypeError(f"Invalid args: active={active}, but must be an bool")

        until, duration = _normalise_until(mode, active, until, duration)

        payload = "".join(
            (
                dhw_idx,
                "01" if bool(active) else "00",
                mode,
                "FFFFFF" if duration is None else f"{duration:06X}",
                "" if until is None else dtm_to_hex(until),
            )
        )

        return cls(W_, _1F41, payload, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/10A0
    @validate_api_params()
    def get_dhw_params(cls, ctl_id: str, **kwargs):
        """Constructor to get the params of the DHW (c.f. parser_10a0)."""

        dhw_idx = kwargs.pop(SZ_DHW_IDX, "00")  # only 00 or 01 (rare)
        return cls(RQ, _10A0, dhw_idx, ctl_id, **kwargs)

    @classmethod  # constructor for W_/10A0
    @validate_api_params()
    def set_dhw_params(
        cls,
        ctl_id: str,
        *,
        setpoint: float = 50.0,
        overrun: int = 5,
        differential: int = 1,
        **kwargs,
    ):
        """Constructor to set the params of the DHW (c.f. parser_10a0)."""
        # Defaults for newer evohome colour:
        # Defaults for older evohome colour: ?? (30-85) C, ? (0-10) min, ? (1-10) C
        # Defaults for evohome monochrome:

        # 14:34:26.734 022  W --- 18:013393 01:145038 --:------ 10A0 006 000F6E050064
        # 14:34:26.751 073  I --- 01:145038 --:------ 01:145038 10A0 006 000F6E0003E8
        # 14:34:26.764 074  I --- 01:145038 18:013393 --:------ 10A0 006 000F6E0003E8

        dhw_idx = kwargs.pop(SZ_DHW_IDX, "00")  # only 00 or 01 (rare)

        setpoint = 50.0 if setpoint is None else setpoint
        overrun = 5 if overrun is None else overrun
        differential = 1.0 if differential is None else differential

        if not (30.0 <= setpoint <= 85.0):
            raise ValueError(f"Out of range, setpoint: {setpoint}")
        if not (0 <= overrun <= 10):
            raise ValueError(f"Out of range, overrun: {overrun}")
        if not (1 <= differential <= 10):
            raise ValueError(f"Out of range, differential: {differential}")
        dhw_idx = kwargs.pop(SZ_DHW_IDX, "00")  # can have 2 DHWs, but not ever seen

        payload = (
            f"{dhw_idx}{temp_to_hex(setpoint)}{overrun:02X}{temp_to_hex(differential)}"
        )

        return cls(W_, _10A0, payload, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/1260
    @validate_api_params()
    def get_dhw_temp(cls, ctl_id: str, **kwargs):
        """Constructor to get the temperature of the DHW sensor (c.f. parser_10a0)."""

        dhw_idx = kwargs.pop(SZ_DHW_IDX, "00")  # only 00 or 01 (rare)
        return cls(RQ, _1260, dhw_idx, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/1030
    @validate_api_params(has_zone=True)
    def get_mix_valve_params(cls, ctl_id: str, zone_idx: Union[int, str], **kwargs):
        """Constructor to get the mix valve params of a zone (c.f. parser_1030)."""

        return cls(RQ, _1030, f"{zone_idx:02X}00", ctl_id, **kwargs)  # TODO: needs 00?

    @classmethod  # constructor for W/1030
    @validate_api_params(has_zone=True)
    def set_mix_valve_params(
        cls,
        ctl_id: str,
        zone_idx: Union[int, str],
        *,
        max_flow_setpoint=55,
        min_flow_setpoint=15,
        valve_run_time=150,
        pump_run_time=15,
        **kwargs,
    ):
        """Constructor to set the mix valve params of a zone (c.f. parser_1030)."""

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
                f"CC01{1:02X}",
            )
        )

        return cls(W_, _1030, payload, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/3220
    @validate_api_params()
    def get_opentherm_data(cls, dev_id: str, msg_id: Union[int, str], **kwargs):
        """Constructor to get (Read-Data) opentherm msg value (c.f. parser_3220)."""

        msg_id = msg_id if isinstance(msg_id, int) else int(msg_id, 16)
        payload = f"0080{msg_id:02X}0000" if parity(msg_id) else f"0000{msg_id:02X}0000"
        return cls(RQ, _3220, payload, dev_id, **kwargs)

    @classmethod  # constructor for RQ/0008
    @validate_api_params()  # has_zone=Optional
    def get_relay_demand(cls, dev_id: str, zone_idx: Union[int, str] = None, **kwargs):
        """Constructor to get the demand of a relay/zone (c.f. parser_0008)."""

        payload = "00" if zone_idx is None else f"{zone_idx:02X}"
        return cls(RQ, _0008, payload, dev_id, **kwargs)

    @classmethod  # constructor for RQ/0006
    @validate_api_params()
    def get_schedule_version(cls, ctl_id: str, **kwargs):
        """Constructor to get the current version (change counter) of the schedules.

        This number is increased whenever any zone's schedule is changed (incl. the DHW
        zone), and is used to avoid the relatively large expense of downloading a
        schedule, only to see that it hasn't changed.
        """

        return cls(RQ, _0006, "00", ctl_id, **kwargs)

    @classmethod  # constructor for RQ/0404
    @validate_api_params(has_zone=True)
    def get_schedule_fragment(
        cls,
        ctl_id: str,
        zone_idx: Union[int, str],
        frag_num: int,
        frag_cnt: int,
        **kwargs,
    ):
        """Constructor to get a schedule fragment (c.f. parser_0404).

        Usually a zone, but will be the DHW schedule if zone_idx == 0xFA, 'FA', or 'HW'.
        """

        # TODO: check the following rules
        if frag_num == 0:
            raise ValueError(f"frag_num={frag_num}, but it is 1-indexed")
        elif frag_num == 1 and frag_cnt != 0:
            raise ValueError(f"frag_cnt={frag_cnt}, but must be 0 when frag_num=1")
        elif frag_num > frag_cnt and frag_cnt != 0:
            raise ValueError(f"frag_num={frag_num}, but must be <= frag_cnt={frag_cnt}")

        header = "00230008" if zone_idx == 0xFA else f"{zone_idx:02X}200008"

        payload = f"{header}00{frag_num:02X}{frag_cnt:02X}"
        return cls(RQ, _0404, payload, ctl_id, **kwargs)

    @classmethod  # constructor for W/0404
    @validate_api_params(has_zone=True)
    def set_schedule_fragment(
        cls,
        ctl_id: str,
        zone_idx: Union[int, str],
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
        return cls(W_, _0404, payload, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/0100
    @validate_api_params()
    def get_system_language(cls, ctl_id: str, **kwargs):
        """Constructor to get the language of a system (c.f. parser_0100)."""

        return cls(RQ, _0100, "00", ctl_id, **kwargs)

    @classmethod  # constructor for RQ/0418
    @validate_api_params()
    def get_system_log_entry(cls, ctl_id: str, log_idx: Union[int, str], **kwargs):
        """Constructor to get a log entry from a system (c.f. parser_0418)."""

        log_idx = log_idx if isinstance(log_idx, int) else int(log_idx, 16)
        return cls(RQ, _0418, f"{log_idx:06X}", ctl_id, **kwargs)

    @classmethod  # constructor for RQ/2E04
    @validate_api_params()
    def get_system_mode(cls, ctl_id: str, **kwargs):
        """Constructor to get the mode of a system (c.f. parser_2e04)."""

        return cls(RQ, _2E04, FF, ctl_id, **kwargs)

    @classmethod  # constructor for W/2E04
    @validate_api_params()
    def set_system_mode(cls, ctl_id: str, system_mode, *, until=None, **kwargs):
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

        return cls(W_, _2E04, payload, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/313F
    @validate_api_params()
    def get_system_time(cls, ctl_id: str, **kwargs):
        """Constructor to get the datetime of a system (c.f. parser_313f)."""

        return cls(RQ, _313F, "00", ctl_id, **kwargs)

    @classmethod  # constructor for W/313F
    @validate_api_params()
    def set_system_time(cls, ctl_id: str, datetime: dt, is_dst: bool = False, **kwargs):
        """Constructor to set the datetime of a system (c.f. parser_313f)."""
        #  W --- 30:185469 01:037519 --:------ 313F 009 0060003A0C1B0107E5

        datetime = dtm_to_hex(datetime, is_dst=is_dst, incl_seconds=True)
        return cls(W_, _313F, f"0060{datetime}", ctl_id, **kwargs)

    @classmethod  # constructor for RQ/1100
    @validate_api_params()
    def get_tpi_params(cls, dev_id: str, *, domain_id=None, **kwargs):
        """Constructor to get the TPI params of a system (c.f. parser_1100)."""

        if domain_id is None:
            domain_id = "00" if dev_id[:2] == DEV_TYPE_MAP.BDR else FC
        return cls(RQ, _1100, domain_id, dev_id, **kwargs)

    @classmethod  # constructor for W/1100
    @validate_api_params()
    def set_tpi_params(
        cls,
        ctl_id: str,
        domain_id: Union[str, None],
        *,
        cycle_rate: int = 3,  # TODO: check
        min_on_time: int = 5,  # TODO: check
        min_off_time: int = 5,  # TODO: check
        proportional_band_width: Union[float, None] = None,  # TODO: check
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

        return cls(W_, _1100, payload, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/000A
    @validate_api_params(has_zone=True)
    def get_zone_config(cls, ctl_id: str, zone_idx: Union[int, str], **kwargs):
        """Constructor to get the config of a zone (c.f. parser_000a)."""

        return cls(RQ, _000A, f"{zone_idx:02X}00", ctl_id, **kwargs)  # TODO: needs 00?

    @classmethod  # constructor for W/000A
    @validate_api_params(has_zone=True)
    def set_zone_config(
        cls,
        ctl_id: str,
        zone_idx: Union[int, str],
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

        return cls(W_, _000A, payload, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/2349
    @validate_api_params(has_zone=True)
    def get_zone_mode(cls, ctl_id: str, zone_idx: Union[int, str], **kwargs):
        """Constructor to get the mode of a zone (c.f. parser_2349)."""

        return cls(RQ, _2349, f"{zone_idx:02X}00", ctl_id, **kwargs)  # TODO: needs 00?

    @classmethod  # constructor for W/2349
    @validate_api_params(has_zone=True)
    def set_zone_mode(
        cls,
        ctl_id: str,
        zone_idx: Union[int, str],
        *,
        mode: str = None,
        setpoint: float = None,
        until: dt = None,
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
        #  W --- 18:013393 01:145038 --:------ 2349 013 0004E201FFFFFF330B1A0607E4
        #  W --- 22:017139 01:140959 --:------ 2349 007 0801F400FFFFFF

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

        return cls(W_, _2349, payload, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/0004
    @validate_api_params(has_zone=True)
    def get_zone_name(cls, ctl_id: str, zone_idx: Union[int, str], **kwargs):
        """Constructor to get the name of a zone (c.f. parser_0004)."""

        return cls(RQ, _0004, f"{zone_idx:02X}00", ctl_id, **kwargs)  # TODO: needs 00?

    @classmethod  # constructor for W/0004
    @validate_api_params(has_zone=True)
    def set_zone_name(cls, ctl_id: str, zone_idx: Union[int, str], name: str, **kwargs):
        """Constructor to set the name of a zone (c.f. parser_0004)."""

        payload = f"{zone_idx:02X}00{str_to_hex(name)[:40]:0<40}"
        return cls(W_, _0004, payload, ctl_id, **kwargs)

    @classmethod  # constructor for W/2309
    @validate_api_params(has_zone=True)
    def set_zone_setpoint(
        cls, ctl_id: str, zone_idx: Union[int, str], setpoint: float, **kwargs
    ):
        """Constructor to set the setpoint of a zone (c.f. parser_2309)."""
        #  W --- 34:092243 01:145038 --:------ 2309 003 0107D0

        payload = f"{zone_idx:02X}{temp_to_hex(setpoint)}"
        return cls(W_, _2309, payload, ctl_id, **kwargs)

    @classmethod  # constructor for RQ/30C9
    @validate_api_params(has_zone=True)
    def get_zone_temp(cls, ctl_id: str, zone_idx: Union[int, str], **kwargs):
        """Constructor to get the current temperature of a zone (c.f. parser_30c9)."""

        return cls(RQ, _30C9, f"{zone_idx:02X}", ctl_id, **kwargs)

    @classmethod  # constructor for RQ/12B0
    @validate_api_params(has_zone=True)
    def get_zone_window_state(cls, ctl_id: str, zone_idx: Union[int, str], **kwargs):
        """Constructor to get the openwindow state of a zone (c.f. parser_12b0)."""

        return cls(RQ, _12B0, f"{zone_idx:02X}", ctl_id, **kwargs)

    @classmethod  # constructor for RP/3EF1 (I/3EF1?)  # TODO: trap corrupt values?
    @validate_api_params()
    def put_actuator_cycle(
        cls,
        src_id: str,
        dst_id: str,
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
                f"Faked device {src_id} has unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.BDR}:xxxxxx"
            )

        payload = "00"
        payload += f"{cycle_countdown:04X}" if cycle_countdown is not None else "7FFF"
        payload += f"{actuator_countdown:04X}"
        payload += f"{int(modulation_level * 200):02X}FF"
        return cls.packet(RP, _3EF1, payload, addr0=src_id, addr1=dst_id, **kwargs)

    @classmethod  # constructor for I/3EF0  # TODO: trap corrupt states?
    @validate_api_params()
    def put_actuator_state(cls, dev_id: str, modulation_level: float, **kwargs):
        """Constructor to announce the modulation level of an actuator (3EF0).

        This is for use by a faked BDR91A or similar.
        """
        #  I --- 13:049798 --:------ 13:049798 3EF0 003 00C8FF
        #  I --- 13:106039 --:------ 13:106039 3EF0 003 0000FF

        if dev_id[:2] != DEV_TYPE_MAP.BDR:
            raise TypeError(
                f"Faked device {dev_id} has unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.BDR}:xxxxxx"
            )

        payload = (
            "007FFF"
            if modulation_level is None
            else f"00{int(modulation_level * 200):02X}FF"
        )
        return cls.packet(I_, _3EF0, payload, addr0=dev_id, addr2=dev_id, **kwargs)

    @classmethod  # constructor for 1FC9 (rf_bind) 3-way handshake
    def put_bind(cls, verb, codes, src_id, *, idx="00", dst_id=None, **kwargs):
        """Constructor for RF bind commands (1FC9), for use by faked devices."""

        #  I --- 34:021943 --:------ 34:021943 1FC9 024 00-2309-8855B7 00-1FC9-8855B7
        #  W --- 01:145038 34:021943 --:------ 1FC9 006 00-2309-06368E
        #  I --- 34:021943 01:145038 --:------ 1FC9 006 00-2309-8855B7

        hex_id = Address.convert_to_hex(src_id)
        codes = (list(codes) if isinstance(codes, tuple) else [codes]) + [_1FC9]

        if dst_id is None and verb == I_:
            payload = "".join(f"{idx}{c}{hex_id}" for c in codes)
            addr2 = src_id

        elif dst_id and verb in (I_, W_):
            payload = f"00{codes[0]}{hex_id}"
            addr2 = NON_DEV_ADDR.id

        else:
            raise ValueError("Invalid parameters")

        kwargs.update({"priority": Priority.HIGH, "retries": 3})
        return cls.packet(
            verb, _1FC9, payload, addr0=src_id, addr1=dst_id, addr2=addr2, **kwargs
        )

    @classmethod  # constructor for I/1260  # TODO: trap corrupt temps?
    @validate_api_params()
    def put_dhw_temp(cls, dev_id: str, temperature: float, **kwargs):
        """Constructor to announce the current temperature of an DHW sensor (1260).

        This is for use by a faked CS92A or similar.
        """

        dhw_idx = kwargs.pop(SZ_DHW_IDX, "00")  # only 00 or 01 (rare)

        if dev_id[:2] != DEV_TYPE_MAP.DHW:
            raise TypeError(
                f"Faked device {dev_id} has unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.DHW}:xxxxxx"
            )

        payload = f"{dhw_idx}{temp_to_hex(temperature)}"
        return cls.packet(I_, _1260, payload, addr0=dev_id, addr2=dev_id, **kwargs)

    @classmethod  # constructor for I/0002  # TODO: trap corrupt temps?
    @validate_api_params()
    def put_outdoor_temp(cls, dev_id: str, temperature: float, **kwargs):
        """Constructor to announce the current temperature of an outdoor sensor (0002).

        This is for use by a faked HB85 or similar.
        """

        if dev_id[:2] != DEV_TYPE_MAP.OUT:
            raise TypeError(
                f"Faked device {dev_id} has unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.OUT}:xxxxxx"
            )

        payload = f"00{temp_to_hex(temperature)}01"
        return cls.packet(I_, _0002, payload, addr0=dev_id, addr2=dev_id, **kwargs)

    @classmethod  # constructor for I/30C9  # TODO: trap corrupt temps?
    @validate_api_params()
    def put_sensor_temp(cls, dev_id: str, temperature: float, **kwargs):
        """Constructor to announce the current temperature of a thermostat (3C09).

        This is for use by a faked DTS92(E) or similar.
        """
        #  I --- 34:021943 --:------ 34:021943 30C9 003 000C0D

        if dev_id[:2] != DEV_TYPE_MAP.HCW:
            raise TypeError(
                f"Faked device {dev_id} has unsupported device type: "
                f"device_id should be like {DEV_TYPE_MAP.HCW}:xxxxxx"
            )

        payload = f"00{temp_to_hex(temperature)}"
        return cls.packet(I_, _30C9, payload, addr0=dev_id, addr2=dev_id, **kwargs)

    @classmethod  # constructor for internal use only
    def _puzzle(cls, msg_type=None, message="", **kwargs):

        if msg_type is None:
            msg_type = "12" if message else "10"

        assert msg_type in LOOKUP_PUZZ, "Invalid/deprecated Puzzle type"

        kwargs["priority"] = kwargs.pop("priority", Priority.HIGHEST)
        if msg_type == "10":
            kwargs["disable_backoff"] = kwargs.pop("disable_backoff", True)
            kwargs["retries"] = kwargs.pop("retries", 24)

        payload = f"00{msg_type}"

        if msg_type != "13":
            payload += f"{int(timestamp() * 1000):012X}"

        if msg_type == "10":
            payload += str_to_hex(f"v{VERSION}")
        elif msg_type == "11":
            payload += str_to_hex(message[:4] + message[5:7] + message[8:])
        else:
            payload += str_to_hex(message)

        return cls(I_, _PUZZ, payload[:48], NUL_DEV_ADDR.id, **kwargs)

    @classmethod  # generic constructor
    def packet(
        cls,
        verb,
        code,
        payload,
        *,
        addr0=None,
        addr1=None,
        addr2=None,
        seqn=None,
        **kwargs,
    ):
        """Construct commands with fewer assumptions/checks than the main constructor.

        For example:
            I 056 --:------ --:------ 02:123456 99FD 003 000404
        """

        verb = I_ if verb == "I" else W_ if verb == "W" else verb

        addr0 = addr0 or NON_DEV_ADDR.id
        addr1 = addr1 or NON_DEV_ADDR.id
        addr2 = addr2 or NON_DEV_ADDR.id

        src, dst, *_ = pkt_addrs(" ".join((addr0, addr1, addr2)))

        cmd = cls(verb, code, payload, dst.id, from_id=src.id, **kwargs)

        if seqn in ("", "-", "--", "---"):
            cmd._seqn = "---"
        elif seqn is not None:
            cmd._seqn = f"{int(seqn):03d}"

        cmd._frame = COMMAND_FORMAT.format(
            cmd.verb,
            cmd.seqn,
            *(a.id for a in cmd._addrs),
            cmd.code,
            cmd.len,
            cmd.payload,
        )

        cmd._validate()

        return cmd

    @classmethod  # constructor for internal use only
    def from_str(cls, cmd_str: str, **kwargs):
        """Create a command from a string.

        Examples include (whitespace for readability):
            'RQ     01:123456               1F09 00'
            'RQ     01:123456     13:123456 3EF0 00'
            'RQ     07:045960     01:054173 10A0 00137400031C'
            ' W 123 30:045960 -:- 32:054173 22F1 001374'
        """

        cmd = cmd_str.upper().split()
        if len(cmd) < 4:
            raise ValueError(f"Command is invalid: '{cmd_str}'")

        verb = cmd.pop(0)
        seqn = "---" if DEVICE_ID_REGEX.ANY.match(cmd[0]) else cmd.pop(0)
        payload = cmd.pop()[:48]
        code = cmd.pop()

        if not 0 < len(cmd) < 4:
            raise ValueError(f"Command is invalid: '{cmd_str}'")
        elif len(cmd) == 1:
            addrs = (HGI_DEV_ADDR.id, cmd[0], NON_DEV_ADDR.id)
        elif len(cmd) == 3:
            addrs = (cmd[0], cmd[1], cmd[2])
        elif cmd[0] == cmd[1]:
            addrs = (cmd[0], NON_DEV_ADDR.id, cmd[1])
        else:
            addrs = (cmd[0], cmd[1], NON_DEV_ADDR.id)

        addrs = {f"addr{k}": v for k, v in enumerate(addrs)}

        return cls.packet(verb, code, payload, **addrs, seqn=seqn, **kwargs)

    @classmethod  # constructor for internal use only
    def from_frame(cls, frame: str, **kwargs):
        """Create a command from a frame (a raw string) (no RSSI)."""

        raw = frame.split()
        cmd = cls.packet(
            raw[0], raw[5], raw[7], addr0=raw[2], addr1=raw[3], addr2=raw[4], **kwargs
        )  # may: raise InvalidPacketError

        try:
            raw[1] == "---" or int(raw[1])
        except ValueError:
            raise InvalidPacketError(f"invalid seqn: {raw[1]}")

        if raw[6] != cmd._len:
            raise InvalidPacketError(f"invalid length: {cmd[6]}")

        return cmd


# A convenience dict
CODE_API_MAP = {
    f"{I_}/{_0002}": Command.put_outdoor_temp,
    f"{RQ}/{_0004}": Command.get_zone_name,
    f"{W_}/{_0004}": Command.set_zone_name,
    f"{RQ}/{_0008}": Command.get_relay_demand,
    f"{RQ}/{_000A}": Command.get_zone_config,
    f"{W_}/{_000A}": Command.set_zone_config,
    f"{RQ}/{_0100}": Command.get_system_language,
    f"{RQ}/{_0404}": Command.get_schedule_fragment,
    f"{W_}/{_0404}": Command.set_schedule_fragment,
    f"{RQ}/{_0418}": Command.get_system_log_entry,
    f"{RQ}/{_1030}": Command.get_mix_valve_params,
    f"{W_}/{_1030}": Command.set_mix_valve_params,
    f"{RQ}/{_10A0}": Command.get_dhw_params,
    f"{W_}/{_10A0}": Command.set_dhw_params,
    f"{RQ}/{_1100}": Command.get_tpi_params,
    f"{W_}/{_1100}": Command.set_tpi_params,
    f"{RQ}/{_1260}": Command.get_dhw_temp,
    f"{I_}/{_1260}": Command.put_dhw_temp,
    f"{RQ}/{_12B0}": Command.get_zone_window_state,
    f"{RQ}/{_1F41}": Command.get_dhw_mode,
    f"{W_}/{_1F41}": Command.set_dhw_mode,
    f"{RQ}/{_2349}": Command.get_zone_mode,
    f"{W_}/{_2349}": Command.set_zone_mode,
    f"{RQ}/{_2E04}": Command.get_system_mode,
    f"{W_}/{_2E04}": Command.set_system_mode,
    f"{I_}/{_30C9}": Command.put_sensor_temp,
    f"{RQ}/{_30C9}": Command.get_zone_temp,
    f"{RQ}/{_313F}": Command.get_system_time,
    f"{W_}/{_313F}": Command.set_system_time,
    f"{RQ}/{_3220}": Command.get_opentherm_data,
}  # TODO: RQ/0404 (Zone & DHW)


class FaultLog:  # 0418  # TODO: used a NamedTuple
    """The fault log of a system."""

    def __init__(self, ctl, **kwargs) -> None:
        _LOGGER.debug("FaultLog(ctl=%s).__init__()", ctl)

        self._loop = ctl._gwy._loop

        self.id = ctl.id
        self.ctl = ctl
        # self.tcs = ctl.tcs
        self._gwy = ctl._gwy

        self._faultlog = None
        self._faultlog_done = None

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

    async def get_faultlog(
        self, start=0, limit=6, force_refresh=None
    ) -> Optional[dict]:
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
        null_header = "|".join((RP, self.id, _0418))
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
    def faultlog(self) -> Optional[dict]:
        """Return the fault log of a system."""
        if not self._faultlog_done:
            return

        result = {
            x: {k: v for k, v in y.items() if k[:1] != "_"}
            for x, y in self._faultlog.items()
        }

        return {k: list(v.values()) for k, v in result.items()}

    @property
    def _faultlog_outdated(self) -> bool:
        return self._faultlog_done and len(self._faultlog_done) and self._faultlog_done
