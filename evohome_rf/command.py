#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""Evohome RF - a RAMSES-II protocol decoder & analyser.

Construct a command (packet that is to be sent).
"""

import asyncio
import json
import logging
import struct
import zlib

# from collections import namedtuple
from datetime import datetime as dt
from datetime import timedelta as td
from functools import total_ordering
from types import SimpleNamespace
from typing import Optional

from .const import (
    CODE_SCHEMA,
    COMMAND_REGEX,
    HGI_DEV_ADDR,
    NON_DEV_ADDR,
    NUL_DEV_ADDR,
    SYSTEM_MODE_LOOKUP,
    SYSTEM_MODE_MAP,
    ZONE_MODE_LOOKUP,
    ZONE_MODE_MAP,
    ZoneMode,
    __dev_mode__,
)
from .exceptions import ExpiredCallbackError
from .helpers import (
    dt_now,
    dtm_to_hex,
    dts_to_hex,
    extract_addrs,
    str_to_hex,
    temp_to_hex,
)
from .opentherm import parity

# from .ramses import RAMSES_CODES

COMMAND_FORMAT = "{:<2} {} {} {} {} {} {:03d} {}"

DAY_OF_WEEK = "day_of_week"
HEAT_SETPOINT = "heat_setpoint"
SWITCHPOINTS = "switchpoints"
TIME_OF_DAY = "time_of_day"

SCHEDULE = "schedule"
ZONE_IDX = "zone_idx"

TIMER_SHORT_SLEEP = 0.05
TIMER_LONG_TIMEOUT = td(seconds=60)

FIVE_MINS = td(minutes=5)

CALLBACK = "callback"
DEAMON = "daemon"
EXPIRES = "expires"
FUNC = "func"
ARGS = "args"

QOS = "qos"
DISABLE_BACKOFF = "disable_backoff"
PRIORITY = "priority"
RETRIES = "retries"
TIMEOUT = "timeout"
QOS_KEYS = (DISABLE_BACKOFF, PRIORITY, RETRIES, TIMEOUT)

FRAGMENT = "fragment"
FRAG_INDEX = "frag_index"
FRAG_TOTAL = "frag_total"
MSG = "msg"

I_, RQ, RP, W_ = " I", "RQ", "RP", " W"

Priority = SimpleNamespace(LOWEST=8, LOW=6, DEFAULT=4, HIGH=2, HIGHEST=0)

DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


def _pkt_header(pkt: str, rx_header=None) -> Optional[str]:
    """Return the QoS header of a packet."""

    verb = pkt[4:6]
    if rx_header:
        verb = RP if verb == RQ else I_  # RQ/RP, or W/I
    code = pkt[41:45]
    src, dst, _ = extract_addrs(pkt[11:40])
    addr = dst if src.type == "18" else src
    payload = pkt[50:]

    header = "|".join((verb, addr.id, code))

    if code in ("0001", "7FFF") and rx_header:  # code has no no RQ, no W
        return

    if code in ("0005", "000C"):  # zone_idx, device_class
        return "|".join((header, payload[:4]))

    if code == "0404":  # zone_schedule: zone_idx, frag_idx
        return "|".join((header, payload[:2] + payload[10:12]))

    if code == "0418":  # fault_log: log_idx
        if payload == CODE_SCHEMA["0418"]["null_rp"]:
            return header
        return "|".join((header, payload[4:6]))

    if code in ("1F09", "1FC9", "2E04"):  # have no domain_id
        return header

    return "|".join((header, payload[:2]))  # assume has a domain_id


@total_ordering
class Command:
    """The command class."""

    def __init__(self, verb, dest_id, code, payload, **kwargs) -> None:
        """Initialise the class."""

        assert QOS not in kwargs, "FIXME"

        self.verb = f"{verb:>2}"[:2]
        assert self.verb in (I_, RQ, RP, W_), f"invalid verb: '{self.verb}'"

        self.seqn = "---"
        self.from_addr, self.dest_addr, self.addrs = extract_addrs(
            f"{kwargs.get('from_id', HGI_DEV_ADDR.id)} {dest_id} {NON_DEV_ADDR.id}"
        )
        self.code = code
        self.payload = payload

        self._is_valid = None
        if not self.is_valid:
            raise ValueError(f"Invalid parameter values for command: {self}")

        # callback used by app layer (protocol.py)
        self.callback = kwargs.pop(CALLBACK, {})  # func, args, daemon, timeout

        # qos used by pkt layer (transport.py)
        self.qos = self._qos(**kwargs)  # disable_backoff, priority, retries, timeout

        # priority used by msg layer for next cmd to send (protocol.py)
        self._priority = self.qos.pop(PRIORITY, Priority.DEFAULT)
        self._priority_dtm = dt_now()

        self._rx_header = None
        self._tx_header = None

    def __str__(self) -> str:
        """Return a brief readable string representation of this object."""

        return repr(self)  # # TODO: switch to: return self.tx_header

    def __repr__(self) -> str:
        """Return a full string representation of this object."""

        return COMMAND_FORMAT.format(
            self.verb,
            self.seqn,
            self.addrs[0].id,
            self.addrs[1].id,
            self.addrs[2].id,
            self.code,
            int(len(self.payload) / 2),
            self.payload,
        )

    def _qos(self, **kwargs) -> dict:
        """Return the default QoS params of this (request) packet."""

        qos = {
            k: v for k, v in kwargs.items() if k in QOS_KEYS
        }  # the defaults for these are in packet.py

        if self.code in ("0016", "1F09") and self.verb == RQ:
            qos[PRIORITY] = qos.get(PRIORITY, Priority.HIGH)
            qos[RETRIES] = qos.get(RETRIES, 5)

        elif self.code == "0404" and self.verb in (RQ, W_):
            qos[PRIORITY] = qos.get(PRIORITY, Priority.HIGH)
            qos[TIMEOUT] = qos.get(TIMEOUT, td(seconds=0.30))

        elif self.code == "0418" and self.verb == RQ:
            qos[PRIORITY] = qos.get(PRIORITY, Priority.LOW)
            qos[RETRIES] = qos.get(RETRIES, 3)

        return qos

    @property
    def tx_header(self) -> str:
        """Return the QoS header of this (request) packet."""
        if self._tx_header is None:
            self._tx_header = _pkt_header(f"... {self}")
        return self._tx_header

    @property
    def rx_header(self) -> Optional[str]:
        """Return the QoS header of a corresponding response packet (if any)."""
        if self.tx_header and self._rx_header is None:
            self._rx_header = _pkt_header(f"... {self}", rx_header=True)
        return self._rx_header

    # @property
    # def null_header(self) -> Optional[str]:
    #     """Return the QoS header of a null response packet (if any)."""
    #     if self.tx_header and self._rx_header is None:
    #         self._rx_header = _pkt_header(f"... {self}", null_header=True)
    #     return self._rx_header

    @property
    def is_valid(self) -> Optional[bool]:
        """Return True if a valid command, otherwise return False/None."""

        if self._is_valid is not None:
            return self._is_valid

        # assert self.code in [k for k, v in RAMSES_CODES.items() if v.get(self.verb)]

        if not COMMAND_REGEX.match(str(self)) or 2 > len(self.payload) > 96:
            self._is_valid = False
        else:
            self._is_valid = True

        if not self._is_valid:
            _LOGGER.debug("Command has an invalid structure: %s", self)

        return self._is_valid

    @staticmethod
    def _is_valid_operand(other) -> bool:
        return hasattr(other, "_priority") and hasattr(other, "_priority_dtm")

    def __eq__(self, other) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self._priority, self._priority_dtm) == (
            other._priority,
            other._priority_dtm,
        )

    def __lt__(self, other) -> bool:
        if not self._is_valid_operand(other):
            return NotImplemented
        return (self._priority, self._priority_dtm) < (
            other._priority,
            other._priority_dtm,
        )

    @classmethod  # constructor for 1F41  # TODO
    def get_dhw_mode(cls, ctl_id, **kwargs):
        """Constructor to get the mode of the DHW (c.f. parser_1f41)."""
        return cls(RQ, ctl_id, "1F41", "00", **kwargs)

    @classmethod  # constructor for 1F41  # TODO
    def set_dhw_mode(cls, ctl_id, mode=None, active: bool = None, until=None, **kwargs):
        """Constructor to set/reset the mode of the DHW (c.f. parser_1f41)."""

        if mode is None and active is None:
            raise ValueError("Invalid args: Both mode and active cant be None")

        if mode is None:  # and active is not None: TODO: use: advanced_override?
            mode = ZoneMode.TEMPORARY if until else ZoneMode.PERMANENT
        elif isinstance(mode, int):
            mode = f"{mode:02X}"
        if mode in ZONE_MODE_MAP:
            mode = ZONE_MODE_MAP[mode]
        elif mode not in ZONE_MODE_LOOKUP:
            raise TypeError(f"Invalid args: Unknown mode: {mode}")

        if active is None and mode != ZoneMode.SCHEDULE:
            raise ValueError(f"Invalid args: For {mode}, active cant be None")
        elif active is not None and not isinstance(active, (bool, int)):
            raise ValueError(f"Invalid args: active={active}, should be bool")

        if until is None and mode == ZoneMode.TEMPORARY:
            mode = ZoneMode.ADVANCED  # until = dt.now() + td(hour=1)
        elif until is not None and mode in (ZoneMode.SCHEDULE, ZoneMode.PERMANENT):
            raise ValueError(f"Invalid args: For {mode}, until should be None")

        assert mode in ZONE_MODE_LOOKUP, mode

        payload = "00"
        payload += "01" if bool(active) else "00"
        payload += ZONE_MODE_LOOKUP[mode] + "FFFFFF"
        payload += "" if until is None else dtm_to_hex(until)

        return cls(W_, ctl_id, "1F41", payload, **kwargs)

    @classmethod  # constructor for 10A0  # TODO
    def set_dhw_params(
        cls,
        ctl_id,
        setpoint: float = 50.0,
        overrun: int = 5,
        differential: int = 1,
        **kwargs,
    ):
        """Constructor to set the params of the DHW (c.f. parser_10a0)."""

        # 14:34:26.734 022  W --- 18:013393 01:145038 --:------ 10A0 006 000F6E050064
        # 14:34:26.751 073  I --- 01:145038 --:------ 01:145038 10A0 006 000F6E0003E8
        # 14:34:26.764 074  I --- 01:145038 18:013393 --:------ 10A0 006 000F6E0003E8

        setpoint = 50.0 if setpoint is None else setpoint
        overrun = 5 if overrun is None else overrun
        differential = 1.0 if differential is None else differential

        assert 30.0 <= setpoint <= 85.0, setpoint
        assert 0 <= overrun <= 10, overrun
        assert 1 <= differential <= 10, differential

        payload = f"00{temp_to_hex(setpoint)}{overrun:02X}{temp_to_hex(differential)}"

        return cls(W_, ctl_id, "10A0", payload, **kwargs)

    @classmethod  # constructor for RQ/0404  # TODO
    def get_dhw_schedule_fragment(cls, ctl_id, frag_idx, frag_cnt, **kwargs):
        """Constructor to get a DHW schedule fragment (c.f. parser_0404)."""
        payload = f"0023000800{frag_idx + 1:02X}{frag_cnt:02X}"
        return cls(RQ, ctl_id, "0404", payload, **kwargs)

    @classmethod  # constructor for 1030  # TODO
    def set_mix_valve_params(
        cls,
        ctl_id,
        zone_idx,
        max_flow_setpoint=55,
        min_flow_setpoint=15,
        valve_run_time=150,
        pump_run_time=15,
        **kwargs,
    ):
        """Constructor to set the mix valve params of a zone (c.f. parser_1030)."""

        payload = f"{zone_idx:02X}" if isinstance(zone_idx, int) else zone_idx

        assert 0 <= max_flow_setpoint <= 99, max_flow_setpoint
        assert 0 <= min_flow_setpoint <= 50, min_flow_setpoint
        assert 0 <= valve_run_time <= 240, valve_run_time
        assert 0 <= pump_run_time <= 99, pump_run_time

        payload += f"C801{max_flow_setpoint:02X}"
        payload += f"C901{min_flow_setpoint:02X}"
        payload += f"CA01{valve_run_time:02X}"
        payload += f"CB01{pump_run_time:02X}"
        payload += f"CC01{1:02X}"

        return cls(W_, ctl_id, "1030", payload, **kwargs)

    @classmethod  # constructor for RQ/0418  # TODO
    def get_system_log_entry(cls, ctl_id, log_idx, **kwargs):
        """Constructor to get a log entry from a system (c.f. parser_0418)."""
        log_idx = log_idx if isinstance(log_idx, int) else int(log_idx, 16)
        return cls(RQ, ctl_id, "0418", f"{log_idx:06X}", **kwargs)

    @classmethod  # constructor for RQ/2E04
    def get_system_mode(cls, ctl_id, **kwargs):
        """Constructor to get the mode of a system (c.f. parser_2e04)."""
        return cls(RQ, ctl_id, "2E04", "FF", **kwargs)

    @classmethod  # constructor for 2E04  # TODO
    def set_system_mode(cls, ctl_id, system_mode, until=None, **kwargs):
        """Constructor to set/reset the mode of a system (c.f. parser_2e04)."""

        if system_mode is None:
            raise ValueError("Invalid args: system_mode cant be None")

        if isinstance(system_mode, int):
            system_mode = f"{system_mode:02X}"
        if system_mode in SYSTEM_MODE_MAP:
            system_mode = SYSTEM_MODE_MAP[system_mode]
        elif system_mode not in SYSTEM_MODE_LOOKUP:
            raise TypeError(f"Invalid args: Unknown system_mode: {system_mode}")

        # TODO: these need fixing
        # if until is None and system_mode == "xxx":
        #     system_mode = ZoneMode.ADVANCED  # until = dt.now() + td(hour=1)
        # elif until is not None and system_mode in (SystemMode.AUTO, SystemMode.RESET):
        #     raise ValueError(f"Invalid args: For {system_mode}, until should be None")

        assert system_mode in SYSTEM_MODE_LOOKUP, system_mode

        payload = SYSTEM_MODE_LOOKUP[system_mode]
        payload += dtm_to_hex(until) + ("00" if until is None else "01")

        return cls(W_, ctl_id, "2E04", payload, **kwargs)

    @classmethod  # constructor for RQ/3220  # TODO
    def get_opentherm_data(cls, dev_id, msg_id, **kwargs):
        """Constructor to get (Read-Data) opentherm msg value (c.f. parser_3220)."""
        msg_id = msg_id if isinstance(msg_id, int) else int(msg_id, 16)
        payload = f"0080{msg_id:02X}0000" if parity(msg_id) else f"0000{msg_id:02X}0000"
        return cls(RQ, dev_id, "3220", payload, **kwargs)

    @classmethod  # constructor for RQ/313F
    def get_system_time(cls, ctl_id, **kwargs):
        """Constructor to get the datetime of a system (c.f. parser_313f)."""
        return cls(RQ, ctl_id, "313F", "00", **kwargs)

    @classmethod  # constructor for 313F
    def set_system_time(cls, ctl_id, datetime, **kwargs):
        """Constructor to set the datetime of a system (c.f. parser_313f)."""
        #  W --- 30:185469 01:037519 --:------ 313F 009 0060003A0C1B0107E5

        return cls(W_, ctl_id, "313F", f"006000{dtm_to_hex(datetime)}", **kwargs)

    @classmethod  # constructor for RQ/1100  # TODO
    def get_tpi_params(cls, ctl_id, **kwargs):
        """Constructor to get the TPI params of a system (c.f. parser_1100)."""
        return cls(RQ, ctl_id, "1100", "FC", **kwargs)

    @classmethod  # constructor for 1100  # TODO
    def set_tpi_params(
        cls,
        ctl_id,
        domain_id,
        cycle_rate=3,  # TODO: check
        min_on_time=5,  # TODO: check
        min_off_time=5,  # TODO: check
        proportional_band_width=None,  # TODO: check
        **kwargs,
    ):
        """Constructor to set the TPI params of a system (c.f. parser_1100)."""

        payload = f"{domain_id:02X}" if isinstance(domain_id, int) else domain_id

        assert cycle_rate is None or cycle_rate in (3, 6, 9, 12), cycle_rate
        assert min_on_time is None or 1 <= min_on_time <= 5, min_on_time
        assert min_off_time is None or 1 <= min_off_time <= 5, min_off_time
        assert (
            proportional_band_width is None or 1.5 <= proportional_band_width <= 3.0
        ), proportional_band_width

        payload += f"{cycle_rate * 4:02X}"
        payload += f"{int(min_on_time * 4):02X}"
        payload += f"{int(min_off_time * 4):02X}FF"
        payload += f"{temp_to_hex(proportional_band_width)}01"

        return cls(W_, ctl_id, "1100", payload, **kwargs)

    @classmethod  # constructor for RQ/000A  # TODO
    def get_zone_config(cls, ctl_id, zone_idx, **kwargs):
        """Constructor to get the config of a zone (c.f. parser_000a)."""
        zone_idx = zone_idx if isinstance(zone_idx, int) else int(zone_idx, 16)
        return cls(RQ, ctl_id, "000A", f"{zone_idx:02X}00", **kwargs)

    @classmethod  # constructor for 000A  # TODO
    def set_zone_config(
        cls,
        ctl_id,
        zone_idx,
        min_temp=5,
        max_temp=35,
        local_override: bool = False,
        openwindow_function: bool = False,
        multiroom_mode: bool = False,
        **kwargs,
    ):
        """Constructor to set the config of a zone (c.f. parser_000a)."""

        payload = f"{zone_idx:02X}" if isinstance(zone_idx, int) else zone_idx

        assert 5 <= min_temp <= 21, min_temp
        assert 21 <= max_temp <= 35, max_temp
        assert isinstance(local_override, bool), local_override
        assert isinstance(openwindow_function, bool), openwindow_function
        assert isinstance(multiroom_mode, bool), multiroom_mode

        bitmap = 0 if local_override else 1
        bitmap |= 0 if openwindow_function else 2
        bitmap |= 0 if multiroom_mode else 16

        payload += f"{bitmap:02X}"
        payload += temp_to_hex(min_temp)
        payload += temp_to_hex(max_temp)

        return cls(W_, ctl_id, "000A", payload, **kwargs)

    @classmethod  # constructor for RQ/2349
    def get_zone_mode(cls, ctl_id, zone_idx, **kwargs):
        """Constructor to get the mode of a zone (c.f. parser_2349)."""
        zone_idx = zone_idx if isinstance(zone_idx, int) else int(zone_idx, 16)
        return cls(RQ, ctl_id, "2349", f"{zone_idx:02X}00", **kwargs)

    @classmethod  # constructor for W/2349
    def set_zone_mode(
        cls, ctl_id, zone_idx, mode=None, setpoint=None, until=None, **kwargs
    ):
        """Constructor to set/reset the mode of a zone (c.f. parser_2349).

        The setpoint has a resolution of 0.1 C. If a setpoint temperature is required,
        but none is provided, evohome will use the maximum possible value.

        The until has a resolution of 1 min.

        Incompatible combinations:
        - mode == Follow & setpoint not None (will silently ignore setpoint)
        - mode == Temporary & until is None (will silently ignore)
        """
        #  W --- 18:013393 01:145038 --:------ 2349 013 0004E201FFFFFF330B1A0607E4
        #  W --- 22:017139 01:140959 --:------ 2349 007 0801F400FFFFFF

        if mode is None and setpoint is None:
            raise ValueError("Invalid args: Both mode and setpoint cant be None")

        if mode is None:
            # TODO: the else may need to be profile-specific, e.g. ADVANCED for 01:
            mode = ZoneMode.TEMPORARY if until else ZoneMode.PERMANENT
        elif isinstance(mode, int):
            mode = f"{mode:02X}"
        if mode in ZONE_MODE_MAP:
            mode = ZONE_MODE_MAP[mode]
        elif mode not in ZONE_MODE_LOOKUP:
            raise TypeError(f"Invalid args: Unknown mode: {mode}")

        if setpoint is None and mode != ZoneMode.SCHEDULE:
            raise ValueError(f"Invalid args: For {mode}, setpoint cant be None")
        elif setpoint is not None and not isinstance(setpoint, (int, float)):
            raise ValueError(f"Invalid args: setpoint={setpoint}, should be float")

        if until is None and mode == ZoneMode.TEMPORARY:
            mode = ZoneMode.ADVANCED  # until = dt.now() + td(hour=1)
        elif until is not None and mode in (ZoneMode.SCHEDULE, ZoneMode.PERMANENT):
            raise ValueError(f"Invalid args: For {mode}, until should be None")

        assert mode in ZONE_MODE_LOOKUP, mode

        payload = f"{zone_idx:02X}" if isinstance(zone_idx, int) else zone_idx
        payload += temp_to_hex(setpoint)  # None means max, if a temp is required
        payload += ZONE_MODE_LOOKUP[mode] + "FFFFFF"
        payload += "" if until is None else dtm_to_hex(until)

        return cls(W_, ctl_id, "2349", payload, **kwargs)

    @classmethod  # constructor for RQ/0004  # TODO
    def get_zone_name(cls, ctl_id, zone_idx, **kwargs):
        """Constructor to get the name of a zone (c.f. parser_0004)."""
        zone_idx = zone_idx if isinstance(zone_idx, int) else int(zone_idx, 16)
        return cls(RQ, ctl_id, "0004", f"{zone_idx:02X}00", **kwargs)

    @classmethod  # constructor for 0004  # TODO
    def set_zone_name(cls, ctl_id, zone_idx, name: str, **kwargs):
        """Constructor to set the name of a zone (c.f. parser_0004)."""

        payload = f"{zone_idx:02X}" if isinstance(zone_idx, int) else zone_idx

        payload += f"00{str_to_hex(name)[:24]:0<40}"  # TODO: check limit 12 (24)?

        return cls(W_, ctl_id, "0004", payload, **kwargs)

    @classmethod  # constructor for 2309
    def set_zone_setpoint(cls, ctl_id, zone_idx, setpoint: float, **kwargs):
        """Constructor to set the setpoint of a zone (c.f. parser_2309)."""
        #  W --- 34:092243 01:145038 --:------ 2309 003 0107D0

        payload = f"{zone_idx:02X}" if isinstance(zone_idx, int) else zone_idx
        payload += temp_to_hex(setpoint)

        return cls(W_, ctl_id, "2309", payload, **kwargs)

    @classmethod  # constructor for RQ/0404  # TODO
    def get_zone_schedule_fragment(cls, ctl_id, zone_idx, frag_idx, frag_cnt, **kwargs):
        """Constructor to get a zone schedule fragment (c.f. parser_0404)."""
        zone_idx = zone_idx if isinstance(zone_idx, int) else int(zone_idx, 16)
        payload = f"{zone_idx:02X}20000800{frag_idx + 1:02X}{frag_cnt:02X}"
        return cls(RQ, ctl_id, "0404", payload, **kwargs)

    @classmethod
    def _puzzle(
        cls, msg_type="01", message=None, ordinal=0, interval=0, length=None, **kwargs
    ):

        if msg_type == "00":
            payload = f"00{dts_to_hex(dt.now())}7F"
            payload += f"{str_to_hex(message)}7F"

        elif msg_type in ("01", "02", "03"):
            payload = f"{msg_type}{str_to_hex(message)}7F"

        else:
            payload = f"7F{dts_to_hex(dt.now())}7F"
            payload += f"{ordinal % 0x10000:04X}7F{int(interval * 100):04X}7F"

        if length:
            payload = payload.ljust(length * 2, "F")

        return cls(I_, NUL_DEV_ADDR.id, "7FFF", payload[:48], **kwargs)

    @classmethod
    def packet(cls, verb, seqn, addr0, addr1, addr2, code, payload, **kwargs):
        """Construct commands with fewer assumptions/checks than the main constructor.

        For example:
            I 056 --:------ --:------ 02:123456 99FD 003 000404
        """

        verb = I_ if verb == I_ else W_ if verb == W_ else verb

        cmd = cls(verb, NUL_DEV_ADDR.id, code, payload, **kwargs)

        if seqn in ("", "-", "--", "---"):
            cmd.seqn = "---"
        elif seqn is not None:
            cmd.seqn = f"{int(seqn):03d}"

        cmd.from_addr, cmd.dest_addr, cmd.addrs = extract_addrs(
            f"{addr0} {addr1} {addr2}"
        )

        cmd._is_valid = None
        if not cmd.is_valid:
            raise ValueError(f"Invalid parameter values for command: {cmd}")

        return cmd


class FaultLog:  # 0418  # TODO: used a NamedTuple
    """The fault log of a system."""

    def __init__(self, ctl, msg=None, **kwargs) -> None:
        _LOGGER.debug("FaultLog(ctl=%s).__init__()", ctl)

        self._loop = ctl._gwy._loop

        self.id = ctl.id
        self._ctl = ctl
        # self._evo = ctl._evo
        self._gwy = ctl._gwy

        self._fault_log = None
        self._fault_log_done = None

        self._limit = 11  # TODO: make configurable

    def __repr_(self) -> str:
        return json.dumps(self._fault_log) if self._fault_log_done else None

    def __str_(self) -> str:
        return f"{self._ctl} (fault log)"

    @property
    def fault_log(self) -> Optional[dict]:
        """Return the fault log of a system."""
        if not self._fault_log_done:
            return

        result = {
            x: {k: v for k, v in y.items() if k[:1] != "_"}
            for x, y in self._fault_log.items()
        }

        return {k: [x for x in v.values()] for k, v in result.items()}

    async def get_fault_log(self, force_refresh=None) -> Optional[dict]:
        """Get the fault log of a system."""
        _LOGGER.debug("FaultLog(%s).get_fault_log()", self)

        self._fault_log = {}  # TODO: = namedtuple("Fault", "timestamp fault_state ...")
        self._fault_log_done = None

        self._rq_log_entry(log_idx=0)  # calls loop.create_task()

        time_start = dt.now()
        while not self._fault_log_done:
            await asyncio.sleep(TIMER_SHORT_SLEEP)
            if dt.now() > time_start + TIMER_LONG_TIMEOUT * 2:
                raise ExpiredCallbackError("failed to obtain log entry (long)")

        return self.fault_log

    def _rq_log_entry(self, log_idx=0):
        """Request the next log entry."""
        _LOGGER.debug("FaultLog(%s)._rq_log_entry(%s)", self, log_idx)

        def rq_callback(msg) -> None:
            _LOGGER.debug("FaultLog(%s)._proc_log_entry(%s)", self.id, msg)

            if not msg:
                self._fault_log_done = True
                # raise ExpiredCallbackError("failed to obtain log entry (short)")
                return

            log = dict(msg.payload)
            log_idx = int(log.pop("log_idx"), 16)
            if not log:  # null response (no payload)
                # TODO: delete other callbacks rather than waiting for them to expire
                self._fault_log_done = True
                return

            self._fault_log[log_idx] = log  # TODO: make a named tuple
            if log_idx < self._limit:
                self._rq_log_entry(log_idx + 1)
            else:
                self._fault_log_done = True

        # TODO: (make method) register callback for null response (no payload)
        null_header = "|".join((RP, self.id, "0418"))
        if null_header not in self._gwy.msg_transport._callbacks:
            self._gwy.msg_transport._callbacks[null_header] = {
                FUNC: rq_callback,
                DEAMON: True,
            }

        rq_callback = {FUNC: rq_callback, TIMEOUT: 10}
        self._gwy.send_cmd(
            Command.get_system_log_entry(self._ctl.id, log_idx, callback=rq_callback)
        )


class Schedule:  # 0404
    """The schedule of a zone."""

    def __init__(self, zone, **kwargs) -> None:
        _LOGGER.debug("Schedule(zone=%s).__init__()", zone.id)  # TODO: str(zone) breaks

        self._loop = zone._gwy._loop

        self.id = zone.id
        self._zone = zone
        self.idx = zone.idx

        self._ctl = zone._ctl
        self._evo = zone._evo
        self._gwy = zone._gwy

        self._schedule = None
        self._schedule_done = None

        # initialse the fragment array()
        self._num_frags = None
        self._rx_frags = None
        self._tx_frags = None

    def __repr_(self) -> str:
        return json.dumps(self.schedule) if self._schedule_done else None

    def __str_(self) -> str:
        return f"{self._zone} (schedule)"

    @property
    def schedule(self) -> Optional[dict]:
        """Return the schedule of a zone."""
        if not self._schedule_done or None in self._rx_frags:
            return
        if self._schedule:
            return self._schedule

        if self._rx_frags[0][MSG].payload[FRAG_TOTAL] == 255:
            return {}

        frags = [v for d in self._rx_frags for k, v in d.items() if k == FRAGMENT]

        try:
            self._schedule = self._frags_to_sched(frags)
        except zlib.error:
            self._schedule = None
            _LOGGER.exception("Invalid schedule fragments: %s", frags)
            return

        return self._schedule

    async def get_schedule(self, force_refresh=None) -> Optional[dict]:
        """Get the schedule of a zone."""
        _LOGGER.debug(f"Schedule({self.id}).get_schedule()")

        if not await self._obtain_lock():  # TODO: should raise a TimeOut
            return

        if force_refresh:
            self._schedule_done = None

        if not self._schedule_done:
            self._rq_fragment(frag_cnt=0)  # calls loop.create_task()

            time_start = dt.now()
            while not self._schedule_done:
                await asyncio.sleep(TIMER_SHORT_SLEEP)
                if dt.now() > time_start + TIMER_LONG_TIMEOUT:
                    self._release_lock()
                    raise ExpiredCallbackError("failed to get schedule")

        self._release_lock()

        return self.schedule

    def _rq_fragment(self, frag_cnt=0) -> None:
        """Request the next missing fragment (index starts at 1, not 0)."""
        _LOGGER.debug("Schedule(%s)._rq_fragment(%s)", self.id, frag_cnt)

        def rq_callback(msg) -> None:
            if not msg:  # _LOGGER.debug()... TODO: needs fleshing out
                # TODO: remove any callbacks from msg._gwy.msg_transport._callbacks
                _LOGGER.warning(f"Schedule({self.id}): Callback timed out")
                self._schedule_done = True
                return

            _LOGGER.debug(
                f"Schedule({self.id})._proc_fragment(msg), frag_idx=%s, frag_cnt=%s",
                msg.payload.get(FRAG_INDEX),
                msg.payload.get(FRAG_TOTAL),
            )

            if msg.payload[FRAG_TOTAL] == 255:  # no schedule (i.e. no zone)
                _LOGGER.warning(f"Schedule({self.id}): No schedule")
                # TODO: remove any callbacks from msg._gwy.msg_transport._callbacks
                pass  # self._rx_frags = [None]

            elif msg.payload[FRAG_TOTAL] != len(self._rx_frags):  # e.g. 1st frag
                self._rx_frags = [None] * msg.payload[FRAG_TOTAL]

            self._rx_frags[msg.payload[FRAG_INDEX] - 1] = {
                FRAGMENT: msg.payload[FRAGMENT],
                MSG: msg,
            }

            # discard any fragments significantly older that this most recent fragment
            for frag in [f for f in self._rx_frags if f is not None]:
                frag = None if frag[MSG].dtm < msg.dtm - FIVE_MINS else frag

            if None in self._rx_frags:  # there are still frags to get
                self._rq_fragment(frag_cnt=msg.payload[FRAG_TOTAL])
            else:
                self._schedule_done = True

        if frag_cnt == 0:
            self._rx_frags = [None]  # and: frag_idx = 0

        frag_idx = next((i for i, f in enumerate(self._rx_frags) if f is None), -1)

        # 053 RQ --- 30:185469 01:037519 --:------ 0006 001 00
        # 045 RP --- 01:037519 30:185469 --:------ 0006 004 000500E6

        # 059 RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0100
        # 045 RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0104 688...
        # 059 RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0204
        # 045 RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0204 4AE...
        # 059 RQ --- 30:185469 01:037519 --:------ 0404 007 00-23000800 0304
        # 046 RP --- 01:037519 30:185469 --:------ 0404 048 00-23000829 0304 6BE...

        rq_callback = {FUNC: rq_callback, TIMEOUT: 1}
        cmd = Command.get_zone_schedule_fragment(
            self._ctl.id, self.idx, frag_idx, frag_cnt, callback=rq_callback
        )
        self._gwy.send_cmd(cmd)

    @staticmethod
    def _frags_to_sched(frags: list) -> dict:
        # _LOGGER.debug(f"Sched({self})._frags_to_sched: array is: %s", frags)
        raw_schedule = zlib.decompress(bytearray.fromhex("".join(frags)))

        zone_idx, schedule = None, []
        old_day, switchpoints = 0, []

        for i in range(0, len(raw_schedule), 20):
            zone_idx, day, time, temp, _ = struct.unpack(
                "<xxxxBxxxBxxxHxxHH", raw_schedule[i : i + 20]
            )
            if day > old_day:
                schedule.append({DAY_OF_WEEK: old_day, SWITCHPOINTS: switchpoints})
                old_day, switchpoints = day, []
            switchpoints.append(
                {
                    TIME_OF_DAY: "{0:02d}:{1:02d}".format(*divmod(time, 60)),
                    HEAT_SETPOINT: temp / 100,
                }
            )

        schedule.append({DAY_OF_WEEK: old_day, SWITCHPOINTS: switchpoints})

        return {ZONE_IDX: f"{zone_idx:02X}", SCHEDULE: schedule}

    @staticmethod
    def _sched_to_frags(schedule: dict) -> list:
        # _LOGGER.debug(f"Sched({self})._sched_to_frags: array is: %s", schedule)
        frags = [
            (
                int(schedule[ZONE_IDX], 16),
                int(week_day[DAY_OF_WEEK]),
                int(setpoint[TIME_OF_DAY][:2]) * 60 + int(setpoint[TIME_OF_DAY][3:]),
                int(setpoint[HEAT_SETPOINT] * 100),
            )
            for week_day in schedule[SCHEDULE]
            for setpoint in week_day[SWITCHPOINTS]
        ]
        frags = [struct.pack("<xxxxBxxxBxxxHxxHxx", *s) for s in frags]

        cobj = zlib.compressobj(level=9, wbits=14)
        blob = b"".join([cobj.compress(s) for s in frags]) + cobj.flush()
        blob = blob.hex().upper()

        return [blob[i : i + 82] for i in range(0, len(blob), 82)]

    async def set_schedule(self, schedule) -> None:
        """Set the schedule of a zone."""
        _LOGGER.debug(f"Schedule({self.id}).set_schedule(schedule)")

        if not await self._obtain_lock():  # TODO: should raise a TimeOut
            return

        self._schedule_done = None

        self._tx_frags = self._sched_to_frags(schedule)
        self._tx_fragment(frag_idx=0)

        time_start = dt.now()
        while not self._schedule_done:
            await asyncio.sleep(TIMER_SHORT_SLEEP)
            if dt.now() > time_start + TIMER_LONG_TIMEOUT:
                self._release_lock()
                raise ExpiredCallbackError("failed to set schedule")

        self._release_lock()

    def _tx_fragment(self, frag_idx=0) -> None:
        """Send the next fragment (index starts at 0)."""
        _LOGGER.debug(
            "Schedule(%s)._tx_fragment(%s/%s)", self.id, frag_idx, len(self._tx_frags)
        )

        def tx_callback(msg) -> None:
            _LOGGER.debug(
                f"Schedule({self.id})._proc_fragment(msg), frag_idx=%s, frag_cnt=%s",
                msg.payload.get(FRAG_INDEX),
                msg.payload.get(FRAG_TOTAL),
            )

            if msg.payload[FRAG_INDEX] < msg.payload[FRAG_TOTAL]:
                self._tx_fragment(frag_idx=msg.payload.get(FRAG_INDEX))
            else:
                self._schedule_done = True

        payload = "{0}200008{1:02X}{2:02d}{3:02d}{4:s}".format(
            self.idx,
            int(len(self._tx_frags[frag_idx]) / 2),
            frag_idx + 1,
            len(self._tx_frags),
            self._tx_frags[frag_idx],
        )
        tx_callback = {FUNC: tx_callback, TIMEOUT: 3}  # 1 sec too low
        self._gwy.send_cmd(
            Command(W_, self._ctl.id, "0404", payload, callback=tx_callback)
        )

    async def _obtain_lock(self) -> bool:  # Lock to prevent Rx/Tx at same time
        while True:

            self._evo.zone_lock.acquire()
            if self._evo.zone_lock_idx is None:
                self._evo.zone_lock_idx = self.idx
            self._evo.zone_lock.release()

            if self._evo.zone_lock_idx == self.idx:
                break

            await asyncio.sleep(0.1)  # gives the other zone enough time

        return True

    def _release_lock(self) -> None:
        self._evo.zone_lock.acquire()
        self._evo.zone_lock_idx = None
        self._evo.zone_lock.release()
