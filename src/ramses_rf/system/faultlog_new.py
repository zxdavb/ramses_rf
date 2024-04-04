#!/usr/bin/env python3
#
"""RAMSES RF - Expose an 0418 fault log (is a stateful process)."""

from __future__ import annotations

import dataclasses
import logging
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Literal, Never, NewType, TypeAlias

from ramses_tx import Message, Packet
from ramses_tx.const import (
    SZ_LOG_ENTRY,
    SZ_LOG_IDX,
    FaultDeviceClass,
    FaultState,
    FaultType,
)
from ramses_tx.helpers import parse_fault_log_entry
from ramses_tx.schemas import DeviceIdT

from ramses_rf.const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:
    from ramses_rf.system.heat import Evohome


_LOGGER = logging.getLogger(__name__)


#  {'log_idx': '00', 'log_entry': ('21-12-23T11:59:35', 'restore', 'battery_low', 'actuator', '00', '04:164787', 'B0', '0000', 'FFFF7000')}


@dataclasses.dataclass(frozen=True, kw_only=True, order=True)
class FaultLogEntry:
    """A fault log entry of an evohome fault log.

    Fault log entries do have a log_idx attr, but this is merely their current location
    in the system's fault log.
    """

    timestamp: str  # #               # 21-12-23T11:59:35 - assume is unique
    fault_state: FaultState  # #      # fault, restore, unknown_c0
    fault_type: FaultType  # #        # system_fault, battery_low, sensor_fault, etc.
    domain_idx: str  # #              # 00-0F, FC, etc. ? only if dev_class is/not CTL?
    device_class: FaultDeviceClass  # # controller, actuator, sensor, etc.
    device_id: DeviceIdT | None  # #  # 04:164787

    @classmethod
    def from_msg(cls, msg: Message) -> FaultLogEntry:
        """Create a fault log entry from a message's packet."""
        return cls.from_pkt(msg._pkt)

    @classmethod
    def from_pkt(cls, pkt: Packet) -> FaultLogEntry:
        """Create a fault log entry from a packet's payload."""

        log_entry = parse_fault_log_entry(pkt.payload)
        if log_entry is None:
            raise TypeError("Null fault log entry")

        return cls(**{k: v for k, v in log_entry.items() if k[:1] != "_"})  # type: ignore[arg-type]


FaultDtmT = NewType("FaultDtmT", str)
FaultIdxIntT = NewType("FaultIdxIntT", int)

FaultLogT: TypeAlias = dict[Never, Never] | dict[FaultDtmT, FaultLogEntry]
FaultMapT: TypeAlias = OrderedDict[Never, Never] | OrderedDict[FaultIdxIntT, FaultDtmT]


class FaultLog:  # 0418  # TODO: use a NamedTuple
    """The fault log of an evohome system.

    This code assumes that the `timestamp` attr of each log entry is a unique identifer.

    Null entries do not have a timestamp. All subsequent entries will also be null.

    The `log_idx` is not an identifier: it is merely the current position of a log entry
    in the system log.

    New entries are added to the top of the log (log_idx=0), and the log_idx is
    incremented for all exisiting log enties.
    """

    _MAX_LOG_IDX = 0x3E

    def __init__(self, ctl: Evohome) -> None:
        self._ctl = ctl
        self.id = ctl.id
        self._gwy = ctl._gwy

        self._log: FaultLogT = dict()
        self._map: FaultMapT = OrderedDict()
        self._log_done: bool | None = None

        self._is_current: bool = True  # if we now our log is out of date

    def _get_idx_from_map(
        self, dtm: FaultDtmT, /, *, default: FaultIdxIntT | None = None
    ) -> FaultIdxIntT | None:
        idx_: FaultIdxIntT
        dtm_: FaultDtmT

        for idx_, dtm_ in self._map.items():
            if dtm_ == dtm:
                return idx_
        return default

    def _insert_into_map(self, idx: FaultIdxIntT, dtm: FaultDtmT | None) -> FaultMapT:
        """Rebuild the map, given the new log entry data."""

        new_map: FaultMapT = OrderedDict()

        # usu. idx == 0, but could be > 0
        new_map |= {
            k: v for k, v in self._map.items() if k < idx and (dtm is None or v > dtm)
        }

        if dtm is None:  # there are no subsequent log entries
            return new_map

        new_map |= {idx: dtm}

        if not (idxs := [k for k, v in self._map.items() if v < dtm]):
            return new_map

        if (next_idx := min(idxs)) > idx:
            diff = 0
        elif next_idx == idx:
            diff = 1  # next - idx + 1
        else:
            diff = idx + 1  # 1 if self._map.get(idx) else 0

        new_map |= {
            k + diff: v  # type: ignore[misc]
            for k, v in self._map.items()
            if (k >= idx or v < dtm) and k + diff <= self._MAX_LOG_IDX
        }

        return new_map

    def _handle_msg(self, msg: Message) -> None:
        """Handle a fault log message."""

        if msg.code != Code._0418:
            return

        # parse_fault_log_entry() uses _log_idx
        idx: FaultIdxIntT = int(msg.payload[SZ_LOG_IDX], 16)  # type: ignore[assignment]

        if msg.payload[SZ_LOG_ENTRY] is None:  # NOTE: Subsequent entries will be empty
            self._map = self._insert_into_map(idx, None)
            self._log = {k: v for k, v in self._log.items() if k in self._map.values()}
            return  # If idx != 0, should we also check from idx = 0?

        entry = FaultLogEntry.from_msg(msg)  # if msg.payload[SZ_LOG_ENTRY] else None
        dtm: FaultDtmT = entry.timestamp  # type: ignore[assignment]

        if self._map.get(idx) == dtm:  # type: ignore[call-overload]
            return  # i.e. No evidence anything has changed

        if dtm not in self._log:
            self._log |= {dtm: entry}  # must add entry before _insert_into_map()
        self._map = self._insert_into_map(idx, dtm)  # updates self._map
        self._log = {k: v for k, v in self._log.items() if k in self._map.values()}

        # if idx != 0:  # there's other (new/changed) entries above this one?
        #     pass

    @property
    def faultlog(self) -> dict[int, Any] | None:
        """Return the fault log of a system."""

        # if self._faultlog:
        #     return self._faultlog

        return {  # TODO: ensure sorted
            idx: entry
            for idx, dtm_m in self._map.items()
            for dtm_e, entry in self._log.items()
            if dtm_m == dtm_e
        }

    def is_current(self, force_io: bool | None = None) -> bool:
        """Return True if the local fault log is identical to the controllers.

        If force_io, retrieve the 0th log entry and check it is identical to the local
        copy.
        """

        if not self._is_current:
            return False
        return True


# fmt: off
FaultIdxStrT = Literal[
    '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0A', '0B', '0C', '0D', '0E', '0F',
    '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1A', '1B', '1C', '1D', '1E', '1F',
    '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2A', '2B', '2C', '2D', '2E', '2F',
    '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3A', '3B', '3C', '3D', '3E', '3F',
]
# fmt: on
