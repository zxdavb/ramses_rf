#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Expose an 0418 fault log (is a stateful process).
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime as dt, timedelta as td
from typing import TYPE_CHECKING

from ramses_tx import Command
from ramses_tx.const import SZ_DAEMON, SZ_FUNC, SZ_TIMEOUT, __dev_mode__

from ..exceptions import ExpiredCallbackError

# skipcq: PY-W2000
from ..const import (  # noqa: F401, isort: skip, pylint: disable=unused-import
    I_,
    RP,
    RQ,
    W_,
    Code,
)

if TYPE_CHECKING:  # mypy TypeVars and similar (e.g. Index, Verb)
    # skipcq: PY-W2000
    from ..const import Index, Verb  # noqa: F401, pylint: disable=unused-import


DEV_MODE = __dev_mode__ and False

_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


TIMER_SHORT_SLEEP = 0.05
TIMER_LONG_TIMEOUT = td(seconds=60)


# TODO: make stateful (a la binding)
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

        if self._gwy._read_only:
            raise RuntimeError("Sending is disabled")

        self._START = 0 if start is None else start
        self._limit = 6 if limit is None else limit

        self._faultlog = {}  # TODO: = namedtuple("Fault", "timestamp fault_state ...")
        self._faultlog_done = None

        self._rq_log_entry(log_idx=self._START)

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

        # FIXME: refactoring protocol stack
        # FIXME: make a better way of creating these callbacks
        # register callback for null response, which has no ctx (no frag_id),
        # and so a different header
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
