#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Helper functions."""
from __future__ import annotations

import asyncio
from copy import deepcopy
from inspect import iscoroutinefunction


def merge(src: dict, dst: dict, _dc: bool = None) -> dict:
    """Deep merge a src dict (precedent) into a dst dict and return the result.

    run me with nosetests --with-doctest file.py

    >>>            s = {'data': {'rows': {'pass': 'dog',                'num': '1'}}}
    >>>            d = {'data': {'rows': {               'fail': 'cat', 'num': '5'}}}
    >>> merge(s, d) == {'data': {'rows': {'pass': 'dog', 'fail': 'cat', 'num': '1'}}}
    True
    """

    new_dst = dst if _dc else deepcopy(dst)  # start with copy of dst, merge src into it
    for key, value in src.items():  # values are only: dict, list, value or None
        if isinstance(value, dict):  # is dict
            node = new_dst.setdefault(key, {})  # get node or create one
            merge(value, node, _dc=True)

        elif not isinstance(value, list):  # is value
            new_dst[key] = value  # src takes precidence, assert will fail

        elif key not in new_dst or not isinstance(new_dst[key], list):  # is list
            new_dst[key] = src[key]  # not expected, but maybe

        else:
            new_dst[key] = list(set(src[key] + new_dst[key]))  # will sort

    # assert _is_subset(shrink(src), shrink(new_dst))
    return new_dst


def shrink(value: dict, keep_falsys: bool = False, keep_hints: bool = False) -> dict:
    """Return a minimized dict, after removing all the meaningless items.

    Specifically, removes items with:
    - uwanted keys (starting with '_')
    - falsey values
    """

    def walk(node):
        if isinstance(node, dict):
            return {
                k: walk(v)
                for k, v in node.items()
                if (keep_hints or k[:1] != "_") and (keep_falsys or walk(v))
            }
        elif isinstance(node, list):
            try:
                return sorted([walk(x) for x in node if x])
            except TypeError:  # if a list of dicts
                return [walk(x) for x in node if x]
        else:
            return node

    if not isinstance(value, dict):
        raise TypeError("value is not a dict")

    return walk(value)


def schedule_task(fnc, *args, delay=None, period=None, **kwargs) -> asyncio.Task:
    """Start a coro after delay seconds."""

    async def execute_fnc(fnc, *args, **kwargs):
        if iscoroutinefunction(fnc):
            return await fnc(*args, **kwargs)
        return fnc(*args, **kwargs)

    async def schedule_fnc(delay, period, fnc, *args, **kwargs):
        if delay:
            await asyncio.sleep(delay)

        if not period:
            await execute_fnc(fnc, *args, **kwargs)
            return

        while period:
            await execute_fnc(fnc, *args, **kwargs)
            await asyncio.sleep(period)

    return asyncio.create_task(
        schedule_fnc(delay, period, fnc, *args, **kwargs), name=str(fnc)
    )


def _setup_event_handlers(self) -> None:  # HACK: for dev/test only
    import logging
    import os
    import signal

    _LOGGER = logging.getLogger(__name__)

    def handle_exception(loop, context):
        """Handle exceptions on any platform."""
        _LOGGER.error("Caught an exception (%s), processing...", context["message"])

        exc = context.get("exception")
        if exc:
            try:
                raise exc
            except KeyboardInterrupt:
                pass

    async def handle_sig_posix(sig):
        """Handle signals on posix platform."""
        _LOGGER.debug("Received a signal (%s), processing...", sig.name)

        if sig == signal.SIGUSR1:
            _LOGGER.info("Schema: \r\n%s", {self.tcs.id: self.tcs.schema})
            _LOGGER.info("Params: \r\n%s", {self.tcs.id: self.tcs.params})
            _LOGGER.info("Status: \r\n%s", {self.tcs.id: self.tcs.status})

        elif sig == signal.SIGUSR2:
            _LOGGER.info("Status: \r\n%s", {self.tcs.id: self.tcs.status})

    _LOGGER.debug("_setup_event_handlers(): Creating exception handler...")
    self._loop.set_exception_handler(handle_exception)

    _LOGGER.debug("_setup_event_handlers(): Creating signal handlers...")
    if os.name == "posix":  # full support
        for sig in [signal.SIGUSR1, signal.SIGUSR2]:
            self._loop.add_signal_handler(
                sig, lambda sig=sig: self._loop.create_task(handle_sig_posix(sig))
            )
    elif os.name == "nt":  # supported, but YMMV
        _LOGGER.warning("Be aware, YMMV with Windows...")
    else:  # unsupported
        raise RuntimeError(f"Unsupported OS for this module: {os.name}")
