#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Helper functions."""

import asyncio
import re
from inspect import iscoroutinefunction


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

    async def execute_func(fnc, *args, **kwargs):
        if iscoroutinefunction(fnc):
            return await fnc(*args, **kwargs)
        return fnc(*args, **kwargs)

    async def schedule_func(delay, period, fnc, *args, **kwargs):
        if delay:
            await asyncio.sleep(delay)

        if not period:
            asyncio.create_task(execute_func(fnc, *args, **kwargs))
            return

        while period:
            asyncio.create_task(execute_func(fnc, *args, **kwargs))
            await asyncio.sleep(period)

    return asyncio.create_task(schedule_func(delay, period, fnc, *args, **kwargs))


def _out_slugify_string(key: str) -> str:
    """Convert a string to snake_case."""
    string = re.sub(r"[\-\.\s]", "_", str(key))
    return (string[0]).lower() + re.sub(
        r"[A-Z]", lambda matched: f"_{matched.group(0).lower()}", string[1:]
    )
