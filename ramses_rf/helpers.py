#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Helper functions."""

import asyncio
import re
from inspect import iscoroutinefunction


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
