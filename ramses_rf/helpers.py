#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - Helper functions."""

import asyncio
import re
from inspect import iscoroutinefunction
from typing import Callable


def OUT_periodic(period) -> Callable:
    def scheduler(fcn):
        async def wrapper(*args, **kwargs):
            while True:
                asyncio.create_task(fcn(*args, **kwargs))
                await asyncio.sleep(period)

        return wrapper

    return scheduler


def schedule_task(func, *args, delay=None, period=None, **kwargs) -> asyncio.Task:
    """Start a coro after delay seconds."""

    async def execute_func(func, *args, **kwargs):
        if iscoroutinefunction(func):
            return await func(*args, **kwargs)
        return func(*args, **kwargs)

    async def schedule_func(delay, period, func, *args, **kwargs):
        if delay:
            await asyncio.sleep(delay)

        if not period:
            asyncio.create_task(execute_func(func, *args, **kwargs))
            return

        while period:
            asyncio.create_task(execute_func(func, *args, **kwargs))
            await asyncio.sleep(period)

    return asyncio.create_task(schedule_func(delay, period, func, *args, **kwargs))


def OUT_slugify_string(key: str) -> str:
    """Convert a string to snake_case."""
    string = re.sub(r"[\-\.\s]", "_", str(key))
    return (string[0]).lower() + re.sub(
        r"[A-Z]", lambda matched: f"_{matched.group(0).lower()}", string[1:]
    )
