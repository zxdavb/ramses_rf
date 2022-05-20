#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers and corresponding output (schema, traits, params, status).
"""

import json

from ramses_rf import Gateway
from tests.common import TEST_DIR

WORK_DIR = f"{TEST_DIR}/engine"

SERIAL_PORT = "/dev/usb0"


async def load_test_system(config: dict = None) -> Gateway:
    """Create a system state from a packet log (using an optional configuration)."""

    try:
        with open(f"{WORK_DIR}/config.json") as f:
            kwargs = json.load(f)
    except FileNotFoundError:
        kwargs = {"config": {}}

    if config:
        kwargs.update(config)

    gwy = Gateway(SERIAL_PORT, **kwargs)
    await gwy.start()

    return gwy


async def test_get_0006():
    gwy = await load_test_system()

    version = await gwy.tcs.get_schedule_version()

    print(f"version = {version}")
