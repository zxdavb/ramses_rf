#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers and corresponding output (schema, traits, params, status).
"""

import json

from serial.tools import list_ports

from ramses_rf import Gateway
from tests.common import TEST_DIR

WORK_DIR = f"{TEST_DIR}/engine"

SERIAL_PORT = "/dev/ttyUSB0"


async def load_test_system(ser_name, config: dict = None) -> Gateway:
    """Create a system state from a packet log (using an optional configuration)."""

    try:
        with open(f"{WORK_DIR}/config.json") as f:
            kwargs = json.load(f)
    except FileNotFoundError:
        kwargs = {"config": {}}

    if config:
        kwargs.update(config)

    gwy = Gateway(ser_name, **kwargs)
    return gwy


async def test_get_0006():

    if not (c for c in list_ports.comports() if c.device == SERIAL_PORT):
        return

    gwy = await load_test_system(SERIAL_PORT)

    await gwy.start(start_discovery=False)  # may: SerialException

    version = await gwy.tcs.get_schedule_version()  # RQ|0006, may: TimeoutError

    assert isinstance(version, int)
    assert version == gwy.tcs._msgs["0006"].payload["change_counter"]

    await gwy.stop()
