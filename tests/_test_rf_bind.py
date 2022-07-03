#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers and corresponding output (schema, traits, params, status).
"""

import json
from copy import deepcopy

from serial.tools import list_ports

from ramses_rf.const import SZ_SCHEDULE, SZ_TOTAL_FRAGS, SZ_ZONE_IDX, _0006, _0404
from ramses_rf.schedule import (
    DAY_OF_WEEK,
    ENABLED,
    HEAT_SETPOINT,
    SCHEMA_SCHEDULE_DHW,
    SCHEMA_SCHEDULE_ZON,
    SWITCHPOINTS,
    TIME_OF_DAY,
)
from tests.common import TEST_DIR

WORK_DIR = f"{TEST_DIR}/rf_engine"


if ports := [c for c in list_ports.comports() if c.device[-7:-1] == "ttyACM"]:
    from ramses_rf import Gateway

    SERIAL_PORT = ports[0].device
    GWY_ID = "01:145038"

else:
    from tests.mock_gateway import MockGateway as Gateway

    SERIAL_PORT = "/dev/ttyMOCK"
    GWY_ID = "01:000730"


# import tracemalloc
# tracemalloc.start()


async def load_test_system(config: dict = None) -> Gateway:
    """Create a system state from a packet log (using an optional configuration)."""

    with open(f"{WORK_DIR}/config.json") as f:
        kwargs = json.load(f)

    if config:
        kwargs.update(config)

    gwy = Gateway(SERIAL_PORT, **kwargs)

    return gwy, gwy.system_by_id[GWY_ID]


# async def test_ww_0404_zone():

#     gwy, tcs = await load_test_system(config={"disable_discovery": True})
#     await gwy.start(start_discovery=False)  # may: SerialException

#     if tcs.zones:
#         await write_schedule(tcs.zones[0])

#     await gwy.stop()
