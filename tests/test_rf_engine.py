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

WORK_DIR = f"{TEST_DIR}/rf_engine"

SERIAL_PORT = "/dev/ttyUSB0"


async def load_test_system(ser_name, config: dict = None) -> Gateway:
    """Create a system state from a packet log (using an optional configuration)."""

    with open(f"{WORK_DIR}/config.json") as f:
        kwargs = json.load(f)

    if config:
        kwargs.update(config)

    gwy = Gateway(ser_name, **kwargs)
    return gwy


async def test_rq_0006():
    def validate_result(version):
        assert isinstance(version, int)
        assert version == gwy.tcs._msgs["0006"].payload["change_counter"]

        return version

    if not [c for c in list_ports.comports() if c.device == SERIAL_PORT]:
        return

    gwy = await load_test_system(SERIAL_PORT)
    await gwy.start(start_discovery=False)  # may: SerialException

    version = await gwy.tcs.get_schedule_version()  # RQ|0006, may: TimeoutError
    version = validate_result(version)

    gwy.config.disable_sending = True
    assert version == await gwy.tcs.get_schedule_version(force_refresh=False)

    try:
        await gwy.tcs.get_schedule_version(force_refresh=True)
    except RuntimeError:  # sending is disabled
        assert True
    else:
        assert False

    await gwy.stop()


async def test_rq_0404():
    def validate_result(schedule):
        # assert isinstance(schedule, list)
        assert len(schedule) == 7

        for idx, day_of_week in enumerate(schedule):
            # assert isinstance(day_of_week, dict)
            assert day_of_week["day_of_week"] == idx

            # assert isinstance(day_of_week["switchpoints"], dict)
            for switchpoint in day_of_week["switchpoints"]:
                assert isinstance(switchpoint["time_of_day"], str)
                assert isinstance(switchpoint["heat_setpoint"], float)

        return schedule

    if not [c for c in list_ports.comports() if c.device == SERIAL_PORT]:
        return

    gwy = await load_test_system(SERIAL_PORT)
    await gwy.start(start_discovery=False)  # may: SerialException

    zone_idx = "01"
    zone = gwy.tcs.zone_by_idx[zone_idx]

    schedule = await zone.get_schedule()  # RQ|0404, may: TimeoutError
    schedule = validate_result(schedule)

    assert zone._schedule._schedule["zone_idx"] == zone.idx == zone_idx
    assert zone._schedule._schedule["schedule"] == zone.schedule == schedule

    gwy.config.disable_sending = True
    assert schedule == await zone.get_schedule(force_refresh=False)

    try:
        await zone.get_schedule(force_refresh=True)
    except RuntimeError:  # sending is disabled
        assert True
    else:
        assert False

    await gwy.stop()
