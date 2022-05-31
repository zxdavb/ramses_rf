#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers and corresponding output (schema, traits, params, status).
"""

import json

from serial.tools import list_ports

from ramses_rf import Gateway
from ramses_rf.const import SZ_SCHEDULE, SZ_TOTAL_FRAGS, SZ_ZONE_IDX, _0006, _0404
from ramses_rf.schedule import (
    DAY_OF_WEEK,
    HEAT_SETPOINT,
    SCHEMA_SCHEDULE,
    SWITCHPOINTS,
    TIME_OF_DAY,
)
from tests.common import TEST_DIR
from tests.mock_gateway import MockGateway

WORK_DIR = f"{TEST_DIR}/rf_engine"

SERIAL_PORT = "/dev/ttyUSB0"


# import tracemalloc
# tracemalloc.start()


async def load_test_system(ser_name, config: dict = None) -> Gateway:
    """Create a system state from a packet log (using an optional configuration)."""

    with open(f"{WORK_DIR}/config.json") as f:
        kwargs = json.load(f)

    if config:
        kwargs.update(config)

    if [c for c in list_ports.comports() if c.device == SERIAL_PORT]:
        gwy = Gateway(ser_name, **kwargs)
    else:
        gwy = MockGateway(ser_name, **kwargs)

    return gwy


def assert_schedule_dict(schedule):
    if schedule is None:
        # schedule = [{DAY_OF_WEEK: i, SWITCHPOINTS: []} for i in range(7)]
        return

    _ = SCHEMA_SCHEDULE(schedule)

    # assert isinstance(schedule, list)
    assert len(schedule) == 7

    for idx, day_of_week in enumerate(schedule):
        # assert isinstance(day_of_week, dict)
        assert day_of_week[DAY_OF_WEEK] == idx

        # assert isinstance(day_of_week[SWITCHPOINTS], dict)
        for switchpoint in day_of_week[SWITCHPOINTS]:
            assert isinstance(switchpoint[TIME_OF_DAY], str)
            assert isinstance(switchpoint[HEAT_SETPOINT], float)

    return schedule


async def write_schedule(zone, schedule) -> None:
    zone._gwy.config.disable_sending = False
    _ = await zone.set_schedule(schedule)  # RQ|0404, may: TimeoutError


async def read_schedule(zone) -> dict:

    zone._gwy.config.disable_sending = False
    schedule = await zone.get_schedule()  # RQ|0404, may: TimeoutError
    schedule = assert_schedule_dict(schedule)

    if schedule is None:  # TODO: remove?
        assert zone._msgs[_0404].payload[SZ_TOTAL_FRAGS] == 255
        return

    assert zone._schedule._schedule[SZ_ZONE_IDX] == zone.idx
    assert zone._schedule._schedule[SZ_SCHEDULE] == zone.schedule == schedule

    zone._gwy.config.disable_sending = True
    assert schedule == await zone.get_schedule(force_io=False)

    try:
        await zone.get_schedule(force_io=True)
    except RuntimeError:  # sending is disabled
        assert True
    else:
        assert False

    return schedule


async def test_rq_0006():
    def assert_version(version):
        assert isinstance(version, int)
        assert version == gwy.tcs._msgs[_0006].payload["change_counter"]

        return version

    gwy = await load_test_system(SERIAL_PORT, config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    # gwy.config.disable_sending = False
    version, _ = await gwy.tcs._schedule_version()  # RQ|0006, may: TimeoutError
    version = assert_version(version)

    gwy.config.disable_sending = True
    assert version == (await gwy.tcs._schedule_version(force_io=False))[0]

    try:
        await gwy.tcs._schedule_version(force_io=True)
    except RuntimeError:  # sending is disabled
        assert True
    else:
        assert False

    gwy.config.disable_sending = False
    version, _ = await gwy.tcs._schedule_version()  # RQ|0006, may: TimeoutError
    version = assert_version(version)

    # await asyncio.sleep(30)
    await gwy.stop()


async def _test_rq_0404_dhw():

    gwy = await load_test_system(SERIAL_PORT, config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if gwy.tcs.dhw:
        await read_schedule(gwy.tcs.dhw)

    await gwy.stop()


async def test_rq_0404_zone():

    gwy = await load_test_system(SERIAL_PORT, config={"disable_dicovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if gwy.tcs.zones:
        await read_schedule(gwy.tcs.zones[0])
    #     await write_schedule(gwy.tcs.zones[0], schedule)

    await gwy.stop()


async def _test_w_0404_zone():

    gwy = await load_test_system(SERIAL_PORT, config={"disable_dicovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if gwy.tcs.zones:
        await write_schedule(gwy.tcs.zones[0])

    await gwy.stop()
