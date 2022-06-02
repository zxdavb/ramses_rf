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


def assert_schedule_dict(schedule_full):
    if schedule_full is None:
        # schedule = [{DAY_OF_WEEK: i, SWITCHPOINTS: []} for i in range(7)]
        return

    if schedule_full[SZ_ZONE_IDX] == "HW":
        SCHEMA_SCHEDULE_DHW(schedule_full)
    else:
        SCHEMA_SCHEDULE_ZON(schedule_full)

    schedule = schedule_full[SZ_SCHEDULE]
    # assert isinstance(schedule, list)
    assert len(schedule) == 7

    for idx, day_of_week in enumerate(schedule):
        # assert isinstance(day_of_week, dict)
        assert day_of_week[DAY_OF_WEEK] == idx

        # assert isinstance(day_of_week[SWITCHPOINTS], dict)
        for switchpoint in day_of_week[SWITCHPOINTS]:
            assert isinstance(switchpoint[TIME_OF_DAY], str)
            if HEAT_SETPOINT in switchpoint:
                assert isinstance(switchpoint[HEAT_SETPOINT], float)
            else:
                assert isinstance(switchpoint[ENABLED], bool)
    return schedule


async def write_schedule(zone) -> None:

    zone._gwy.config.disable_sending = False
    schedule_0 = await zone.get_schedule()  # RQ|0404, may: TimeoutError

    schedule_1 = deepcopy(schedule_0)

    if zone.idx == "HW":
        schedule_1[0][SWITCHPOINTS][0][ENABLED] = not (
            schedule_1[0][SWITCHPOINTS][0][ENABLED]
        )
    else:
        schedule_1[0][SWITCHPOINTS][0][HEAT_SETPOINT] = (
            schedule_1[0][SWITCHPOINTS][0][HEAT_SETPOINT] + 1
        )

    _ = await zone.set_schedule(schedule_1)  # RQ|0404, may: TimeoutError
    schedule_3 = await zone.get_schedule()

    assert schedule_1 == schedule_3


async def read_schedule(zone) -> dict:

    zone._gwy.config.disable_sending = False
    schedule = await zone.get_schedule()  # RQ|0404, may: TimeoutError
    schedule = assert_schedule_dict(zone._schedule._schedule)

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
        assert version == tcs._msgs[_0006].payload["change_counter"]
        return version

    gwy, tcs = await load_test_system(config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    # gwy.config.disable_sending = False
    version, _ = await tcs._schedule_version()  # RQ|0006, may: TimeoutError
    version = assert_version(version)

    gwy.config.disable_sending = True
    assert version == (await tcs._schedule_version(force_io=False))[0]

    try:
        await tcs._schedule_version(force_io=True)
    except RuntimeError:  # sending is disabled
        assert True
    else:
        assert False

    gwy.config.disable_sending = False
    version, _ = await tcs._schedule_version()  # RQ|0006, may: TimeoutError
    version = assert_version(version)

    # await asyncio.sleep(30)
    await gwy.stop()


async def test_rq_0404_dhw():

    gwy, tcs = await load_test_system(config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if tcs.dhw:
        await read_schedule(tcs.dhw)

    await gwy.stop()


async def test_rq_0404_zone():

    gwy, tcs = await load_test_system(config={"disable_dicovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if tcs.zones:
        await read_schedule(tcs.zones[0])

    await gwy.stop()


async def test_ww_0404_zone():

    gwy, tcs = await load_test_system(config={"disable_dicovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if tcs.zones:
        await write_schedule(tcs.zones[0])

    await gwy.stop()
