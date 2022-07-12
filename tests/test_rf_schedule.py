#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers and corresponding output (schema, traits, params, status).
"""

import json
from copy import deepcopy

from serial.tools import list_ports

from ramses_rf.const import SZ_SCHEDULE, SZ_TOTAL_FRAGS, SZ_ZONE_IDX, Codx
from ramses_rf.system.schedule import (
    DAY_OF_WEEK,
    ENABLED,
    HEAT_SETPOINT,
    SCH_SCHEDULE_DHW,
    SCH_SCHEDULE_ZON,
    SWITCHPOINTS,
    TIME_OF_DAY,
)
from tests.common import TEST_DIR

# import tracemalloc
# tracemalloc.start()


WORK_DIR = f"{TEST_DIR}/rf_engine"


if ports := [
    c for c in list_ports.comports() if c.device[-7:-1] in ("ttyACM", "ttyUSB")
]:
    from ramses_rf import Gateway

    SERIAL_PORT = ports[0].device
    GWY_ID = "01:145038"

else:
    from tests.mock_gateway import MockGateway as Gateway

    SERIAL_PORT = "/dev/ttyMOCK"
    GWY_ID = "01:000730"


async def load_test_system(config: dict = None) -> Gateway:
    """Create a system state from a packet log (using an optional configuration)."""

    with open(f"{WORK_DIR}/config.json") as f:
        kwargs = json.load(f)

    if config:
        kwargs.update(config)

    gwy = Gateway(SERIAL_PORT, **kwargs)

    return gwy, gwy.system_by_id[GWY_ID]


def assert_schedule_dict(schedule_full):

    if schedule_full[SZ_ZONE_IDX] == "HW":
        SCH_SCHEDULE_DHW(schedule_full)
    else:
        SCH_SCHEDULE_ZON(schedule_full)

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

    # zone._gwy.config.disable_sending = False

    ver_old, _ = await zone.tcs._schedule_version(force_io=True)
    sch_old = await zone.get_schedule()

    sch_new = deepcopy(sch_old)

    if zone.idx == "HW":
        sch_new[0][SWITCHPOINTS][0][ENABLED] = not (
            sch_new[0][SWITCHPOINTS][0][ENABLED]
        )
    else:
        sch_new[0][SWITCHPOINTS][0][HEAT_SETPOINT] = (
            sch_new[0][SWITCHPOINTS][0][HEAT_SETPOINT] + 1
        ) % 5 + 6

    _ = await zone.set_schedule(sch_new)  # check zone._schedule._schedule

    ver_tst, _ = await zone.tcs._schedule_version(force_io=True)
    sch_tst = await zone.get_schedule()

    assert ver_old < ver_tst

    assert sch_tst != sch_old
    assert sch_tst == sch_new

    sch_end = await zone.set_schedule(sch_old)  # put things back

    assert zone._gwy.pkt_transport.serial.port == "/dev/ttyMOCK" or (sch_end == sch_old)


async def read_schedule(zone) -> dict:

    # zone._gwy.config.disable_sending = False

    schedule = await zone.get_schedule()  # RQ|0404, may: TimeoutError

    if schedule is None:
        assert zone._msgs[Codx._0404].payload[SZ_TOTAL_FRAGS] is None
        return

    schedule = assert_schedule_dict(zone._schedule._schedule)

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
        assert version == tcs._msgs[Codx._0006].payload["change_counter"]
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

    await gwy.stop()


async def test_0404_dhw():  # Needs mocking

    if SERIAL_PORT == "/dev/ttyMOCK":
        return

    gwy, tcs = await load_test_system(config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if tcs.dhw:
        await read_schedule(tcs.dhw)

    await gwy.stop()


async def test_0404_zone():

    gwy, tcs = await load_test_system(config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if tcs.zones:
        await read_schedule(tcs.zones[0])

    await gwy.stop()


async def _test_ww_0404_dhw():

    gwy, tcs = await load_test_system(config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if tcs.dhw:
        await write_schedule(tcs.dhw)

    await gwy.stop()


async def _test_ww_0404_zone():

    gwy, tcs = await load_test_system(config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    if tcs.zones:
        await write_schedule(tcs.zones[0])

    await gwy.stop()
