#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test faking of Heat devices.
"""

import asyncio

from ramses_rf.system import System, Zone

#
from tests.common import SERIAL_PORT, TEST_DIR, Gateway
from tests.common import load_test_system_alt as load_test_system
from tests.mock import CTL_ID, MOCKED_PORT

WORK_DIR = f"{TEST_DIR}/rf_engine"
CONFIG_FILE = "config_heat.json"


def find_test_zone(gwy: Gateway) -> tuple[System, Zone]:

    tcs = gwy.system_by_id[CTL_ID]
    return tcs, tcs.zones[0]


async def test_zon_sensor():  # I/30C9 (zone temp, 'C)

    # TODO: test mocked zone (not sensor) temp (i.e. at MockDeviceCtl)

    gwy = await load_test_system(f"{WORK_DIR}/{CONFIG_FILE}")
    _, zone = find_test_zone(gwy)

    # TODO: remove this block when can assure zone.sensor is not None
    if SERIAL_PORT != MOCKED_PORT and zone.sensor is None:
        await gwy.stop()
        return

    org_temp = zone.temperature  # may be None
    old_temp = 19.5 if org_temp is None else org_temp  # HACK

    zone.sensor.temperature = old_temp - 0.5

    await asyncio.sleep(0.5)  # 0.3 is too low
    new_temp = zone.sensor.temperature
    assert new_temp == old_temp - 0.5, f"new: {new_temp}, old: {old_temp}"

    # await gwy.async_send_cmd(Command.get_zone_temp(tcs.id, zone.idx))
    # zon_temp = zone.temperature
    # assert zon_temp == old_temp - 0.5, f"new: {new_temp}, old: {old_temp}"

    zone.sensor.temperature = old_temp

    await asyncio.sleep(0.5)  # 0.3 is too low
    new_temp = zone.sensor.temperature
    assert new_temp == old_temp, f"new: {new_temp}, old: {old_temp}"

    # await gwy.async_send_cmd(Command.get_zone_temp(tcs.id, zone.idx))
    # zon_temp = zone.temperature
    # assert zon_temp == old_temp - 0.5, f"new: {new_temp}, old: {old_temp}"

    await gwy.stop()


# async def test_dhw_sensor():  # I/1260 (DHW temp, 'C)
# async def test_out_sensor():  # I/0002 (outside temp, 'C)


async def test_zon_sensor_unfaked():  # I/30C9

    gwy = await load_test_system(f"{WORK_DIR}/{CONFIG_FILE}")
    tcs = gwy.system_by_id[CTL_ID]
    zone = tcs.zones[0]

    # TODO: remove this block when can assure zone.sensor is not None
    if SERIAL_PORT != MOCKED_PORT and zone.sensor is None:
        await gwy.stop()
        return

    org_temp = zone.temperature  # may be None
    old_temp = 19.5 if org_temp is None else org_temp  # HACK

    zone.sensor._faked = True
    try:
        zone.sensor.temperature = old_temp - 0.5
    except RuntimeError:
        assert False

    zone.sensor._faked = False
    try:
        zone.sensor.temperature = old_temp - 0.5
    except RuntimeError:
        pass
    else:
        assert False

    await gwy.stop()
