#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test faking of Heat devices.
"""

import asyncio

from ramses_rf.system import System, Zone
from tests_rf.common import (
    TEST_DIR,
    Gateway,
    MockGateway,
    abort_if_rf_test_fails,
    find_test_tcs,
    load_test_gwy,
    test_ports,
)

WORK_DIR = f"{TEST_DIR}/rf_engine"
CONFIG_FILE = "config_heat.json"


def pytest_generate_tests(metafunc):
    metafunc.parametrize("test_port", test_ports.items())


def find_test_zone(gwy: Gateway) -> tuple[System, Zone]:

    tcs = find_test_tcs(gwy)
    return tcs, tcs.zone_by_idx["01"]


@abort_if_rf_test_fails
async def test_zon_sensor(test_port):  # I/30C9 (zone temp, 'C)

    # TODO: test mocked zone (not sensor) temp (i.e. at MockDeviceCtl)

    gwy = await load_test_gwy(*test_port, f"{WORK_DIR}/{CONFIG_FILE}")
    _, zone = find_test_zone(gwy)

    # TODO: remove this block when can assure zone.sensor is not None
    if not isinstance(gwy, MockGateway) and zone.sensor is None:
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


@abort_if_rf_test_fails
async def test_zon_sensor_unfaked(test_port):  # I/30C9
    gwy = await load_test_gwy(*test_port, f"{WORK_DIR}/{CONFIG_FILE}")
    _, zone = find_test_zone(gwy)

    # TODO: remove this block when can assure zone.sensor is not None
    if not isinstance(gwy, MockGateway) and zone.sensor is None:
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
