#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers and corresponding output (schema, traits, params, status).
"""

import asyncio
import json

from serial.tools import list_ports

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


# async def test_dhw_sensor():  # I/1260
#     pass


# async def test_fan_mode():  # I/22F1
#     pass


# async def test_weather_sensor():  # I/0002
#     pass


async def test_zone_sensor():  # I/30C9

    # TODO: test mocked zone (not sensor) temp (i.e. at MockDeviceCtl)

    gwy, tcs = await load_test_system(config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    zone = tcs.zones[0]

    if SERIAL_PORT != "/dev/ttyMOCK" and zone.sensor is None:  # gwy.ser_name == ...
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


async def test_zone_sensor_unfaked():  # I/30C9

    gwy, tcs = await load_test_system(config={"disable_discovery": True})
    await gwy.start(start_discovery=False)  # may: SerialException

    zone = tcs.zones[0]

    if SERIAL_PORT != "/dev/ttyMOCK" and zone.sensor is None:  # gwy.ser_name == ...
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
