#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test faking of HVAC devices.
"""

import asyncio
import json

from serial.tools import list_ports

from ramses_rf.device import HvacRemote, HvacVentilator
from tests.common import TEST_DIR
from tests.mock import FAN_ID, MOCKED_PORT, MockDeviceFan

# import tracemalloc
# tracemalloc.start()


WORK_DIR = f"{TEST_DIR}/rf_engine"
CONFIG_FILE = "config_hvac.json"


if ports := [
    c for c in list_ports.comports() if c.device[-7:-1] in ("ttyACM", "ttyUSB")
]:
    from ramses_rf import Gateway

    SERIAL_PORT = ports[0].device
    FAN_ID = "32:155617"  # noqa: F811

else:
    from tests.mock import MockGateway as Gateway

    SERIAL_PORT = MOCKED_PORT  # FAN_ID = FAN_ID


async def load_test_system(config: dict = None) -> Gateway:
    """Create a system state from a packet log (using an optional configuration)."""

    with open(f"{WORK_DIR}/{CONFIG_FILE}") as f:
        kwargs = json.load(f)

    if config:
        kwargs.update(config)

    gwy = Gateway(SERIAL_PORT, **kwargs)
    await gwy.start(start_discovery=False)  # may: SerialException

    if hasattr(
        gwy.pkt_transport.serial, "mock_devices"
    ):  # needs ser instance, so after gwy.start()
        gwy.pkt_transport.serial.mock_devices = [MockDeviceFan(gwy, FAN_ID)]

    return gwy  # , gwy.system_by_id[CTL_ID]


def find_test_devices(gwy: Gateway) -> tuple[HvacRemote, HvacVentilator]:

    try:
        fan = [d for d in gwy.devices if d._SLUG == "FAN"][0]
    except IndexError:
        fan = None

    try:
        rem = [d for d in gwy.devices if d._SLUG == "REM"][0]
    except IndexError:
        rem = None

    return rem, fan


async def test_fan_mode():  # I/22F1

    # TODO: test mocked zone (not sensor) temp (i.e. at MockDeviceCtl)

    gwy = await load_test_system(config={"disable_discovery": True})
    rem, fan = find_test_devices(gwy)

    # TODO: remove this block when can assure zone.sensor is not None
    if SERIAL_PORT != MOCKED_PORT and rem is None:
        await gwy.stop()
        return

    org_rate = fan.fan_info  # may be None
    org_rate = 19.5 if org_rate is None else org_rate  # HACK

    rem.fan_rate = old_temp - 0.5

    await asyncio.sleep(0.5)  # 0.3 is too low
    new_rate = fan.fan_info
    assert new_rate == old_rate - 0.5, f"new: {new_rate}, old: {old_rate}"

    # await gwy.async_send_cmd(Command.get_zone_temp(tcs.id, zone.idx))
    # zon_temp = zone.temperature
    # assert zon_temp == old_temp - 0.5, f"new: {new_temp}, old: {old_temp}"

    rem.fan_rate = old_temp

    await asyncio.sleep(0.5)  # 0.3 is too low
    new_temp = zone.sensor.temperature
    assert new_temp == old_temp, f"new: {new_temp}, old: {old_temp}"

    # await gwy.async_send_cmd(Command.get_zone_temp(tcs.id, zone.idx))
    # zon_temp = zone.temperature
    # assert zon_temp == old_temp - 0.5, f"new: {new_temp}, old: {old_temp}"

    await gwy.stop()


# async def test_co2_sensor():  # I/1298
# async def test_rh_sensor():  # I/12A0


async def test_fan_mode_unfaked():  # I/22F1

    gwy = await load_test_system(config={"disable_discovery": True})
    rem, fan = find_test_devices(gwy)

    # TODO: remove this block when can assure zone.sensor is not None
    if SERIAL_PORT != MOCKED_PORT and rem is None:
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
