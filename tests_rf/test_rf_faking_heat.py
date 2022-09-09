#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test faking of Heat devices.
"""

import asyncio

from ramses_rf.const import Code
from ramses_rf.protocol import Command, Message
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

WORK_DIR = f"{TEST_DIR}/configs"
CONFIG_FILE = "config_heat.json"


def pytest_generate_tests(metafunc):
    metafunc.parametrize("test_port", test_ports.items(), ids=test_ports.keys())


# async def test_dhw_sensor(test_port):  # I/1260 (DHW temp, °C)
# async def test_out_sensor(test_port):  # I/0002 (outside temp, °C)

RQ_ZONE_TEMP_EXPECTED = 10
RP_ZONE_TEMP_EXPECTED = 11
RP_ZONE_TEMP_RECEIVED = 12

PUT_SENSOR_TEMP_EXPECTED = 10
PUT_SENSOR_TEMP_RECEIVED = 11


def track_packet_flow(msg, tcs_id, zone_idx, sensor_id):
    """Test the flow of packets (messages)."""

    global flow_marker

    if msg.code != Code._30C9:
        return

    if msg._pkt._hdr == f"30C9|RQ|{zone_idx}":
        assert flow_marker == RQ_ZONE_TEMP_EXPECTED
        flow_marker = RP_ZONE_TEMP_EXPECTED

    elif msg._pkt._hdr == f"30C9|RP|{zone_idx}":
        assert flow_marker == RP_ZONE_TEMP_EXPECTED
        flow_marker = RP_ZONE_TEMP_RECEIVED

    if msg._pkt._hdr == f"30C9|I_|{tcs_id}":
        assert flow_marker == PUT_SENSOR_TEMP_EXPECTED
        flow_marker = PUT_SENSOR_TEMP_RECEIVED

    else:
        assert False, msg


@abort_if_rf_test_fails
async def test_zon_sensor(test_port):  # I/30C9 (zone temp, °C)
    """Test sensor faking on a faked zone."""

    global flow_marker

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, tcs.id, zone.idx, zone.sensor.id)

    gwy: Gateway | MockGateway = await load_test_gwy(
        *test_port, f"{WORK_DIR}/{CONFIG_FILE}"
    )
    tcs: System = find_test_tcs(gwy)
    zones: list[Zone] = [z for z in tcs.zones if z.sensor and z.sensor is not tcs.ctl]

    try:
        zone = [z for z in zones if z.sensor.is_faked][0]
    except IndexError as exc:
        await gwy.stop()
        if isinstance(gwy, MockGateway):
            raise exc
        return

    flow_marker = RQ_ZONE_TEMP_EXPECTED
    await gwy.async_send_cmd(Command.get_zone_temp(tcs.id, zone.idx))
    await asyncio.sleep(0)
    # assert flow_marker == RP_ZONE_TEMP_RECEIVED

    org_temp: None | float = zone.temperature
    old_temp: float = 10.01 if org_temp is None else org_temp
    new_temp: float = old_temp + 2.33

    flow_marker = PUT_SENSOR_TEMP_EXPECTED
    try:
        # zone.sensor.temperature = new_temp
        await gwy.async_send_cmd(Command.put_sensor_temp(zone.sensor.id, new_temp))
    except RuntimeError:
        assert False
    # assert flow_marker == PUT_SENSOR_TEMP_RECEIVED

    flow_marker = RQ_ZONE_TEMP_EXPECTED
    # get_temp = await gwy.async_send_cmd(Command.get_zone_temp(tcs.id, zone.idx))
    # assert get_temp == new_temp  # TODO
    # assert flow_marker == RP_ZONE_TEMP_RECEIVED

    # for non-mocked gwy, put things back the way they were
    if not isinstance(gwy, MockGateway) and org_temp is not None:
        zone.sensor.temperature = org_temp

    await gwy.stop()
