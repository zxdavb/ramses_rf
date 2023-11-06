#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test faking of Heat devices.
"""

from tests_deprecated.common import (
    TEST_DIR,
    MockGateway,
    abort_if_rf_test_fails,
    find_test_tcs,
    load_test_gwy,
    test_ports,
)

from ramses_rf.const import Code
from ramses_rf.system import System, Zone
from ramses_tx import Command, Message

WORK_DIR = f"{TEST_DIR}/configs"
CONFIG_FILE = "config_heat.json"


def pytest_generate_tests(metafunc):
    metafunc.parametrize("test_port", test_ports.items(), ids=test_ports.keys())


# async def test_dhw_sensor(test_port):  # I/1260 (DHW temp, °C)
# async def test_out_sensor(test_port):  # I/0002 (outside temp, °C)

RQ_ZONE_TEMP_EXPECTED = 10
RP_ZONE_TEMP_EXPECTED = 11
RP_ZONE_TEMP_RECEIVED = 12

PUT_SENSOR_TEMP_EXPECTED = 20
PUT_SENSOR_TEMP_RECEIVED = 21

# NOTE: used as a global
flow_marker: int = None  # type: ignore[assignment]


def track_packet_flow(msg, tcs_id, zone_idx, sensor_id):
    """Test the flow of packets (messages)."""

    global flow_marker

    if msg.code != Code._30C9:
        return

    if msg._pkt._hdr == f"30C9|RQ|{tcs_id}|{zone_idx}":
        assert flow_marker == RQ_ZONE_TEMP_EXPECTED
        flow_marker = RP_ZONE_TEMP_EXPECTED

    elif msg._pkt._hdr == f"30C9|RP|{tcs_id}|{zone_idx}":
        assert flow_marker == RP_ZONE_TEMP_EXPECTED
        flow_marker = RP_ZONE_TEMP_RECEIVED

    elif msg._pkt._hdr == f"30C9| I|{sensor_id}":
        assert flow_marker == PUT_SENSOR_TEMP_EXPECTED
        flow_marker = PUT_SENSOR_TEMP_RECEIVED

    else:
        assert False, msg


async def _test_zon_sensor(gwy, tcs, zone, sensor):
    global flow_marker

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, tcs.id, zone.idx, sensor.id)

    gwy.create_client(track_packet_flow_wrapper)

    flow_marker = RQ_ZONE_TEMP_EXPECTED
    msg_1 = await gwy.async_send_cmd(Command.get_zone_temp(tcs.id, zone.idx))
    assert msg_1 and flow_marker == RP_ZONE_TEMP_RECEIVED

    org_temp: None | float = msg_1.payload["temperature"]
    old_temp: float = 10.01 if org_temp is None else org_temp
    set_temp: float = int((old_temp + 2.33) * 100) % 3500 / 100

    assert zone.temperature == org_temp

    flow_marker = PUT_SENSOR_TEMP_EXPECTED
    msg_2 = await gwy.async_send_cmd(Command.put_sensor_temp(sensor.id, set_temp))
    assert msg_2 and flow_marker == PUT_SENSOR_TEMP_RECEIVED

    flow_marker = RQ_ZONE_TEMP_EXPECTED
    msg_3 = await gwy.async_send_cmd(Command.get_zone_temp(tcs.id, zone.idx))
    assert msg_3 and flow_marker == RP_ZONE_TEMP_RECEIVED

    if isinstance(gwy, MockGateway):  # FIXME: MockCTL needs improving
        return

    assert zone.temperature == set_temp

    # for non-mocked gwy, put things back the way they were?
    if isinstance(gwy, MockGateway) or org_temp is None:
        return

    flow_marker = PUT_SENSOR_TEMP_EXPECTED
    msg_4 = await gwy.async_send_cmd(Command.put_sensor_temp(sensor.id, set_temp))
    assert msg_4 and flow_marker == PUT_SENSOR_TEMP_RECEIVED

    # TODO: doesn't work! ?ignored by CTL as too soon after previous put_sensor_temp
    # assert zone.temperature == org_temp
    pass


@abort_if_rf_test_fails
async def test_zon_sensor(test_port):  # I/30C9 (zone temp, °C)
    """Test zone sensor faking."""

    gwy = await load_test_gwy(*test_port, f"{WORK_DIR}/{CONFIG_FILE}")
    tcs: System = find_test_tcs(gwy)
    zones: list[Zone] = [z for z in tcs.zones if z.sensor and z.sensor is not tcs.ctl]

    try:
        zone = [z for z in zones if z.sensor.is_faked][0]
    except IndexError:
        zone = zones[-1]  # a non-faked zone will do

    if isinstance(gwy, MockGateway):
        sensor = zone.sensor
    else:  # for sensor_id, we rely on the schema being correct, unless we discover:
        cmd_0 = Command.from_attrs(
            # RQ, tcs.ctl.id, Code._000C, f"{zone.idx}{DEV_ROLE.SEN}", from_id=gwy.id
            "RQ",
            tcs.ctl.id,
            Code._000C,
            f"{zone.idx}04",
        )
        msg_0 = await gwy.async_send_cmd(cmd_0)
        sensor = gwy.device_by_id[msg_0.payload["devices"][0]]

    try:
        await _test_zon_sensor(gwy, tcs, zone, sensor)
    finally:
        await gwy.stop()
