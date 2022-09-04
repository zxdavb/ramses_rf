#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test CH/DHW schedules with a mocked controller.
"""

from copy import deepcopy

from ramses_rf.const import SZ_SCHEDULE, SZ_TOTAL_FRAGS, SZ_ZONE_IDX, Code
from ramses_rf.protocol import Message
from ramses_rf.system import DhwZone, System, Zone
from ramses_rf.system.schedule import (
    DAY_OF_WEEK,
    ENABLED,
    HEAT_SETPOINT,
    SCH_SCHEDULE_DHW,
    SCH_SCHEDULE_ZON,
    SWITCHPOINTS,
    TIME_OF_DAY,
)
from tests_rf.common import (
    TEST_DIR,
    abort_if_rf_test_fails,
    find_test_tcs,
    load_test_gwy,
    test_ports,
)
from tests_rf.mock import MOCKED_PORT

WORK_DIR = f"{TEST_DIR}/rf_engine"
CONFIG_FILE = "config_heat.json"


def pytest_generate_tests(metafunc):
    metafunc.parametrize("test_port", test_ports.items(), ids=test_ports.keys())


RQ_0006_EXPECTED = 10
RP_0006_EXPECTED = 11
RP_0006_RECEIVED = 12

RQ_0404_FIRST_EXPECTED = 20
RP_0404_FIRST_EXPECTED = 21
RQ_0404_OTHER_EXPECTED = 22
RP_0404_OTHER_EXPECTED = 23
RP_0404_FINAL_RECEIVED = 24

W__0404_FIRST_EXPECTED = 30
I__0404_FIRST_EXPECTED = 31
W__0404_OTHER_EXPECTED = 32
I__0404_OTHER_EXPECTED = 33
I__0404_FINAL_RECEIVED = 34

# NOTE: used as a global
flow_marker: int = None  # type: ignore[assignment]


def track_packet_flow(msg, tcs_id, zone_idx=None):
    """Test the flow of packets (messages)."""

    global flow_marker

    if msg.code not in (Code._0006, Code._0404):
        return

    # get the schedule version number
    if msg._pkt._hdr == f"0006|RQ|{tcs_id}":
        assert flow_marker == RQ_0006_EXPECTED
        flow_marker = RP_0006_EXPECTED

    elif msg._pkt._hdr == f"0006|RP|{tcs_id}":
        assert flow_marker == RP_0006_EXPECTED
        flow_marker = RP_0006_RECEIVED  # RQ_0404_FIRST_EXPECTED

    # get the first schedule fragment, is possibly the last fragment too
    elif msg._pkt._hdr == f"0404|RQ|{tcs_id}|{zone_idx}01":
        assert flow_marker in (RQ_0404_FIRST_EXPECTED, RP_0006_RECEIVED)
        flow_marker = RP_0404_FIRST_EXPECTED

    elif msg._pkt._hdr == f"0404|RP|{tcs_id}|{zone_idx}01":
        assert flow_marker == RP_0404_FIRST_EXPECTED
        if msg.payload["frag_number"] < msg.payload["total_frags"]:
            flow_marker = RQ_0404_OTHER_EXPECTED
        else:
            flow_marker = RP_0404_FINAL_RECEIVED

    # get the subsequent schedule fragments, until the last fragment
    elif msg._pkt._hdr[:20] == f"0404|RQ|{tcs_id}|{zone_idx}":
        assert flow_marker == RQ_0404_OTHER_EXPECTED
        flow_marker = RP_0404_OTHER_EXPECTED

    elif msg._pkt._hdr[:20] == f"0404|RP|{tcs_id}|{zone_idx}":
        assert flow_marker == RP_0404_OTHER_EXPECTED
        if msg.payload["frag_number"] < msg.payload["total_frags"]:
            flow_marker = RQ_0404_OTHER_EXPECTED
        else:
            flow_marker = RP_0404_FINAL_RECEIVED

    # set the first schedule fragment, is possibly the last fragment too
    elif msg._pkt._hdr == f"0404| W|{tcs_id}|{zone_idx}01":
        assert flow_marker in (
            W__0404_FIRST_EXPECTED,
            RP_0006_RECEIVED,
            RP_0404_FINAL_RECEIVED,
        )
        flow_marker = I__0404_FIRST_EXPECTED

    elif msg._pkt._hdr == f"0404| I|{tcs_id}|{zone_idx}01":
        assert flow_marker == I__0404_FIRST_EXPECTED
        if msg.payload["frag_number"] < msg.payload["total_frags"]:
            flow_marker = W__0404_OTHER_EXPECTED
        else:
            flow_marker = I__0404_FINAL_RECEIVED

    # set the subsequent schedule fragments, until the last fragment
    elif msg._pkt._hdr[:20] == f"0404| W|{tcs_id}|{zone_idx}":
        assert flow_marker == W__0404_OTHER_EXPECTED
        flow_marker = I__0404_OTHER_EXPECTED

    elif msg._pkt._hdr[:20] == f"0404| I|{tcs_id}|{zone_idx}":
        assert flow_marker == I__0404_OTHER_EXPECTED
        if msg.payload["frag_number"] < msg.payload["total_frags"]:
            flow_marker = W__0404_OTHER_EXPECTED
        else:
            flow_marker = I__0404_FINAL_RECEIVED

    else:
        assert False, msg


def assert_schedule_dict(zone: DhwZone | Zone):

    schedule_full = zone._schedule._schedule

    assert schedule_full[SZ_ZONE_IDX] == zone.idx
    assert schedule_full[SZ_SCHEDULE] == zone.schedule

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


async def read_schedule(zone: DhwZone | Zone) -> list:  # uses: flow_marker
    """Test the get_schedule() method for a Zone or for DHW."""

    # [{  'day_of_week': 0,
    #     'switchpoints': [{'time_of_day': '06:30', 'heat_setpoint': 21.0}, ...], }]

    global flow_marker

    # zone._gwy.config.disable_sending = False

    flow_marker = RQ_0006_EXPECTED
    schedule = await zone.get_schedule()  # RQ|0404, may: TimeoutError
    assert flow_marker == RP_0404_FINAL_RECEIVED

    if not schedule:  # valid test?
        assert zone._msgs[Code._0404].payload[SZ_TOTAL_FRAGS] is None
        return []

    schedule = assert_schedule_dict(zone)

    zone._gwy.config.disable_sending = True

    flow_marker = RQ_0006_EXPECTED
    assert schedule == await zone.get_schedule(force_io=False)
    assert flow_marker == RQ_0006_EXPECTED

    try:
        await zone.get_schedule(force_io=True)
    except RuntimeError:  # sending is disabled
        assert True
    else:
        assert False

    return schedule


async def read_schedule_ver(tcs: System) -> list:  # uses: flow_marker
    """Test the get_schedule() method for a Zone or for DHW."""

    global flow_marker

    flow_marker = RQ_0006_EXPECTED
    ver = (await tcs._schedule_version())[0]  # RQ|0006, may: TimeoutError
    assert flow_marker == RP_0006_RECEIVED

    assert isinstance(ver, int)
    assert ver == tcs._msgs[Code._0006].payload["change_counter"]

    flow_marker = RQ_0006_EXPECTED  # actually, is not expected
    assert ver == (await tcs._schedule_version(force_io=False))[0]
    assert flow_marker == RQ_0006_EXPECTED

    ver = (await tcs._schedule_version(force_io=True))[0]  # RQ|0006, may: TimeoutError
    assert flow_marker == RP_0006_RECEIVED

    tcs._gwy.config.disable_sending = True

    flow_marker = RQ_0006_EXPECTED  # actually, is not expected
    ver = (await tcs._schedule_version())[0]  # RQ|0006, may: TimeoutError
    assert flow_marker == RQ_0006_EXPECTED

    try:
        await tcs._schedule_version(force_io=True)
    except RuntimeError:  # sending is disabled
        pass
    else:
        assert False


async def write_schedule(zone: DhwZone | Zone) -> None:  # uses: flow_marker
    """Test the set_schedule() method for a Zone or for DHW."""

    # FYI: [{  'day_of_week': 0,
    #     'switchpoints': [{'time_of_day': '06:30', 'heat_setpoint': 21.0}, ...], }]

    global flow_marker

    # zone._gwy.config.disable_sending = False

    flow_marker = RQ_0006_EXPECTED  # because of force_io=True
    ver_old, _ = await zone.tcs._schedule_version(force_io=True)
    assert flow_marker == RP_0006_RECEIVED

    sch_old = await zone.get_schedule()
    assert flow_marker == RP_0404_FINAL_RECEIVED

    sch_new = deepcopy(sch_old)

    # if zone._gwy.pkt_transport.serial.port == MOCKED_PORT:
    #     # change the schedule (doesn't matter to what)
    #     if zone.idx == "HW":
    #         sch_new[0][SWITCHPOINTS][0][ENABLED] = not (
    #             sch_new[0][SWITCHPOINTS][0][ENABLED]
    #         )
    #     else:
    #         sch_new[0][SWITCHPOINTS][0][HEAT_SETPOINT] = (
    #             sch_new[0][SWITCHPOINTS][0][HEAT_SETPOINT]
    #         ) % 30 + 5

    _ = await zone.set_schedule(sch_new)  # check zone._schedule._schedule
    assert flow_marker == I__0404_FINAL_RECEIVED

    flow_marker = RQ_0006_EXPECTED  # because of force_io=True
    ver_tst, _ = await zone.tcs._schedule_version(force_io=True)  # TODO: force_io=False
    assert flow_marker == RP_0006_RECEIVED

    assert ver_tst > ver_old

    flow_marker = RQ_0006_EXPECTED
    sch_tst = await zone.get_schedule()  # will use latest I/RP|0006
    assert flow_marker == RQ_0006_EXPECTED

    sch_tst = await zone.get_schedule(force_io=True)  # will force RQ|0006
    assert flow_marker == RP_0006_RECEIVED

    assert sch_tst == sch_new
    # if zone._gwy.pkt_transport.serial.port == MOCKED_PORT:
    #     assert sch_tst != sch_old
    #    sch_end = await zone.set_schedule(sch_old)  # put things back


@abort_if_rf_test_fails
async def test_rq_0006_ver(test_port):
    """Test the TCS._schedule_version() method."""

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, tcs.id)

    gwy = await load_test_gwy(*test_port, f"{WORK_DIR}/{CONFIG_FILE}")
    gwy.create_client(track_packet_flow_wrapper)

    tcs: System = find_test_tcs(gwy)

    try:
        await read_schedule_ver(tcs)
    finally:
        await gwy.stop()


@abort_if_rf_test_fails
async def test_rq_0404_dhw(test_port):
    """Test the dhw.get_schedule() method."""

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, tcs.id, dhw.idx)

    gwy = await load_test_gwy(*test_port, f"{WORK_DIR}/{CONFIG_FILE}")
    gwy.create_client(track_packet_flow_wrapper)

    tcs: System = find_test_tcs(gwy)
    dhw: DhwZone = tcs.dhw

    try:
        if dhw or test_port[0] == MOCKED_PORT:  # mocked port should have DHW
            await read_schedule(dhw)
    finally:
        await gwy.stop()


@abort_if_rf_test_fails
async def test_rq_0404_zon(test_port):
    """Test the zone.get_schedule() method."""

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, tcs.id, zon.idx)

    gwy = await load_test_gwy(*test_port, f"{WORK_DIR}/{CONFIG_FILE}")
    gwy.create_client(track_packet_flow_wrapper)

    tcs: System = find_test_tcs(gwy)
    zon: Zone = tcs.zones[0]

    try:
        # if zon:
        await read_schedule(zon)
    finally:
        await gwy.stop()


@abort_if_rf_test_fails
async def test_ww_0404_dhw(test_port):
    """Test the dhw.set_schedule() method (uses get_schedule)."""

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, tcs.id, dhw.idx)

    gwy = await load_test_gwy(*test_port, f"{WORK_DIR}/{CONFIG_FILE}")
    gwy.create_client(track_packet_flow_wrapper)

    tcs: System = find_test_tcs(gwy)
    dhw: DhwZone = tcs.dhw

    try:
        if dhw or test_port[0] == MOCKED_PORT:  # mocked port should have DHW
            await write_schedule(dhw)
    finally:
        await gwy.stop()


@abort_if_rf_test_fails
async def test_ww_0404_zon(test_port):
    """Test the zone.set_schedule() method (uses get_schedule)."""

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, tcs.id, zon.idx)

    gwy = await load_test_gwy(*test_port, f"{WORK_DIR}/{CONFIG_FILE}")
    gwy.create_client(track_packet_flow_wrapper)

    tcs: System = find_test_tcs(gwy)
    zon: Zone = tcs.zones[0]

    try:
        # if zon:
        await write_schedule(zon)
    finally:
        await gwy.stop()
