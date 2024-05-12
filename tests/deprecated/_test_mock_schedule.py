#!/usr/bin/env python3
"""RAMSES RF - Test CH/DHW schedules with a mocked controller."""

from copy import deepcopy
from unittest.mock import patch

from .common import (
    TEST_DIR,
    abort_if_rf_test_fails,
    find_test_tcs,
    load_test_gwy,
    test_ports,
)
from .mocked_devices import MOCKED_PORT

from ramses_rf.const import SZ_SCHEDULE, SZ_TOTAL_FRAGS, SZ_ZONE_IDX, Code
from ramses_rf.system import DhwZone, System, Zone
from ramses_rf.system.schedule import (
    SZ_DAY_OF_WEEK,
    SZ_ENABLED,
    SZ_HEAT_SETPOINT,
    SCH_SCHEDULE_DHW_OUTER,
    SCH_SCHEDULE_ZON_OUTER,
    SZ_SWITCHPOINTS,
    SZ_TIME_OF_DAY,
)
from ramses_tx import Message

WORK_DIR = f"{TEST_DIR}/configs"
CONFIG_FILE = "config_heat.json"


def pytest_generate_tests(metafunc):
    metafunc.parametrize("test_port", test_ports.items(), ids=test_ports.keys())


# NOTE: used as a global
_global_flow_marker: int = None  # type: ignore[assignment]


MIN_INTER_WRITE_GAP = 0  #  patch ramses_tx.transport
WAITING_TIMEOUT_SECS = 0  # patch ramses_rf.binding_fsm


RQ_0006_EXPECTED = 20
RP_0006_EXPECTED = 22
RP_0006_RECEIVED = 29

RQ_0404_FIRST_EXPECTED = 40
RP_0404_FIRST_EXPECTED = 42
RQ_0404_OTHER_EXPECTED = 44
RP_0404_OTHER_EXPECTED = 46
RP_0404_FINAL_RECEIVED = 49

W__0404_FIRST_EXPECTED = 60
I__0404_FIRST_EXPECTED = 62
W__0404_OTHER_EXPECTED = 64
I__0404_OTHER_EXPECTED = 66
I__0404_FINAL_RECEIVED = 69


def track_packet_flow(msg, tcs_id, zone_idx=None):
    """Test the flow of packets (messages)."""

    global _global_flow_marker

    if msg.code not in (Code._0006, Code._0404):
        return

    # get the schedule version number
    if msg._pkt._hdr == f"0006|RQ|{tcs_id}":
        assert _global_flow_marker == RQ_0006_EXPECTED
        _global_flow_marker = RP_0006_EXPECTED

    elif msg._pkt._hdr == f"0006|RP|{tcs_id}":
        assert _global_flow_marker == RP_0006_EXPECTED
        _global_flow_marker = RP_0006_RECEIVED  # RQ_0404_FIRST_EXPECTED

    # get the first schedule fragment, is possibly the last fragment too
    elif msg._pkt._hdr == f"0404|RQ|{tcs_id}|{zone_idx}01":
        assert _global_flow_marker in (RQ_0404_FIRST_EXPECTED, RP_0006_RECEIVED)
        _global_flow_marker = RP_0404_FIRST_EXPECTED

    elif msg._pkt._hdr == f"0404|RP|{tcs_id}|{zone_idx}01":
        assert _global_flow_marker == RP_0404_FIRST_EXPECTED
        if msg.payload["frag_number"] < msg.payload["total_frags"]:
            _global_flow_marker = RQ_0404_OTHER_EXPECTED
        else:
            _global_flow_marker = RP_0404_FINAL_RECEIVED

    # get the subsequent schedule fragments, until the last fragment
    elif msg._pkt._hdr[:20] == f"0404|RQ|{tcs_id}|{zone_idx}":
        assert _global_flow_marker == RQ_0404_OTHER_EXPECTED
        _global_flow_marker = RP_0404_OTHER_EXPECTED

    elif msg._pkt._hdr[:20] == f"0404|RP|{tcs_id}|{zone_idx}":
        assert _global_flow_marker == RP_0404_OTHER_EXPECTED
        if msg.payload["frag_number"] < msg.payload["total_frags"]:
            _global_flow_marker = RQ_0404_OTHER_EXPECTED
        else:
            _global_flow_marker = RP_0404_FINAL_RECEIVED

    # set the first schedule fragment, is possibly the last fragment too
    elif msg._pkt._hdr == f"0404| W|{tcs_id}|{zone_idx}01":
        assert _global_flow_marker in (
            W__0404_FIRST_EXPECTED,
            RP_0006_RECEIVED,
            RP_0404_FINAL_RECEIVED,
        )
        _global_flow_marker = I__0404_FIRST_EXPECTED

    elif msg._pkt._hdr == f"0404| I|{tcs_id}|{zone_idx}01":
        assert _global_flow_marker == I__0404_FIRST_EXPECTED
        if msg.payload["frag_number"] < msg.payload["total_frags"]:
            _global_flow_marker = W__0404_OTHER_EXPECTED
        else:
            _global_flow_marker = I__0404_FINAL_RECEIVED

    # set the subsequent schedule fragments, until the last fragment
    elif msg._pkt._hdr[:20] == f"0404| W|{tcs_id}|{zone_idx}":
        assert _global_flow_marker == W__0404_OTHER_EXPECTED
        _global_flow_marker = I__0404_OTHER_EXPECTED

    elif msg._pkt._hdr[:20] == f"0404| I|{tcs_id}|{zone_idx}":
        assert _global_flow_marker == I__0404_OTHER_EXPECTED
        if msg.payload["frag_number"] < msg.payload["total_frags"]:
            _global_flow_marker = W__0404_OTHER_EXPECTED
        else:
            _global_flow_marker = I__0404_FINAL_RECEIVED

    else:
        assert False, msg


def assert_schedule_dict(zone: DhwZone | Zone):
    schedule_full = zone._schedule._full_schedule

    assert schedule_full[SZ_ZONE_IDX] == zone.idx
    assert schedule_full[SZ_SCHEDULE] == zone.schedule

    if schedule_full[SZ_ZONE_IDX] == "HW":
        SCH_SCHEDULE_DHW_OUTER(schedule_full)
    else:
        SCH_SCHEDULE_ZON_OUTER(schedule_full)

    schedule = schedule_full[SZ_SCHEDULE]
    # assert isinstance(schedule, list)
    assert len(schedule) == 7

    for idx, day_of_week in enumerate(schedule):
        # assert isinstance(day_of_week, dict)
        assert day_of_week[SZ_DAY_OF_WEEK] == idx

        # assert isinstance(day_of_week[SWITCHPOINTS], dict)
        for switchpoint in day_of_week[SZ_SWITCHPOINTS]:
            assert isinstance(switchpoint[SZ_TIME_OF_DAY], str)
            if SZ_HEAT_SETPOINT in switchpoint:
                assert isinstance(switchpoint[SZ_HEAT_SETPOINT], float)
            else:
                assert isinstance(switchpoint[SZ_ENABLED], bool)

    return schedule


async def read_schedule(zone: DhwZone | Zone) -> list:  # uses: flow_marker
    """Test the get_schedule() method for a Zone or for DHW."""

    # [{  'day_of_week': 0,
    #     'switchpoints': [{'time_of_day': '06:30', 'heat_setpoint': 21.0}, ...], }]

    global _global_flow_marker

    _global_flow_marker = RQ_0006_EXPECTED
    schedule = await zone.get_schedule()  # RQ|0404, may: TimeoutError
    assert _global_flow_marker == RP_0404_FINAL_RECEIVED

    if not schedule:  # valid test?
        assert zone._msgs[Code._0404].payload[SZ_TOTAL_FRAGS] is None
        return []

    schedule = assert_schedule_dict(zone)

    zone._gwy._disable_sending = True

    _global_flow_marker = RQ_0006_EXPECTED
    assert schedule == await zone.get_schedule(force_io=False)
    assert _global_flow_marker == RQ_0006_EXPECTED

    try:
        await zone.get_schedule(force_io=True)
    except RuntimeError:  # sending is disabled
        assert True
    else:
        assert False

    return schedule


async def read_schedule_ver(tcs: System) -> list:  # uses: flow_marker
    """Test the get_schedule() method for a Zone or for DHW."""

    global _global_flow_marker

    _global_flow_marker = RQ_0006_EXPECTED
    ver = (await tcs._schedule_version())[0]  # RQ|0006, may: TimeoutError
    assert _global_flow_marker == RP_0006_RECEIVED

    assert isinstance(ver, int)
    assert ver == tcs._msgs[Code._0006].payload["change_counter"]

    _global_flow_marker = RQ_0006_EXPECTED  # actually, is not expected
    assert ver == (await tcs._schedule_version(force_io=False))[0]
    assert _global_flow_marker == RQ_0006_EXPECTED

    ver = (await tcs._schedule_version(force_io=True))[0]  # RQ|0006, may: TimeoutError
    assert _global_flow_marker == RP_0006_RECEIVED

    tcs._gwy._disable_sending = True  # TODO: must speak directly to lower layer?

    _global_flow_marker = RQ_0006_EXPECTED  # actually, is not expected
    ver = (await tcs._schedule_version())[0]  # RQ|0006, may: TimeoutError
    assert _global_flow_marker == RQ_0006_EXPECTED

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

    global _global_flow_marker

    _global_flow_marker = RQ_0006_EXPECTED  # because of force_io=True
    ver_old, _ = await zone.tcs._schedule_version(force_io=True)
    assert _global_flow_marker == RP_0006_RECEIVED

    sch_old = await zone.get_schedule()
    assert _global_flow_marker == RP_0404_FINAL_RECEIVED

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
    assert _global_flow_marker == I__0404_FINAL_RECEIVED

    _global_flow_marker = RQ_0006_EXPECTED  # because of force_io=True
    ver_tst, _ = await zone.tcs._schedule_version(force_io=True)  # TODO: force_io=False
    assert _global_flow_marker == RP_0006_RECEIVED

    assert ver_tst > ver_old

    _global_flow_marker = RQ_0006_EXPECTED
    sch_tst = await zone.get_schedule()  # will use latest I/RP|0006
    assert _global_flow_marker == RQ_0006_EXPECTED

    sch_tst = await zone.get_schedule(force_io=True)  # will force RQ|0006
    assert _global_flow_marker == RP_0006_RECEIVED

    assert sch_tst == sch_new
    # if zone._gwy.pkt_transport.serial.port == MOCKED_PORT:
    #     assert sch_tst != sch_old
    #    sch_end = await zone.set_schedule(sch_old)  # put things back


@abort_if_rf_test_fails  # TODO: should be ramses_tx.protocol.???
@patch("ramses_rf.binding_fsm.WAITING_TIMEOUT_SECS", WAITING_TIMEOUT_SECS)
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
@patch("ramses_tx.transport.MIN_INTER_WRITE_GAP", MIN_INTER_WRITE_GAP)
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
@patch("ramses_tx.transport.MIN_INTER_WRITE_GAP", MIN_INTER_WRITE_GAP)
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
@patch("ramses_tx.transport.MIN_INTER_WRITE_GAP", MIN_INTER_WRITE_GAP)
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
@patch("ramses_tx.transport.MIN_INTER_WRITE_GAP", MIN_INTER_WRITE_GAP)
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
