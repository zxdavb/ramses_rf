#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test binding of Heat devices.
"""

import asyncio
from datetime import datetime as dt
from datetime import timedelta as td

from tests_deprecated.common import (
    MOCKED_PORT,
    MockGateway,
    abort_if_rf_test_fails,
    load_test_gwy,
)

from ramses_rf.binding_fsm import _BindStates
from ramses_rf.const import Code, DevType
from ramses_rf.device import HvacRemote, HvacVentilator
from ramses_rf.device.base import Fakeable
from ramses_rf.schemas import SZ_CONFIG, SZ_DISABLE_DISCOVERY, SZ_ORPHANS_HVAC
from ramses_tx import Message
from ramses_tx.schemas import SZ_CLASS, SZ_ENFORCE_KNOWN_LIST, SZ_FAKED, SZ_KNOWN_LIST

FAN_ID = "21:111111"
REM_ID = "33:333333"
CO2_ID = "44:444444"


class HvacVentilatorFakable(HvacVentilator, Fakeable):
    pass


def pytest_generate_tests(metafunc):
    test_ports = {MOCKED_PORT: MockGateway}

    metafunc.parametrize("test_port", test_ports.items(), ids=test_ports.keys())


BIND_REQUEST_EXPECTED = 10
BIND_OFFER_EXPECTED = 11
BIND_CONFIRM_EXPECTED = 12
BIND_COMPLETED = 13

# NOTE: used as a global
flow_marker: int = None  # type: ignore[assignment]


def track_packet_flow(msg, requestor_id, listener_id, *args, **kwargs):
    """Test the flow of packets (messages) as initiated by the requestor."""

    global flow_marker

    if msg.code not in (Code._1FC9,):
        return

    # track the 3-way handshake
    if msg._pkt._hdr == "1FC9| I|63:262142":  # cast to any listener
        assert flow_marker == BIND_REQUEST_EXPECTED
        flow_marker = BIND_OFFER_EXPECTED

    elif msg._pkt._hdr == f"1FC9| W|{requestor_id}":  # sent to the requestor
        assert flow_marker == BIND_OFFER_EXPECTED
        flow_marker = BIND_CONFIRM_EXPECTED

    elif msg._pkt._hdr == f"1FC9| I|{listener_id}":  # sent to the listener/offerer
        assert flow_marker == BIND_CONFIRM_EXPECTED
        flow_marker = BIND_COMPLETED

    else:
        assert False, msg


@abort_if_rf_test_fails
async def test_hvac_bind_rem(test_port):
    """Bind a REM (remote) to a FAN (ventilation unit)."""

    global flow_marker

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, rem.id, fan.id, Code._22F1)

    config = {
        SZ_CONFIG: {SZ_DISABLE_DISCOVERY: False, SZ_ENFORCE_KNOWN_LIST: True},
        SZ_ORPHANS_HVAC: [FAN_ID, REM_ID],
        SZ_KNOWN_LIST: {
            FAN_ID: {SZ_CLASS: DevType.FAN},
            REM_ID: {SZ_CLASS: DevType.REM, SZ_FAKED: True},
        },
    }

    gwy = await load_test_gwy(*test_port, None, devices=[], **config)
    gwy.create_client(track_packet_flow_wrapper)

    fan: HvacVentilator = gwy.device_by_id[FAN_ID]

    # make an unfakeable device be fakeable...
    fan.__class__ = HvacVentilatorFakable
    setattr(fan, "_faked", None)
    setattr(fan, "_1fc9_state", {"state": _BindStates.IS_IDLE_DEVICE})

    # then enable faking on this device
    fan._make_fake()
    fan._bind_waiting(Code._22F1)

    rem: HvacRemote = gwy.device_by_id[REM_ID]

    flow_marker = BIND_REQUEST_EXPECTED
    rem._bind()

    dtm = dt.now() + td(seconds=5)
    while dtm > dt.now():
        await asyncio.sleep(0.002)
        if flow_marker == BIND_COMPLETED:
            break

    await gwy.stop()
    assert flow_marker == BIND_COMPLETED


@abort_if_rf_test_fails
async def test_hvac_bind_co2(test_port):
    """Bind a CO2 (CO2 sensor) to a FAN (ventilation unit)."""

    global flow_marker

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, co2.id, fan.id, Code._1298)

    config = {
        SZ_CONFIG: {SZ_DISABLE_DISCOVERY: False, SZ_ENFORCE_KNOWN_LIST: True},
        SZ_ORPHANS_HVAC: [FAN_ID, CO2_ID],
        SZ_KNOWN_LIST: {
            FAN_ID: {SZ_CLASS: DevType.FAN},
            CO2_ID: {SZ_CLASS: DevType.CO2, SZ_FAKED: True},
        },
    }

    gwy = await load_test_gwy(*test_port, None, devices=[], **config)
    gwy.create_client(track_packet_flow_wrapper)

    fan: HvacVentilator = gwy.device_by_id[FAN_ID]

    # make an unfakeable device be fakeable...
    fan.__class__ = HvacVentilatorFakable
    setattr(fan, "_faked", None)
    setattr(fan, "_1fc9_state", {"state": _BindStates.IS_IDLE_DEVICE})

    # then enable faking on this device
    fan._make_fake()
    fan._bind_waiting(Code._1298)

    co2: HvacRemote = gwy.device_by_id[CO2_ID]

    flow_marker = BIND_REQUEST_EXPECTED
    co2._bind()

    dtm = dt.now() + td(seconds=5)
    while dtm > dt.now():
        await asyncio.sleep(0.002)
        if flow_marker == BIND_COMPLETED:
            break

    await gwy.stop()
    assert flow_marker == BIND_COMPLETED
