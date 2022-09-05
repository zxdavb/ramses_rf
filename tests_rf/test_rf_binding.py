#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test binding of Heat devices.
"""

import asyncio

from ramses_rf.const import DEV_TYPE, SZ_SENSOR, SZ_ZONES, Code
from ramses_rf.device import HvacRemote, HvacVentilator
from ramses_rf.device.base import BindState, Fakeable
from ramses_rf.protocol import Message
from ramses_rf.protocol.schemas import (
    SZ_CLASS,
    SZ_ENFORCE_KNOWN_LIST,
    SZ_FAKED,
    SZ_KNOWN_LIST,
)
from ramses_rf.schemas import (
    SZ_CONFIG,
    SZ_ENABLE_EAVESDROP,
    SZ_ORPHANS_HEAT,
    SZ_ORPHANS_HVAC,
)
from tests_rf.common import MockGateway, abort_if_rf_test_fails, load_test_gwy
from tests_rf.mock import CTL_ID

FAN_ID = "21:111111"
REM_ID = "33:333333"
TRV_ID = "04:444444"


class HvacVentilatorFakable(HvacVentilator, Fakeable):
    pass


def pytest_generate_tests(metafunc):
    test_ports = {"/dev/ttyMOCK": MockGateway}  # don't use: from tests_rf.common...

    metafunc.parametrize("test_port", test_ports.items(), ids=test_ports.keys())


BIND_REQUEST_EXPECTED = 10
BIND_OFFER_EXPECTED = 11
BIND_CONFIRM_EXPECTED = 12
BIND_COMPLETED = 13

# NOTE: used as a global
flow_marker: int = None  # type: ignore[assignment]


def track_packet_flow(msg, tcs_id, *args, **kwargs):
    """Test the flow of packets (messages)."""

    global flow_marker

    if msg.code not in (Code._1FC9,):
        return

    # track the 3-way handshake
    if msg._pkt._hdr == "1FC9| I|63:262142":
        assert flow_marker == BIND_REQUEST_EXPECTED
        flow_marker = BIND_OFFER_EXPECTED

    elif msg._pkt._hdr == "1FC9| W|33:333333":
        assert flow_marker == BIND_OFFER_EXPECTED
        flow_marker = BIND_CONFIRM_EXPECTED

    elif msg._pkt._hdr == "1FC9| I|21:111111":
        assert flow_marker == BIND_CONFIRM_EXPECTED
        flow_marker = BIND_COMPLETED

    else:
        assert False, msg


@abort_if_rf_test_fails
async def test_hvac_bind_remote(test_port):
    """Bind a REM (remote) to a FAN (ventilation unit)."""

    global flow_marker

    def track_packet_flow_wrapper(msg: Message, *args, **kwargs):
        track_packet_flow(msg, rem.id, fan.id, Code._22F1)

    config = {
        SZ_CONFIG: {SZ_ENABLE_EAVESDROP: False, SZ_ENFORCE_KNOWN_LIST: True},
        SZ_ORPHANS_HVAC: [FAN_ID, REM_ID],
        SZ_KNOWN_LIST: {
            CTL_ID: {},
            FAN_ID: {SZ_CLASS: DEV_TYPE.FAN},
            REM_ID: {SZ_CLASS: DEV_TYPE.REM, SZ_FAKED: True},
        },
    }

    gwy = await load_test_gwy(*test_port, None, **config)
    gwy.create_client(track_packet_flow_wrapper)

    fan: HvacVentilator = gwy.device_by_id[FAN_ID]

    # make an unfakeable be fakeable...
    fan.__class__ = HvacVentilatorFakable
    setattr(fan, "_faked", None)
    setattr(fan, "_1fc9_state", {"state": BindState.UNKNOWN})

    fan._make_fake()
    fan._bind_waiting(Code._22F1)

    rem: HvacRemote = gwy.device_by_id[REM_ID]

    flow_marker = BIND_REQUEST_EXPECTED
    rem._bind()
    await asyncio.sleep(90)

    await gwy.stop()


@abort_if_rf_test_fails
async def _test_heat_bind_remote(test_port):
    config = {
        SZ_CONFIG: {SZ_ENABLE_EAVESDROP: False, SZ_ENFORCE_KNOWN_LIST: True},
        CTL_ID: {
            SZ_ZONES: {
                "01": {SZ_CLASS: "", SZ_SENSOR: CTL_ID},
            },
        },
        SZ_ORPHANS_HEAT: [CTL_ID, TRV_ID],
        SZ_KNOWN_LIST: {
            CTL_ID: {SZ_CLASS: DEV_TYPE.CTL},
            TRV_ID: {SZ_CLASS: DEV_TYPE.TRV, SZ_FAKED: True},
        },
    }

    gwy = await load_test_gwy(*test_port, None, **config)

    fan: HvacVentilator = gwy.device_by_id[CTL_ID]

    # make an unfakeable, fakeable...
    fan.__class__ = HvacVentilatorFakable
    setattr(fan, "_faked", None)
    setattr(fan, "_1fc9_state", {"state": BindState.UNKNOWN})

    fan._make_fake()
    fan._bind_waiting(Code._22F1)

    rem: HvacRemote = gwy.device_by_id[TRV_ID]
    rem._bind()
    await asyncio.sleep(60)

    await gwy.stop()
