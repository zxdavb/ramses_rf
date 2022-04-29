#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Command.put_*, Command.set_* APIs.
"""

import asyncio
import unittest
from datetime import datetime as dt

from ramses_rf import Gateway
from ramses_rf.const import SZ_DOMAIN_ID
from ramses_rf.protocol.address import HGI_DEV_ADDR
from ramses_rf.protocol.command import Command
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet
from tests.common import GWY_CONFIG, TEST_DIR  # noqa: F401

gwy = Gateway(None, config=GWY_CONFIG, loop=asyncio.get_event_loop())


def _test_api_line(api, pkt_line):
    pkt = Packet.from_port(gwy, dt.now(), pkt_line)

    assert str(pkt) == pkt_line[4:]

    msg = Message(gwy, pkt)
    cmd = api(msg.dst.id, **{k: v for k, v in msg.payload.items() if k[:1] != "_"})

    assert cmd.payload == pkt.payload

    return pkt, msg, cmd


def _test_api(api, packets):  # NOTE: incl. addr_set check
    for pkt_line in packets:
        pkt, msg, cmd = _test_api_line(api, pkt_line)

        if msg.src.id == HGI_DEV_ADDR.id:
            assert cmd == pkt  # must have exact same addr set


def test_put_30c9():
    _test_api(Command.put_sensor_temp, PUT_30C9_GOOD)


def test_put_3ef0():
    _test_api(Command.put_actuator_state, PUT_3EF0_GOOD)


def test_put_3ef1():  # NOTE: bespoke
    # _test_api(Command.put_actuator_cycle, PUT_3EF1_GOOD)
    for pkt_line in PUT_3EF1_GOOD:
        pkt = Packet.from_port(gwy, dt.now(), pkt_line)

        assert str(pkt) == pkt_line[4:]

        msg = Message(gwy, pkt)

        kwargs = msg.payload
        modulation_level = kwargs.pop("modulation_level")
        actuator_countdown = kwargs.pop("actuator_countdown")
        cmd = Command.put_actuator_cycle(
            msg.src.id,
            msg.dst.id,
            modulation_level,
            actuator_countdown,
            **{k: v for k, v in kwargs.items() if k[:1] != "_"}
        )

        assert cmd.payload[:-2] == pkt.payload[:-2]

        if msg.src.id == "18:000730":
            assert cmd == pkt  # must have exact same addr set


def test_set_0004():
    # assert str_from_hex(cmd.payload[4:]) == msg.payload["name"]
    _test_api(Command.set_zone_name, SET_0004_GOOD)


def test_set_000a():
    _test_api(Command.set_zone_config, SET_000A_GOOD)


def test_set_1030():
    _test_api(Command.set_mix_valve_params, SET_1030_GOOD)


def test_set_10a0():
    _test_api(Command.set_dhw_params, SET_10A0_GOOD)


def test_set_1100():  # NOTE: bespoke
    # _test_api(Command.set_tpi_params, SET_1100_GOOD)
    for pkt_line in SET_1100_GOOD:
        pkt = Packet.from_port(gwy, dt.now(), pkt_line)

        assert str(pkt) == pkt_line[4:]

        msg = Message(gwy, pkt)

        domain_id = msg.payload.pop(SZ_DOMAIN_ID, None)
        cmd = Command.set_tpi_params(
            msg.dst.id,
            domain_id,
            **{k: v for k, v in msg.payload.items() if k[:1] != "_"}
        )

        assert cmd.payload, pkt.payload

        if msg.src.id == "18:000730":
            assert cmd == pkt  # must have exact same addr set


def test_set_1f41():
    _test_api(Command.set_dhw_mode, SET_1F41_GOOD)


def test_set_2309():
    _test_api(Command.set_zone_setpoint, SET_2309_GOOD)


def test_set_2349():
    _test_api(Command.set_zone_mode, SET_2349_GOOD)


def test_set_2e04():
    _test_api(Command.set_system_mode, SET_2E04_GOOD)


def test_set_313f():  # NOTE: bespoke
    for pkt_line in SET_313F_GOOD:
        pkt = Packet.from_port(gwy, dt.now(), pkt_line)

        assert str(pkt)[:4] == pkt_line[4:8]
        assert str(pkt)[6:] == pkt_line[10:]

        msg = Message(gwy, pkt)

        cmd = Command.set_system_time(
            msg.dst.id, **{k: v for k, v in msg.payload.items() if k[:1] != "_"}
        )

        assert cmd.payload[:4] == pkt.payload[:4]
        assert cmd.payload[6:] == pkt.payload[6:]


PUT_30C9_GOOD = (
    "...  I --- 03:123456 --:------ 03:123456 30C9 003 0007C1",
    "...  I --- 03:123456 --:------ 03:123456 30C9 003 007FFF",
)
PUT_3EF0_FAIL = ("...  I --- 13:123456 --:------ 13:123456 3EF0 003 00AAFF",)
PUT_3EF0_GOOD = (
    "...  I --- 13:123456 --:------ 13:123456 3EF0 003 0000FF",
    "...  I --- 13:123456 --:------ 13:123456 3EF0 003 00C8FF",
)
PUT_3EF1_GOOD = (  # TODO: needs checking
    "... RP --- 13:123456 01:123456 --:------ 3EF1 007 000126012600FF",
    "... RP --- 13:123456 18:123456 --:------ 3EF1 007 007FFF003C0010",  # NOTE: should be: RP|10|3EF1
)
SET_0004_FAIL = (
    "...  W --- 18:000730 01:145038 --:------ 0004 022 05000000000000000000000000000000000000000000",  # name is None
    "...  W --- 18:000730 01:145038 --:------ 0004 022 05005468697320497320412056657279204C6F6E6720",  # trailing space
)
SET_0004_GOOD = (
    "...  W --- 18:000730 01:145038 --:------ 0004 022 00004D617374657220426564726F6F6D000000000000",
    "...  W --- 18:000730 01:145038 --:------ 0004 022 05005468697320497320412056657279204C6F6E6767",
)
SET_000A_GOOD = (
    "...  W --- 18:000730 01:145038 --:------ 000A 006 010001F40DAC",
    "...  W --- 18:000730 01:145038 --:------ 000A 006 031001F409C4",
    "...  W --- 18:000730 01:145038 --:------ 000A 006 050201F40898",
)
SET_1030_GOOD = (  # TODO: no W|1030 seen in the wild
    "...  W --- 18:000730 01:145038 --:------ 1030 016 01C80137C9010FCA0196CB010FCC0101",
)
SET_10A0_GOOD = (  # TODO: no W|10A0 seen in the wild
    "...  W --- 01:123456 07:031785 --:------ 10A0 006 0015180001F4",
    "...  W --- 01:123456 07:031785 --:------ 10A0 006 0015180001F4",
)
SET_1100_FAIL = (
    "...  W --- 01:145038 13:163733 --:------ 1100 008 000C1400007FFF01",  # no domain_id
)
SET_1100_GOOD = (
    "...  W --- 01:145038 13:035462 --:------ 1100 008 00240414007FFF01",
    "...  W --- 01:145038 13:163733 --:------ 1100 008 000C14000000C801",  # min_off_time 0
    "...  W --- 01:145038 13:163733 --:------ 1100 008 00180400007FFF01",  # min_off_time 0
    "...  W --- 01:145038 13:035462 --:------ 1100 008 FC042814007FFF01",  # cycle_rate 1
    "...  W --- 01:145038 13:035462 --:------ 1100 008 FC082814007FFF01",  # cycle_rate 2
    "...  W --- 01:145038 13:035462 --:------ 1100 008 FC243C14007FFF01",  # min_on_time 15
    "...  W --- 01:145038 13:035462 --:------ 1100 008 FC240414007FFF01",
    "...  W --- 01:145038 13:035462 --:------ 1100 008 FC240428007FFF01",  # min_off_time 10
    "...  W --- 01:145038 13:035462 --:------ 1100 008 FC083C14007FFF01",  # cycle_rate 2
    "...  W --- 01:145038 13:035462 --:------ 1100 008 FC083C00007FFF01",  # cycle_rate 2
)
SET_1F41_GOOD = (
    "...  W --- 18:000730 01:050858 --:------ 1F41 012 000104FFFFFF0509160607E5",
    "...  W --- 18:000730 01:050858 --:------ 1F41 006 000000FFFFFF",
    "...  W --- 18:000730 01:050858 --:------ 1F41 012 000104FFFFFF2F0E0D0B07E5",
    "...  W --- 18:000730 01:050858 --:------ 1F41 012 000104FFFFFF19100D0B07E5",
)
SET_2309_FAIL = (
    "...  W --- 18:000730 01:145038 --:------ 2309 003 017FFF",  # temp is None - should be good?
)
SET_2309_GOOD = (
    "...  W --- 18:000730 01:145038 --:------ 2309 003 00047E",
    "...  W --- 18:000730 01:145038 --:------ 2309 003 0101F4",
)
SET_2349_GOOD = (
    "...  W --- 18:005567 01:223036 --:------ 2349 007 037FFF00FFFFFF",
    "...  W --- 22:015492 01:076010 --:------ 2349 007 0101F400FFFFFF",
    "...  W --- 18:000730 01:145038 --:------ 2349 007 06028A01FFFFFF",
    "...  W --- 22:081652 01:063844 --:------ 2349 007 0106400300003C",
    "...  W --- 18:000730 01:050858 --:------ 2349 013 06096004FFFFFF240A050107E6",
    "...  W --- 18:000730 01:050858 --:------ 2349 013 02096004FFFFFF1B0D050107E6",
)
SET_2E04_GOOD = (
    # ..  W --- 30:258720 01:073976 --:------ 2E04 008 0000000000000000",  # wont work
    "...  W --- 30:258720 01:073976 --:------ 2E04 008 00FFFFFFFFFFFF00",
    "...  W --- 30:258720 01:073976 --:------ 2E04 008 01FFFFFFFFFFFF00",
    "...  W --- 30:258720 01:073976 --:------ 2E04 008 020B011A0607E401",
    "...  W --- 30:258720 01:073976 --:------ 2E04 008 0521011A0607E401",
)
SET_313F_GOOD = (
    "...  W --- 30:258720 01:073976 --:------ 313F 009 006000320C040207E6",
    "...  W --- 30:258720 01:073976 --:------ 313F 009 0060011E09010707E6",
    "...  W --- 30:258720 01:073976 --:------ 313F 009 006002210D080C07E5",
    "...  W --- 30:042165 01:076010 --:------ 313F 009 006003090A0D0207E6",
    "...  W --- 30:042165 01:076010 --:------ 313F 009 0060041210040207E6",
)


if __name__ == "__main__":
    unittest.main()
