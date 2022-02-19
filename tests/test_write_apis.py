#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Command.get_* APIs.
"""

import asyncio
import unittest
from datetime import datetime as dt

from ramses_rf import Gateway
from ramses_rf.protocol.command import Command
from ramses_rf.protocol.helpers import str_from_hex
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet

PKT_0004_GOOD = (
    "...  W --- 18:000730 01:145038 --:------ 0004 022 00004D617374657220426564726F6F6D000000000000",
    "...  W --- 18:000730 01:145038 --:------ 0004 022 05005468697320497320412056657279204C6F6E6767",
)
PKT_0004_FAIL = (
    "...  W --- 18:000730 01:145038 --:------ 0004 022 05000000000000000000000000000000000000000000",  # name is None
    "...  W --- 18:000730 01:145038 --:------ 0004 022 05005468697320497320412056657279204C6F6E6720",  # trailing space
)
PKT_000A_GOOD = (
    "...  W --- 18:000730 01:145038 --:------ 000A 006 010001F40DAC",
    "...  W --- 18:000730 01:145038 --:------ 000A 006 031001F409C4",
    "...  W --- 18:000730 01:145038 --:------ 000A 006 050201F40898",
)
PKT_1030_GOOD = (
    "...  W --- 18:000730 01:145038 --:------ 1030 016 01C80137C9010FCA0196CB010FCC0101",
)
PKT_10A0_GOOD = (
    "...  W --- 01:123456 07:031785 --:------ 10A0 006 0015180001F4",
    "...  W --- 01:123456 07:031785 --:------ 10A0 006 0015180001F4",
)
PKT_1100_GOOD = (
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
PKT_1F41_GOOD = (
    "...  W --- 18:000730 01:050858 --:------ 1F41 012 000104FFFFFF0509160607E5",
    "...  W --- 18:000730 01:050858 --:------ 1F41 006 000000FFFFFF",
    "...  W --- 18:000730 01:050858 --:------ 1F41 012 000104FFFFFF2F0E0D0B07E5",
    "...  W --- 18:000730 01:050858 --:------ 1F41 012 000104FFFFFF19100D0B07E5",
)
PKT_1100_FAIL = (
    "...  W --- 01:145038 13:163733 --:------ 1100 008 000C1400007FFF01",  # no domain_id
)
PKT_2309_GOOD = (
    "...  W --- 18:000730 01:145038 --:------ 2309 003 00047E",
    "...  W --- 18:000730 01:145038 --:------ 2309 003 0101F4",
)
PKT_2309_FAIL = (
    "...  W --- 18:000730 01:145038 --:------ 2309 003 017FFF",  # temp is None - should be good?
)
PKT_2349_GOOD = (
    "...  W --- 18:005567 01:223036 --:------ 2349 007 037FFF00FFFFFF",
    "...  W --- 22:015492 01:076010 --:------ 2349 007 0101F400FFFFFF",
    "...  W --- 18:000730 01:145038 --:------ 2349 007 06028A01FFFFFF",
    "...  W --- 22:081652 01:063844 --:------ 2349 007 0106400300003C",
    "...  W --- 18:000730 01:050858 --:------ 2349 013 06096004FFFFFF240A050107E6",
    "...  W --- 18:000730 01:050858 --:------ 2349 013 02096004FFFFFF1B0D050107E6",
)
PKT_2E04_GOOD = (
    # "...  W --- 30:258720 01:073976 --:------ 2E04 008 0000000000000000",
    "...  W --- 30:258720 01:073976 --:------ 2E04 008 00FFFFFFFFFFFF00",
    "...  W --- 30:258720 01:073976 --:------ 2E04 008 01FFFFFFFFFFFF00",

    "...  W --- 30:258720 01:073976 --:------ 2E04 008 020B011A0607E401",
    "...  W --- 30:258720 01:073976 --:------ 2E04 008 0521011A0607E401",
)
PKT_313F_GOOD = (
    "...  W --- 30:258720 01:073976 --:------ 313F 009 006000320C040207E6",
    "...  W --- 30:258720 01:073976 --:------ 313F 009 0060011E09010707E6",
    "...  W --- 30:258720 01:073976 --:------ 313F 009 006002210D080C07E5",
    "...  W --- 30:042165 01:076010 --:------ 313F 009 006003090A0D0207E6",
    "...  W --- 30:042165 01:076010 --:------ 313F 009 0060041210040207E6"
)


class TestWriteApis(unittest.IsolatedAsyncioTestCase):

    _gwy = Gateway(None, loop=asyncio.get_event_loop(), config={})

    async def _test_api_line(self, api, pkt_line):
        pkt = Packet.from_port(self._gwy, dt.now(), pkt_line)

        self.assertEqual(str(pkt), pkt_line[4:])

        msg = Message(self._gwy, pkt)
        cmd = api(msg.dst.id, **{k: v for k, v in msg.payload.items() if k[:1] != "_"})

        self.assertEqual(cmd.payload, pkt.payload)
        # self.assertEqual(cmd, pkt)  # must have same addr set

        return pkt, msg, cmd

    async def _test_api(self, api, packets):
        for pkt_line in packets:
            await self._test_api_line(api, pkt_line)

    async def _test_api_debug(self, api, packets):
        for pkt_line in packets:
            pkt = Packet.from_port(self._gwy, dt.now(), pkt_line)

            # self.assertEqual(str(pkt), pkt_line[4:])

            msg = Message(self._gwy, pkt)
            print(msg.payload)

            cmd = api(
                msg.dst.id, **{k: v for k, v in msg.payload.items() if k[:1] != "_"}
            )

            # self.assertEqual(cmd.payload, pkt.payload)

    async def test_0004(self):
        await self._test_api(Command.set_zone_name, PKT_0004_GOOD)
        # self.assertEqual(str_from_hex(cmd.payload[4:]), msg.payload["name"])

    async def test_000a(self):
        await self._test_api(Command.set_zone_config, PKT_000A_GOOD)

    async def test_1030(self):  # TODO: no W|1030 seen in the wild
        await self._test_api(Command.set_mix_valve_params, PKT_1030_GOOD)

    async def test_10a0(self):  # TODO: no W|10A0 seen in the wild
        await self._test_api(Command.set_dhw_params, PKT_10A0_GOOD)

    async def test_1100(self):  # bespoke
        # await self._test_api(Command.set_tpi_params, PKT_1100_GOOD)
        for pkt_line in PKT_1100_GOOD:
            pkt = Packet.from_port(self._gwy, dt.now(), pkt_line)

            self.assertEqual(str(pkt), pkt_line[4:])

            msg = Message(self._gwy, pkt)

            domain_id = msg.payload.pop("domain_id", "00")
            cmd = Command.set_tpi_params(
                msg.dst.id, domain_id, **{k: v for k, v in msg.payload.items() if k[:1] != "_"}
            )

            self.assertEqual(cmd.payload, pkt.payload)

    async def test_1f41(self):
        await self._test_api(Command.set_dhw_mode, PKT_1F41_GOOD)

    async def test_2309(self):
        await self._test_api(Command.set_zone_setpoint, PKT_2309_GOOD)

    async def test_2349(self):
        await self._test_api(Command.set_zone_mode, PKT_2349_GOOD)

    async def test_2e04(self):
        await self._test_api(Command.set_system_mode, PKT_2E04_GOOD)

    async def test_313f(self):  # bespoke
        for pkt_line in PKT_313F_GOOD:
            pkt = Packet.from_port(self._gwy, dt.now(), pkt_line)

            self.assertEqual(str(pkt)[:4], pkt_line[4:8])
            self.assertEqual(str(pkt)[6:], pkt_line[10:])

            msg = Message(self._gwy, pkt)

            cmd = Command.set_system_time(
                msg.dst.id, **{k: v for k, v in msg.payload.items() if k[:1] != "_"}
            )

            self.assertEqual(cmd.payload[:4], pkt.payload[:4])
            self.assertEqual(cmd.payload[6:], pkt.payload[6:])


if __name__ == "__main__":
    unittest.main()
