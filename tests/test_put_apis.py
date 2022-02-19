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
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet

PUT_30C9_GOOD = (
    "...  I --- 03:123456 --:------ 03:123456 30C9 003 0007C1",
    "...  I --- 03:123456 --:------ 03:123456 30C9 003 007FFF",
)
PUT_3EF0_GOOD = (
    "...  I --- 13:123456 --:------ 13:123456 3EF0 003 0000FF",
    "...  I --- 13:123456 --:------ 13:123456 3EF0 003 00C8FF",
)
PUT_3EF0_FAIL = (
    "...  I --- 13:123456 --:------ 13:123456 3EF0 003 00AAFF",
)
PUT_3EF1_GOOD = (  # TODO: needs checking
    "... RP --- 13:123456 01:123456 --:------ 3EF1 007 000126012600FF",
    "... RP --- 13:123456 18:123456 --:------ 3EF1 007 007FFF003C0010",  # NOTE: should be: RP|10|3EF1
)


class TestSetApis(unittest.IsolatedAsyncioTestCase):

    _gwy = Gateway(None, loop=asyncio.get_event_loop(), config={})

    async def _test_api_line(self, api, pkt_line):
        pkt = Packet.from_port(self._gwy, dt.now(), pkt_line)

        self.assertEqual(str(pkt), pkt_line[4:])

        msg = Message(self._gwy, pkt)
        cmd = api(msg.src.id, **{k: v for k, v in msg.payload.items() if k[:1] != "_"})

        self.assertEqual(cmd, pkt)

        return pkt, msg, cmd

    async def _test_api(self, api, packets):
        for pkt_line in packets:
            await self._test_api_line(api, pkt_line)

    async def test_30c9(self):
        await self._test_api(Command.put_sensor_temp, PUT_30C9_GOOD)

    async def test_3ef0(self):
        await self._test_api(Command.put_actuator_state, PUT_3EF0_GOOD)

    async def test_3ef1(self):  # bespoke
        # await self._test_api(Command.put_actuator_cycle, PUT_3EF1_GOOD)
        for pkt_line in PUT_3EF1_GOOD:
            pkt = Packet.from_port(self._gwy, dt.now(), pkt_line)

            self.assertEqual(str(pkt), pkt_line[4:])

            msg = Message(self._gwy, pkt)

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

            self.assertEqual(cmd.payload[:-2], pkt.payload[:-2])
            # self.assertEqual(cmd, pkt)


if __name__ == "__main__":
    unittest.main()
