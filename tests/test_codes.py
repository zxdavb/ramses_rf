#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import asyncio
import unittest
from pathlib import Path

from common import GWY_CONFIG, TEST_DIR

from ramses_rf import Gateway
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet

LOG_DIR = f"{TEST_DIR}/codes"


class TestSchemaLoad(unittest.IsolatedAsyncioTestCase):

    gwy = Gateway("/dev/null", config=GWY_CONFIG, loop=asyncio.get_event_loop())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy.config.disable_sending = True

    # def setUp(self):
    #     logging.basicConfig(level=logging.DEBUG)
    #     logging.getLogger().setLevel(logging.DEBUG)

    #     logging.disable(logging.DEBUG)

    def _proc_log_line(self, pkt_line):

        pkt_line, pkt_dict = pkt_line.split("#", maxsplit=1)
        if pkt_line[27:].strip():
            msg = Message(
                self.gwy, Packet.from_file(self.gwy, pkt_line[:26], pkt_line[27:])
            )

            self.assertEqual(msg.payload, eval(pkt_dict))

    def test_from_jsn_files(self):

        files = Path(LOG_DIR).glob("*.log")
        for f_name in files:
            with self.subTest(f_name):
                with open(f_name) as f:
                    while line := (f.readline()):
                        if line.strip():
                            self._proc_log_line(line)


if __name__ == "__main__":
    unittest.main()
