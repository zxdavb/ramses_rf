#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the various helper APIs.
"""

import unittest
from datetime import datetime as dt

from common import GWY_CONFIG, TEST_DIR  # noqa: F401

from ramses_rf.const import DEV_CLASS_MAP
from ramses_rf.protocol.const import attr_dict_factory
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet
from ramses_rf.protocol.parsers import PAYLOAD_PARSERS


PARSER_DIR = f"{TEST_DIR}/parser"
LOG_FILES = (
    "000C_long",
    "000C_short",
)

class TestParsers(unittest.TestCase):
    def test_pkt_parser(self, pkt_line, payload):
        pkt = Packet.from_port(self.gwy, dt.now(), pkt_line)

        self.assertEqual(str(pkt), pkt_line[4:])

        msg = Message(self.gwy, pkt)

        self.assertEqual(pkt.payload, payload)

    # def test_pkt_parser(self) -> None:
    #     for _dict in (PKTS_000C_LONG, ):
    #         map(self._test_pkt_parser, _dict.items()))


PKTS_000C_LONG = (
    "... RP --- 01:123456 18:000730 --:------ 000C 012 06-00-00119A99 06-00-00119B21"
    "... RP --- 01:123456 18:000730 --:------ 000C 018 07-08-001099C3 07-08-001099C5 07-08-001099BF"
    "... RP --- 01:123456 18:000730 --:------ 000C 036 07-08-001099C3 07-08-001099C5 07-08-001099BF 07-08-001099BE 07-08-001099BD 07-08-001099BC"
)

PKTS_000C_SHORT = (
    "... RP --- 01:123456 18:000730 --:------ 000C 011 01-00-00121B54    00-00121B52"
    "... RP --- 01:123456 18:000730 --:------ 000C 016 00-00-00109901    00-0011ED92    00-0011EDA0"
    "... RP --- 01:123456 18:000730 --:------ 000C 036 07-08-00109901    00-00109902    00-00109903    00-00109904    00-00109905    00-00109906    00-00109907    00-00109908"
)

if __name__ == "__main__":
    unittest.main()
