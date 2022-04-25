#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers.
"""

import asyncio
from pathlib import Path, PurePath

import pytest

from ramses_rf import Gateway
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet
from tests.common import GWY_CONFIG, TEST_DIR


@pytest.fixture
async def gwy():
    gwy = Gateway("/dev/null", config=GWY_CONFIG, loop=asyncio.get_event_loop())
    gwy.config.disable_sending = True
    return gwy


def id_fnc(param):
    return PurePath(param).name


def pytest_generate_tests(metafunc):
    metafunc.parametrize(
        "f_name", Path(f"{TEST_DIR}/parsers").glob("*.log"), ids=id_fnc
    )


def test_payload_from_log_files(gwy, f_name):
    with open(f_name) as f:
        while line := (f.readline()):
            if line.strip():
                _proc_log_line(gwy, line)


def _proc_log_line(gwy, pkt_line):
    pkt_line, pkt_dict = pkt_line.split("#", maxsplit=1)
    if pkt_line[27:].strip():
        msg = Message(gwy, Packet.from_file(gwy, pkt_line[:26], pkt_line[27:]))
        assert msg.payload == eval(pkt_dict)
