#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers.
"""

from pathlib import Path, PurePath

from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet
from tests.common import TEST_DIR, gwy  # noqa: F401


def id_fnc(param):
    return PurePath(param).name


def pytest_generate_tests(metafunc):
    metafunc.parametrize(
        "f_name", Path(f"{TEST_DIR}/parsers").glob("*.log"), ids=id_fnc
    )


def test_payload_from_log_files(gwy, f_name):  # noqa: F811
    with open(f_name) as f:
        while line := (f.readline()):
            if line.strip():
                _proc_log_line(gwy, line)


def _proc_log_line(gwy, pkt_line):  # noqa: F811
    pkt_line, pkt_dict = pkt_line.split("#", maxsplit=1)
    if pkt_line[27:].strip():
        msg = Message(gwy, Packet.from_file(gwy, pkt_line[:26], pkt_line[27:]))
        assert msg.payload == eval(pkt_dict)
