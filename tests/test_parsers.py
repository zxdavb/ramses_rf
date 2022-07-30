#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers.
"""

from pathlib import Path, PurePath

from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet
from tests.common import gwy  # noqa: F401
from tests.common import TEST_DIR

WORK_DIR = f"{TEST_DIR}/parsers"

HAS_ARRAY = "has_array"
HAS_IDX = "has_idx"
HAS_PAYLOAD = "has_payload"
IS_FRAGMENT = "is_fragment"
META_KEYS = (HAS_ARRAY, HAS_IDX, HAS_PAYLOAD, IS_FRAGMENT)


def id_fnc(param):
    return PurePath(param).name


def pytest_generate_tests(metafunc):
    metafunc.parametrize("f_name", sorted(Path(WORK_DIR).glob("*.log")), ids=id_fnc)


def _proc_log_line(gwy, pkt_line):  # noqa: F811
    pkt_line, pkt_dict, *_ = list(
        map(str.strip, pkt_line.split("#", maxsplit=1) + [""])
    )

    if not pkt_line:
        return

    msg = Message(gwy, Packet.from_file(gwy, pkt_line[:26], pkt_line[27:]))

    if not pkt_dict:
        return
    pkt_dict = eval(pkt_dict)

    if isinstance(pkt_dict, list) or not any(k for k in pkt_dict if k in META_KEYS):
        assert msg.payload == pkt_dict
        return

    assert HAS_ARRAY not in pkt_dict or msg._has_array == pkt_dict[HAS_ARRAY]
    assert HAS_IDX not in pkt_dict or msg._pkt._idx == pkt_dict[HAS_IDX]
    assert HAS_PAYLOAD not in pkt_dict or msg._has_payload == pkt_dict[HAS_PAYLOAD]
    assert (
        IS_FRAGMENT not in pkt_dict or bool(msg._is_fragment) == pkt_dict[IS_FRAGMENT]
    )


def test_parsers_from_log_files(gwy, f_name):  # noqa: F811
    with open(f_name) as f:
        while line := (f.readline()):
            _proc_log_line(gwy, line)
