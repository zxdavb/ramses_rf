#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers.
"""

import asyncio
import json
from pathlib import Path, PurePath

import pytest

from ramses_rf import Gateway
from ramses_rf.helpers import shrink
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet
from tests.common import GWY_CONFIG, TEST_DIR, shuffle_dict


@pytest.fixture
async def gwy():
    gwy = Gateway("/dev/null", config=GWY_CONFIG, loop=asyncio.get_event_loop())
    gwy.config.disable_sending = True
    return gwy


def id_fnc(param):
    return PurePath(param).name


def pytest_generate_tests(metafunc):
    folders = [f for f in Path(f"{TEST_DIR}/systems").iterdir() if f.is_dir()]

    metafunc.parametrize("f_name", folders, ids=id_fnc)


def test_payload_from_log_files(gwy, f_name):
    with open(f"{f_name}/packet.log") as f:
        while line := (f.readline()):
            if line.strip():
                _proc_log_line(gwy, line)


def _proc_log_line(gwy, pkt_line):
    pkt_line, pkt_dict = pkt_line.split("#", maxsplit=1)
    if pkt_line[27:].strip():
        msg = Message(gwy, Packet.from_file(gwy, pkt_line[:26], pkt_line[27:]))
        assert msg.payload == eval(pkt_dict)


KNOWN_LIST = {"30:079129": {"class": "ventilator"}}  # TODO: or FAN


async def test_systems_from_log_files(gwy, f_name):
    with open(f"{f_name}/packet.log") as f:
        gwy = Gateway(
            None,
            input_file=f,
            config=GWY_CONFIG,
            known_list=KNOWN_LIST,
            loop=asyncio.get_event_loop(),
        )
        await gwy.start()

    with open(f"{f_name}/schema.json") as f:
        schema = json.load(f)

    with open(f"{f_name}/status.json") as f:
        status = json.load(f)

    assert shrink(gwy.schema) == shrink(schema)
    assert shrink(gwy.status) == shrink(status)

    gwy.serial_port = "/dev/null"  # HACK: needed to pause engine

    schema, packets = gwy._get_state(include_expired=True)
    packets = shuffle_dict(packets)
    await gwy._set_state(packets, clear_state=True)

    assert shrink(gwy.schema) == shrink(schema)
    # assert shrink(gwy.status) == shrink(status)  # TODO
