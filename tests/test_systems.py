#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers and corresponding output (schema, traits, params, status).
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

    metafunc.parametrize("dir_name", folders, ids=id_fnc)


async def load_test_system(dir_name, config: dict = None) -> Gateway:

    try:
        with open(f"{dir_name}/config.json") as f:
            kwargs = json.load(f)
    except FileNotFoundError:
        kwargs = {}

    if config:
        kwargs.update(config)

    with open(f"{dir_name}/packet.log") as f:
        gwy = Gateway(
            None,
            input_file=f,
            loop=asyncio.get_event_loop(),
            **kwargs,
        )
        await gwy.start()

    return gwy


def load_expected_results(dir_name) -> dict:

    with open(f"{dir_name}/schema.json") as f:
        schema = json.load(f)

    try:
        with open(f"{dir_name}/traits.json") as f:
            traits = json.load(f)
    except FileNotFoundError:
        traits = None

    try:
        with open(f"{dir_name}/params.json") as f:
            params = json.load(f)
    except FileNotFoundError:
        params = None

    try:
        with open(f"{dir_name}/status.json") as f:
            status = json.load(f)
    except FileNotFoundError:
        status = None

    # TODO: do traits, status
    return {"schema": schema, "traits": traits, "params": params, "status": status}


def assert_single_expected(actual, expected: dict = None) -> None:

    if expected is not None:
        assert shrink(actual) == shrink(expected)


def assert_expected(gwy, expected) -> None:

    assert_single_expected(gwy.schema, expected.get("schema"))
    # sert_result(gwy.traits, expected.get("traits"))
    assert_single_expected(gwy.params, expected.get("params"))
    # sert_result(gwy.status, expected.get("status"))


def test_payload_from_log_files(gwy, dir_name):
    def proc_log_line(gwy, pkt_line):
        pkt_line, pkt_dict = pkt_line.split("#", maxsplit=1)
        if pkt_line[27:].strip():
            msg = Message(gwy, Packet.from_file(gwy, pkt_line[:26], pkt_line[27:]))
            assert msg.payload == eval(pkt_dict)

    with open(f"{dir_name}/packet.log") as f:
        while line := (f.readline()):
            if line.strip():
                proc_log_line(gwy, line)


async def test_systems_from_log_files(dir_name):
    expected: dict = load_expected_results(dir_name)
    gwy: Gateway = await load_test_system(dir_name)

    gwy.serial_port = "/dev/null"  # HACK: needed to pause engine
    schema, _ = gwy._get_state(include_expired=True)

    assert_single_expected(schema, expected.get("schema"))

    assert_expected(gwy, expected)


async def test_shuffle_from_log_files(dir_name):

    expected: dict = load_expected_results(dir_name)
    gwy: Gateway = await load_test_system(dir_name)

    gwy.serial_port = "/dev/null"  # HACK: needed to pause engine
    _, packets = gwy._get_state(include_expired=True)

    packets = shuffle_dict(packets)
    await gwy._set_state(packets)

    assert_expected(gwy, expected)


async def test_schemax_with_log_files(dir_name):

    expected: dict = load_expected_results(dir_name)
    gwy: Gateway = await load_test_system(dir_name, expected["schema"])

    assert_expected(gwy, expected)
