#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test eavesdropping of a device class.
"""

import json
from pathlib import Path, PurePath

from ramses_rf import Gateway
from ramses_rf.processor import _create_devices_from_addrs
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet
from tests.common import gwy  # noqa: F401
from tests.common import TEST_DIR, assert_expected

WORK_DIR = f"{TEST_DIR}/eavesdrop_dev_class"


def id_fnc(param):
    return PurePath(param).name


def pytest_generate_tests(metafunc):
    folders = [f for f in Path(WORK_DIR).iterdir() if f.is_dir()]
    metafunc.parametrize("dir_name", folders, ids=id_fnc)


def test_packets_from_log_file(gwy, dir_name):  # noqa: F811
    def proc_log_line(gwy, pkt_line):
        pkt_line, dev_slugs = pkt_line.split("#", maxsplit=1)

        if not pkt_line[27:].strip():
            return

        msg = Message(gwy, Packet.from_file(gwy, pkt_line[:26], pkt_line[27:]))
        _create_devices_from_addrs(gwy, msg)
        msg.src._handle_msg(msg)

        assert msg.src._SLUG in eval(dev_slugs)

    gwy.config.enable_eavesdrop = True

    with open(f"{dir_name}/packet.log") as f:
        while line := (f.readline()):
            if line.strip():
                proc_log_line(gwy, line)


async def test_dev_eavesdrop_off(dir_name):

    gwy: Gateway = None  # noqa: F811

    with open(f"{dir_name}/packet.log") as f:
        gwy = Gateway(None, input_file=f, config={"enable_eavesdrop": False})
        await gwy.start()

    try:
        with open(f"{dir_name}/known_list_eavesdrop_off.json") as f:
            assert_expected(gwy.known_list, json.load(f).get("known_list"))
    except FileNotFoundError:
        pass

    try:
        with open(f"{dir_name}/schema_eavesdrop_off.json") as f:
            assert_expected(gwy.schema, json.load(f))
    except FileNotFoundError:
        pass


async def test_dev_eavesdrop_on(dir_name):

    gwy: Gateway = None  # noqa: F811

    with open(f"{dir_name}/packet.log") as f:
        gwy = Gateway(None, input_file=f, config={"enable_eavesdrop": True})
        await gwy.start()

    with open(f"{dir_name}/known_list_eavesdrop_on.json") as f:
        assert_expected(gwy.known_list, json.load(f).get("known_list"))

    try:
        with open(f"{dir_name}/schema_eavesdrop_on.json") as f:
            assert_expected(gwy.schema, json.load(f))
    except FileNotFoundError:
        pass
