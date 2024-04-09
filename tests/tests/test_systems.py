#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers and corresponding output (schema, traits, params, status).
"""

from pathlib import Path, PurePath

from ramses_rf import Gateway
from ramses_rf.helpers import shrink
from ramses_tx.message import Message
from ramses_tx.packet import Packet
from tests.helpers import (
    TEST_DIR,
    assert_expected,
    assert_expected_set,
    load_expected_results,
    load_test_gwy,
    shuffle_dict,
)

WORK_DIR = f"{TEST_DIR}/systems"


def id_fnc(param):
    return PurePath(param).name


def pytest_generate_tests(metafunc) -> None:
    folders = [f for f in Path(WORK_DIR).iterdir() if f.is_dir() and f.name[:1] != "_"]
    metafunc.parametrize("dir_name", folders, ids=id_fnc)


def test_payloads_from_log_file(dir_name: Path) -> None:
    """Assert that each message payload is as expected."""
    # RP --- 02:044328 18:200214 --:------ 2309 003 0007D0       # {'ufh_idx': '00', 'setpoint': 20.0}

    def proc_log_line(pkt_line):
        if "#" not in pkt_line:
            return

        pkt_line, pkt_eval = pkt_line.split("#", maxsplit=1)

        if not pkt_line[27:].strip():
            return

        pkt = Packet.from_file(pkt_line[:26], pkt_line[27:])
        msg = Message(pkt)

        assert msg.payload == eval(pkt_eval)

    with open(f"{dir_name}/packet.log") as f:
        while line := (f.readline()):
            if line.strip():
                proc_log_line(line)


async def test_schemax_with_log_file(dir_name: Path) -> None:
    """Compare the schema built from a log file with the expected results."""

    expected: dict = load_expected_results(dir_name) or {}

    # if not expected["schema"]:
    #     return  # nothing to test

    gwy: Gateway = await load_test_gwy(
        dir_name, **expected["schema"], known_list=expected["known_list"]
    )

    global_schema, _ = gwy.get_state()

    assert_expected(
        shrink(global_schema),
        shrink(expected["schema"]),
    )

    await gwy.stop()


async def test_systems_from_log_file(dir_name: Path) -> None:
    """Compare the system built from a log file with the expected results."""

    expected: dict = load_expected_results(dir_name) or {}
    gwy: Gateway = await load_test_gwy(dir_name)

    assert_expected_set(gwy, expected)

    await gwy.stop()


async def test_restore_from_log_file(dir_name: Path) -> None:
    """Compare the system built from a get_state log file with the expected results."""

    expected: dict = load_expected_results(dir_name) or {}
    gwy: Gateway = await load_test_gwy(dir_name)

    schema, packets = gwy.get_state(include_expired=True)

    await gwy._restore_cached_packets(packets)
    assert_expected_set(gwy, expected)
    # assert shrink(gwy.schema) == shrink(schema)

    await gwy.stop()


async def test_shuffle_from_log_file(dir_name: Path) -> None:
    """Compare the system built from a shuffled log file with the expected results."""

    expected: dict = load_expected_results(dir_name) or {}
    gwy: Gateway = await load_test_gwy(dir_name)

    schema, packets = gwy.get_state(include_expired=True)

    packets = shuffle_dict(packets)

    await gwy._restore_cached_packets(packets)
    assert_expected_set(gwy, expected)
    # assert shrink(gwy.schema) == shrink(schema)

    packets = shuffle_dict(packets)

    await gwy._restore_cached_packets(packets)
    assert_expected_set(gwy, expected)
    # assert shrink(gwy.schema) == shrink(schema)

    await gwy.stop()
