#!/usr/bin/env python3
"""RAMSES RF - Test the payload parsers."""

from pathlib import Path, PurePath

import pytest

from ramses_tx.const import Code
from ramses_tx.message import Message
from ramses_tx.packet import Packet

from .helpers import TEST_DIR

WORK_DIR = f"{TEST_DIR}/parsers"

HAS_ARRAY = "has_array"
HAS_IDX = "has_idx"
HAS_PAYLOAD = "has_payload"
IS_FRAGMENT = "is_fragment"
META_KEYS = (HAS_ARRAY, HAS_IDX, HAS_PAYLOAD, IS_FRAGMENT)


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    def id_fnc(param: Path) -> str:
        return PurePath(param).name

    metafunc.parametrize("f_name", sorted(Path(WORK_DIR).glob("*.log")), ids=id_fnc)


def _proc_log_line(log_line: str) -> None:
    pkt_line, pkt_eval, *_ = list(
        map(str.strip, log_line.split("#", maxsplit=1) + [""])
    )

    if not pkt_line:
        return

    pkt = Packet.from_file(pkt_line[:26], pkt_line[27:])
    msg = Message(pkt)

    # assert bool(msg._is_fragment) == pkt._is_fragment
    # assert bool(msg._idx): dict == pkt._idx: Optional[bool | str]  # not useful

    if not pkt_eval:
        return
    try:
        pkt_dict = eval(pkt_eval)
    except SyntaxError:
        if "{" in pkt_eval:  # if so, there is an issue with the log line
            raise  # that should be addressed
        return

    if isinstance(pkt_dict, list) or not any(k for k in pkt_dict if k in META_KEYS):
        assert msg.payload == pkt_dict, msg._pkt
        return

    assert HAS_ARRAY not in pkt_dict or pkt._has_array == pkt_dict[HAS_ARRAY]
    assert HAS_IDX not in pkt_dict or pkt._idx == pkt_dict[HAS_IDX]
    assert HAS_PAYLOAD not in pkt_dict or pkt._has_payload == pkt_dict[HAS_PAYLOAD]
    assert IS_FRAGMENT not in pkt_dict or pkt._is_fragment == pkt_dict[IS_FRAGMENT]


def _proc_log_line_pair_4e15(log_line: str, prev_msg: Message) -> Message | None:
    pkt_line, *_ = list(map(str.strip, log_line.split("#", maxsplit=1) + [""]))

    if not pkt_line:
        return None

    pkt = Packet.from_file(pkt_line[:26], pkt_line[27:])
    this_msg = Message(pkt)

    if not prev_msg or prev_msg.code != Code._4E15:
        return this_msg

    if this_msg.code != Code._3EF0:
        return None

    assert prev_msg.payload["is_cooling"] == this_msg.payload["cool_active"]
    assert prev_msg.payload["is_heating"] == this_msg.payload["ch_active"]
    assert prev_msg.payload["is_dhw_ing"] == this_msg.payload["dhw_active"]

    return this_msg


def test_parsers_from_log_files(f_name: Path) -> None:
    with open(f_name) as f:
        while line := (f.readline()):
            _proc_log_line(line)


def _test_parser_31da(f_name: Path) -> None:
    # assert _31DA_FAN_INFO[int(payload[36:38], 16) & 0x1F] in (
    #     speed_capabilities(payload[30:34])["speed_capabilities"]
    # ) or (
    #     int(payload[36:38], 16) & 0x1F in (1, 2, 3) and int(payload[30:34], 16) & 2**14
    # ) or (
    #     int(payload[36:38], 16) & 0x1F in (11, 12, 13) and int(payload[30:34], 16) & 2**14 and int(payload[30:34], 16) & 2**13
    # ) or (
    #     int(payload[36:38], 16) & 0x1F in (0x00, 0x18, 0x15)
    # ), {_31DA_FAN_INFO[int(payload[36:38], 16) & 0x1F]: speed_capabilities(payload[30:34])}

    # assert payload[36:38] not in ("0B", "0C", "0D") or payload[42:46] == "0000", (
    #     payload[36:38], payload[42:46]
    # )

    pass


def _test_parser_pairs_31d9_31da(f_name: Path) -> None:
    pass


def _test_parser_pairs_4e15_3ef0(f_name: Path) -> None:
    if "4e15" in str(f_name):
        with open(f_name) as f:
            msg = None
            while this_line := (f.readline()):
                msg = _proc_log_line_pair_4e15(this_line, msg)

    # elif "01ff" in str(f_name):
    #     with open(f_name) as f:
    #         msg = None
    #         while this_line := (f.readline()):
    #             msg = _proc_log_line_pair_01ff(this_line, msg)
