#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the payload parsers on a per-device basis.
"""

from pathlib import Path, PurePath

from ramses_tx import exceptions as exc
from ramses_tx.message import Message
from ramses_tx.packet import Packet
from tests.helpers import TEST_DIR

WORK_DIR = f"{TEST_DIR}/devices"


def pytest_generate_tests(metafunc):
    def id_fnc(param):
        return PurePath(param).name

    metafunc.parametrize("f_name", sorted(Path(WORK_DIR).glob("*.log")), ids=id_fnc)


def _proc_log_line(log_line: str):
    pkt_line, pkt_eval, *_ = list(
        map(str.strip, log_line.split("#", maxsplit=1) + [""])
    )

    if not pkt_line:
        return

    try:
        pkt = Packet.from_file(pkt_line[:26], pkt_line[27:])
    except exc.PacketInvalid as err:
        assert False, f"{pkt_line[27:]} < {err}"

    try:
        _ = Message(pkt)
    except exc.PacketPayloadInvalid as err:
        assert False, f"{pkt} < {err}"

    # assert bool(msg._is_fragment) == pkt._is_fragment
    # assert bool(msg._idx): dict == pkt._idx: Optional[bool | str]  # not useful

    if not pkt_eval:
        return
    try:
        _ = eval(pkt_eval)
    except SyntaxError:
        if "{" in pkt_eval:
            raise
        return


def test_parsers_from_log_files(f_name):
    with open(f_name) as f:
        while line := (f.readline()):
            _proc_log_line(line)
