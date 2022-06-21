#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Command.put_*, Command.set_* APIs.
"""

from datetime import datetime as dt

from ramses_rf.protocol.command import Command
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet
from tests.common import gwy  # noqa: F401


def _test_api_line(gwy, api, pkt_line):  # noqa: F811
    pkt = Packet.from_port(gwy, dt.now(), pkt_line)

    assert str(pkt) == pkt_line[4:]

    msg = Message(gwy, pkt)
    cmd = api(
        msg.dst.id,
        src_id=msg.src.id,
        **{k: v for k, v in msg.payload.items() if k[:1] != "_"}
    )

    return pkt, msg, cmd


def _test_api(gwy, api, packets):  # noqa: F811  # NOTE: incl. addr_set check
    for pkt_line in packets:
        pkt, msg, cmd = _test_api_line(gwy, api, pkt_line)

        assert cmd == pkt  # must have exact same addr set


def test_set_22f7_invert(gwy):  # noqa: F811
    _test_api(gwy, Command.set_bypass_position, SET_22F7_GOOD)


def test_set_22f7_kwargs():
    for pkt, kwargs in SET_22F7_KWARGS.items():
        cmd = Command.set_bypass_position("32:155617", src_id="37:171871", **kwargs)

        assert str(cmd) == pkt[4:]  # must have exact same addr set


SET_22F7_GOOD = (
    "...  W --- 37:171871 32:155617 --:------ 22F7 003 0000EF",  # bypass off
    "...  W --- 37:171871 32:155617 --:------ 22F7 003 00C8EF",  # bypass on
    "...  W --- 37:171871 32:155617 --:------ 22F7 003 00FFEF",  # bypass auto
)


SET_22F7_KWARGS = {
    "000  W --- 37:171871 32:155617 --:------ 22F7 003 00FFEF": {"bypass_mode": "auto"},
    "000  W --- 37:171871 32:155617 --:------ 22F7 003 0000EF": {"bypass_mode": "off"},
    "000  W --- 37:171871 32:155617 --:------ 22F7 003 00C8EF": {"bypass_mode": "on"},
    "001  W --- 37:171871 32:155617 --:------ 22F7 003 00FFEF": {
        "bypass_position": None
    },
    "001  W --- 37:171871 32:155617 --:------ 22F7 003 0000EF": {
        "bypass_position": 0.0
    },
    "001  W --- 37:171871 32:155617 --:------ 22F7 003 0064EF": {
        "bypass_position": 0.5
    },
    "001  W --- 37:171871 32:155617 --:------ 22F7 003 00C8EF": {
        "bypass_position": 1.0
    },
}
