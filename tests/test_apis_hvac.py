#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Command.put_*, Command.set_* APIs.
"""

from datetime import datetime as dt

from ramses_rf.protocol.command import CODE_API_MAP
from ramses_rf.protocol.message import Message
from ramses_rf.protocol.packet import Packet
from tests.common import gwy  # noqa: F401


def _test_api_invert(gwy, api, pkt_line):  # noqa: F811
    pkt = Packet.from_port(gwy, dt.now(), pkt_line)

    assert str(pkt) == pkt_line[4:]

    msg = Message(gwy, pkt)
    cmd = api(
        msg.dst.id,
        src_id=msg.src.id,
        **{k: v for k, v in msg.payload.items() if k[:1] != "_"},
    )

    assert cmd == pkt  # must have exact same addr set


def _test_api_kwargs(api, pkt_line, **kwargs):
    cmd = api(HRU, src_id=REM, **kwargs)

    assert str(cmd) == pkt_line[4:]  # [4:] to exclude seqn


def test_set_kwargs(gwy):  # noqa: F811
    for test_set in (SET_22F1_KWARGS, SET_22F7_KWARGS):
        for pkt, kwargs in test_set.items():
            api = CODE_API_MAP[f"{pkt[4:6]}|{pkt[41:45]}"]

            _test_api_kwargs(api, pkt, **kwargs)
            _test_api_invert(gwy, api, pkt)


HRU = "32:155617"
REM = "37:171871"
NUL = "--:------"

SET_22F1_KWARGS = {
    f"000  I --- {REM} {HRU} {NUL} 22F1 002 0000": {"fan_mode": None},
    #
    f"001  I --- {REM} {HRU} {NUL} 22F1 002 0000": {"fan_mode": 0},
    f"001  I --- {REM} {HRU} {NUL} 22F1 002 0001": {"fan_mode": 1},
    f"001  I --- {REM} {HRU} {NUL} 22F1 002 0002": {"fan_mode": 2},
    f"001  I --- {REM} {HRU} {NUL} 22F1 002 0003": {"fan_mode": 3},
    f"001  I --- {REM} {HRU} {NUL} 22F1 002 0004": {"fan_mode": 4},
    f"001  I --- {REM} {HRU} {NUL} 22F1 002 0005": {"fan_mode": 5},
    f"001  I --- {REM} {HRU} {NUL} 22F1 002 0006": {"fan_mode": 6},
    f"001  I --- {REM} {HRU} {NUL} 22F1 002 0007": {"fan_mode": 7},
    #
    f"002  I --- {REM} {HRU} {NUL} 22F1 002 0000": {"fan_mode": "00"},
    f"002  I --- {REM} {HRU} {NUL} 22F1 002 0001": {"fan_mode": "01"},
    f"002  I --- {REM} {HRU} {NUL} 22F1 002 0002": {"fan_mode": "02"},
    f"002  I --- {REM} {HRU} {NUL} 22F1 002 0003": {"fan_mode": "03"},
    f"002  I --- {REM} {HRU} {NUL} 22F1 002 0004": {"fan_mode": "04"},
    f"002  I --- {REM} {HRU} {NUL} 22F1 002 0005": {"fan_mode": "05"},
    f"002  I --- {REM} {HRU} {NUL} 22F1 002 0006": {"fan_mode": "06"},
    f"002  I --- {REM} {HRU} {NUL} 22F1 002 0007": {"fan_mode": "07"},
    #
    f"003  I --- {REM} {HRU} {NUL} 22F1 002 0000": {"fan_mode": "away"},
    f"003  I --- {REM} {HRU} {NUL} 22F1 002 0001": {"fan_mode": "low"},
    f"003  I --- {REM} {HRU} {NUL} 22F1 002 0002": {"fan_mode": "medium"},
    f"003  I --- {REM} {HRU} {NUL} 22F1 002 0003": {"fan_mode": "high"},
    f"003  I --- {REM} {HRU} {NUL} 22F1 002 0004": {"fan_mode": "auto"},
    f"003  I --- {REM} {HRU} {NUL} 22F1 002 0005": {"fan_mode": "auto_alt"},
    f"003  I --- {REM} {HRU} {NUL} 22F1 002 0006": {"fan_mode": "boost"},
    f"003  I --- {REM} {HRU} {NUL} 22F1 002 0007": {"fan_mode": "off"},
}


SET_22F7_KWARGS = {
    f"000  W --- {REM} {HRU} {NUL} 22F7 002 00FF": {},  # shouldn't be OK
    #
    f"001  W --- {REM} {HRU} {NUL} 22F7 002 00FF": {"bypass_position": None},
    f"001  W --- {REM} {HRU} {NUL} 22F7 002 0000": {"bypass_position": 0.0},
    # f"001  W --- {REM} {HRU} {NUL} 22F7 002 0064": {"bypass_position": 0.5},
    f"001  W --- {REM} {HRU} {NUL} 22F7 002 00C8": {"bypass_position": 1.0},
    #
    f"002  W --- {REM} {HRU} {NUL} 22F7 002 00FF": {"bypass_mode": None},
    f"002  W --- {REM} {HRU} {NUL} 22F7 002 00FF": {"bypass_mode": "auto"},
    f"002  W --- {REM} {HRU} {NUL} 22F7 002 0000": {"bypass_mode": "off"},
    f"002  W --- {REM} {HRU} {NUL} 22F7 002 00C8": {"bypass_mode": "on"},
}
