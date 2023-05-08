#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Command.put_*, Command.set_* APIs.
"""

from ramses_rf.protocol.command import CODE_API_MAP, Command

EXCLUDED_APIS = ("from_attrs", "_from_attrs", "from_cli")
EXCLUDED_APIS += (  # TODO: ideally, should be an empty list
    "get_schedule_version",
    "put_actuator_cycle",
    "put_actuator_state",
    "put_bind",
    "set_zone_setpoint",
)


def test_all_apis_in_map_WIP():
    """Check that all Command constrcutors are in CODE_API_MAP."""

    cls_apis = [
        v.__name__
        for k, v in Command.__dict__.items()
        if isinstance(v, classmethod) and k[:1] != "_" and k not in EXCLUDED_APIS
    ]

    map_apis = [v.__wrapped__.__name__ for v in CODE_API_MAP.values()]

    assert sorted(cls_apis) == sorted(map_apis)
