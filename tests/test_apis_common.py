#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Command.put_*, Command.set_* APIs.
"""

from ramses_rf.protocol.command import CODE_API_MAP, Command

EXCLUDED_APIS = ("from_attrs", "_from_attrs", "from_cli")
EXCLUDED_APIS += ()  # APIs not added to the CODE_API_MAP, should be an empty tuple


def test_all_apis_in_map():
    """Check that all Command constructors are in CODE_API_MAP."""

    cls_apis = set(
        v.__name__
        for k, v in Command.__dict__.items()
        if isinstance(v, classmethod) and k[:1] != "_" and k not in EXCLUDED_APIS
    )

    map_apis = set(v.__wrapped__.__name__ for v in CODE_API_MAP.values())

    assert not map_apis.symmetric_difference(cls_apis)
