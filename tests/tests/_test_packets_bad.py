#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

from pathlib import Path, PurePath

from ramses_rf import Gateway
from ramses_rf.helpers import shrink
from tests.helpers import TEST_DIR  # noqa: F401

WORK_DIR = f"{TEST_DIR}/logs"

SCHEMA_EMPTY = {"known_list": {}, "main_tcs": None, "orphans": []}


def id_fnc(param):
    return PurePath(param).name


def pytest_generate_tests(metafunc):
    metafunc.parametrize("f_name", Path(WORK_DIR).glob("*.log"), ids=id_fnc)


async def test_log_file(f_name):
    with open(f_name) as f:
        gwy = Gateway(None, input_file=f, config={})
        await gwy.start()

    assert shrink(gwy.schema) == shrink(SCHEMA_EMPTY)

    await gwy.stop()
