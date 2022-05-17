#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schedule functions.
"""

import json
from pathlib import Path, PurePath

from ramses_rf import Gateway
from tests.common import gwy  # noqa: F401
from tests.common import TEST_DIR, assert_expected, load_test_system

WORK_DIR = f"{TEST_DIR}/schedules"


def id_fnc(param):
    return PurePath(param).name


def pytest_generate_tests(metafunc):
    folders = [f for f in Path(WORK_DIR).iterdir() if f.is_dir() and f.name[:1] != "_"]
    metafunc.parametrize("dir_name", folders, ids=id_fnc)


async def test_schedule_get(dir_name):
    """Compare the schedule built from a log file with the expected results."""

    with open(f"{dir_name}/schedule.json") as f:
        schedule = json.load(f)

    gwy: Gateway = await load_test_system(dir_name)  # noqa: F811

    assert_expected(gwy.tcs.zones[0].schedule, schedule)
