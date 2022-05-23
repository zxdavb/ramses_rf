#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schedule functions.
"""

import json
from copy import deepcopy
from pathlib import Path, PurePath

from ramses_rf import Gateway
from ramses_rf.const import SZ_SCHEDULE
from ramses_rf.schedule import (
    HEAT_SETPOINT,
    SWITCHPOINTS,
    fragments_to_schedule,
    schedule_to_fragments,
)
from tests.common import gwy  # noqa: F401
from tests.common import TEST_DIR, load_test_system

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

    zone = gwy.tcs.zones[0]
    assert zone.schedule == schedule[SZ_SCHEDULE]


async def test_schedule_helpers(dir_name):
    """Compare the schedule helpers."""

    with open(f"{dir_name}/schedule.json") as f:
        schedule = json.load(f)

    assert schedule == fragments_to_schedule(schedule_to_fragments(schedule))

    new_schedule = deepcopy(schedule)
    new_schedule[SZ_SCHEDULE][-1][SWITCHPOINTS][-1][HEAT_SETPOINT] = (
        schedule[SZ_SCHEDULE][-1][SWITCHPOINTS][-1][HEAT_SETPOINT] + 1
    )

    # the schedule code relies upon the following inequality...
    # i.e. if the schedule has changed, then the first fragment will be different
    assert schedule_to_fragments(new_schedule)[0] != (
        schedule_to_fragments(schedule)[0]
    )
