#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schedule functions.
"""

import asyncio
import json
import unittest

from ramses_rf import Gateway
from ramses_rf.discovery import SET_SCHED, spawn_scripts
from tests.helpers import TEST_DIR

WORK_DIR = f"{TEST_DIR}/schedules"


class TestSchedule(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def test_schedule_set(self):
        with open(f"{TEST_DIR}/schemas/schema_000.log") as f:
            self.gwy = Gateway(
                None, input_file=f, config={}, loop=self._asyncioTestLoop
            )
            await self.gwy.start()

        with open(f"{WORK_DIR}/schedule.json") as f:
            schedule = json.load(f)

        with open(f"{WORK_DIR}/schedule.json") as f:
            await asyncio.gather(
                *spawn_scripts(self.gwy, **{SET_SCHED: ("01:123456", f)})
            )

        zone = self.gwy.system_by_id["01:145038"].zone_by_idx["01"]
        result = {"zone_idx": zone.idx, "schedule": zone.schedule}

        self.assertEqual(result, schedule)

        await self.gwy.stop()


if __name__ == "__main__":
    unittest.main()
