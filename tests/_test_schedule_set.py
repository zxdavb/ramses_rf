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

from common import GWY_CONFIG, TEST_DIR  # noqa: F401


class TestSchedule(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def test_schedule_set(self):
        with open(f"{TEST_DIR}/schemas/schema_000.log") as f:
            self.gwy = Gateway(
                None, input_file=f, config=GWY_CONFIG, loop=self._asyncioTestLoop
            )
            await self.gwy.start()

            # self.gwy.config.disable_sending = False

        with open(f"{TEST_DIR}/schedules/schedule.json") as f:
            schedule = json.load(f)

        with open(f"{TEST_DIR}/schedules/schedule.json") as f:
            await asyncio.gather(
                *spawn_scripts(self.gwy, **{SET_SCHED: ("01:123456", f)})
            )

        zone = self.gwy.system_by_id["01:145038"].zone_by_idx["01"]
        result = {"zone_idx": zone.idx, "schedule": zone.schedule}

        self.assertEqual(result, schedule)


if __name__ == "__main__":
    unittest.main()
