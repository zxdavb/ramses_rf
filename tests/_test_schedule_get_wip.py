#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schedule functions.
"""

import json
import unittest

from ramses_rf import Gateway
from tests.common import TEST_DIR

WORK_DIR = f"{TEST_DIR}/schedules"


class TestSchedule(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def test_schedule_get(self):
        self.gwy = Gateway(None, packet_dict={}, config={}, loop=self._asyncioTestLoop)

        with open(f"{WORK_DIR}/system_cache.json") as f:
            system_cache = json.load(f)

        await self.gwy._set_state(**system_cache["data"]["client_state"])

        # self.assertEqual(self.gwy.schema, schema)


if __name__ == "__main__":
    unittest.main()
