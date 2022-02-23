#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import os
import unittest

from ramses_rf import Gateway

GWY_CONFIG = {}

LOG_DIR = f"{os.path.dirname(__file__)}"
LOG_FILES = ("pkts_bad_000.log",)

SCHEMA_EMPTY = {"device_hints": {}, "main_controller": None, "orphans": []}


class TestSetApis(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def _test_log_file(self, filename):
        with open(f"{LOG_DIR}/logs/{filename}") as f:
            self.gwy = Gateway(
                None, input_file=f, config=GWY_CONFIG, loop=self._asyncioTestLoop
            )
            await self.gwy.start()

        self.assertEqual(self.gwy.schema, SCHEMA_EMPTY)

    async def test_log_000(self):
        for filename in LOG_FILES:
            await self._test_log_file(filename)

        self.assertEqual(self.gwy.schema, SCHEMA_EMPTY)


if __name__ == "__main__":
    unittest.main()
