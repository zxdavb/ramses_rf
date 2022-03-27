#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import logging
import unittest

from common import GWY_CONFIG, TEST_DIR  # noqa: F401

from ramses_rf import Gateway

LOG_DIR = TEST_DIR
LOG_FILES = ("pkts_bad_000.log",)

SCHEMA_EMPTY = {"device_hints": {}, "main_controller": None, "orphans": []}


class TestSetApis(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def proc_log_file(self, filename):
        with open(f"{LOG_DIR}/logs/{filename}") as f:
            self.gwy = Gateway(
                None, input_file=f, config=GWY_CONFIG, loop=self._asyncioTestLoop
            )
            await self.gwy.start()

        self.assertEqual(self.gwy.schema, SCHEMA_EMPTY)

    async def test_log_000(self):
        logging.disable(logging.ERROR)  # to disable logging in ramses_rf.message

        for filename in LOG_FILES:
            await self.proc_log_file(filename)


if __name__ == "__main__":
    unittest.main()
