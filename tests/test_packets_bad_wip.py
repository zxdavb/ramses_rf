#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import logging
import unittest

from ramses_rf import Gateway
from tests.common import TEST_DIR  # noqa: F401

LOG_DIR = f"{TEST_DIR}/logs"
LOG_FILES = ("pkts_bad_000.log",)

SCHEMA_EMPTY = {"device_hints": {}, "main_controller": None, "orphans": []}


class TestSetApis(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def proc_log_file(self, f_name):
        with open(f"{LOG_DIR}/{f_name}") as f:
            self.gwy = Gateway(
                None, input_file=f, config={}, loop=self._asyncioTestLoop
            )
            await self.gwy.start()

        self.assertEqual(self.gwy.schema, SCHEMA_EMPTY)

    async def test_all_log_files(self):
        logging.disable(logging.ERROR)  # to disable logging in ramses_rf.message

        for f_name in LOG_FILES:
            with self.subTest(f_name):
                await self.proc_log_file(f_name)


if __name__ == "__main__":
    unittest.main()
