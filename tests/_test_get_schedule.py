#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import json
import os
import unittest

from ramses_rf import Gateway

GWY_CONFIG = {}

TEST_DIR = f"{os.path.dirname(__file__)}"


class TestSetApis(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def test_log_000(self):
        self.gwy = Gateway(
            None, packet_dict={}, config=GWY_CONFIG, loop=self._asyncioTestLoop
        )
        with open(f"{TEST_DIR}/logs/system_cache.json") as f:
            system_cache = json.load(f)
        await self.gwy._set_state(**system_cache["data"]["client_state"])

        # self.assertEqual(self.gwy.schema, schema)


if __name__ == "__main__":
    unittest.main()
