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


class TestSchema(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def test_log_000(self):
        with open(f"{TEST_DIR}/schemas/schema_000.log") as f:
            self.gwy = Gateway(
                None, input_file=f, config=GWY_CONFIG, loop=self._asyncioTestLoop
            )
            await self.gwy.start()

        with open(f"{TEST_DIR}/schemas/schema_000.json") as f:
            schema = json.load(f)

        # print(json.dumps(self.gwy.schema, indent=4))
        # print(json.dumps(schema, indent=4))

        self.assertEqual(self.gwy.schema, schema)


if __name__ == "__main__":
    unittest.main()
