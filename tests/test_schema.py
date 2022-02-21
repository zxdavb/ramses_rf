#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import asyncio
import json
import os
import unittest
from datetime import datetime as dt

from ramses_rf import Gateway
from ramses_rf.const import HGI_DEVICE_ID
from ramses_rf.schema import CONFIG, INPUT_FILE, PACKET_LOG

GWY_CONFIG = {}

LOG_DIR = f"{os.path.dirname(__file__)}/logs"


class TestSetApis(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def test_log_00(self):
        with open(f"{LOG_DIR}/schema_000.log") as f:
            self.gwy = Gateway(
                None, input_file=f, config=GWY_CONFIG, loop=self._asyncioTestLoop
            )
            await self.gwy.start()

        with open(f"{LOG_DIR}/schema_000.json") as f:
            schema = json.load(f)

        # print(json.dumps(self._gwy.schema, indent=4))
        # print(json.dumps(schema, indent=4))

        self.assertEqual(self.gwy.schema, schema)


if __name__ == "__main__":
    unittest.main()
