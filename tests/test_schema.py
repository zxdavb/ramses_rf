#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import asyncio
import json
import logging
import os
import unittest

import voluptuous as vol

from ramses_rf import Gateway
from ramses_rf.const import SZ_DEVICES, SZ_SENSOR
from ramses_rf.schema import SZ_CLASS, ZONE_SCHEMA, load_schema

GWY_CONFIG = {}

TEST_DIR = f"{os.path.dirname(__file__)}"

RADIATOR_VALVE = "radiator_valve"


logging.disable(logging.WARNING)


def clean(node) -> dict:
    """Walk through a dict and remove all the meaningless items.

    Specifically: removes uwanted keys (starting with '_') and falsey values.
    """

    if isinstance(node, dict):
        return {k: clean(v) for k, v in node.items() if k[:1] != "_" and clean(v)}
    elif isinstance(node, list):
        return [clean(x) for x in node if x]
    else:
        return node


class TestSchemaBits(unittest.TestCase):
    def test_zone_schema(self):

        self.assertEqual(
            ZONE_SCHEMA({}),
            {SZ_CLASS: None, SZ_DEVICES: [], SZ_SENSOR: None},
        )

        for key in (SZ_CLASS, SZ_SENSOR):
            self.assertRaises(
                vol.error.MultipleInvalid, ZONE_SCHEMA, {key: "_invalid_"}
            )

            self.assertEqual(
                ZONE_SCHEMA({key: None}),
                {SZ_CLASS: None, SZ_DEVICES: [], SZ_SENSOR: None},
            )

        self.assertEqual(
            ZONE_SCHEMA({SZ_CLASS: RADIATOR_VALVE}),
            {SZ_CLASS: RADIATOR_VALVE, SZ_DEVICES: [], SZ_SENSOR: None},
        )

        self.assertEqual(
            ZONE_SCHEMA({SZ_SENSOR: "34:111111"}),
            {SZ_CLASS: None, SZ_DEVICES: [], SZ_SENSOR: "34:111111"},
        )

        for val in (None, ["_invalid_"], "13:111111"):
            self.assertRaises(
                vol.error.MultipleInvalid, ZONE_SCHEMA, {SZ_DEVICES: val}
            )  # NOTE: should be a *list* of device_ids

        for val in ([], ["13:111111"], ["13:222222", "13:111111"]):
            self.assertEqual(
                ZONE_SCHEMA({SZ_DEVICES: val}),
                {SZ_CLASS: None, SZ_DEVICES: val, SZ_SENSOR: None},
            )


class TestSchemaDiscovery(unittest.IsolatedAsyncioTestCase):
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

        self.assertEqual(self.gwy.schema, schema)


class TestSchemaLoad(unittest.TestCase):

    gwy = Gateway(None, config=GWY_CONFIG, loop=asyncio.get_event_loop())

    # def __init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)

    #     self.maxDiff = None

    def test_log_001(self):

        with open(f"{TEST_DIR}/schemas/schema_001.json") as f:
            schema = json.load(f)
        load_schema(self.gwy, **schema)

        self.assertEqual(clean(schema), clean({self.gwy.evo.id: self.gwy.evo.schema}))


if __name__ == "__main__":
    unittest.main()
