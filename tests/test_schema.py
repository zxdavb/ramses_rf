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
from ramses_rf.helpers import clean
from ramses_rf.schema import (
    DHW_SCHEMA,
    SZ_DEVICES,
    SZ_DHW_SENSOR,
    SZ_DHW_VALVE,
    SZ_DHW_VALVE_HTG,
    SZ_KLASS,
    SZ_SENSOR,
    ZONE_SCHEMA,
    load_schema,
)

GWY_CONFIG = {}

TEST_DIR = f"{os.path.dirname(__file__)}"

RADIATOR_VALVE = "radiator_valve"


logging.disable(logging.WARNING)


class TestSchemaBits(unittest.TestCase):
    def test_system_schema(self):
        """Test the DHW schema.

        dhw:
            sensor: 07:777777
            hotwater_valve: 13:111111
            heating_valve: 13:222222
        """

        # self.assertEqual(True, False)

        for dict_ in (
            DHW_SCHEMA({}),
            {SZ_DHW_SENSOR: None, SZ_DHW_VALVE: None, SZ_DHW_VALVE_HTG: None},
        ):
            self.assertEqual(
                dict_,
                {"sensor": None, "hotwater_valve": None, "heating_valve": None},
            )

    def test_zone_schema(self):
        """Test the zone schema.

        '01':
            class: radiator_valve
            sensor: 22:032844
            actuators:
            - 04:111111
            - 04:222222
        """

        for dict_ in (
            ZONE_SCHEMA({}),
            {SZ_KLASS: None, SZ_DEVICES: [], SZ_SENSOR: None},
        ):
            self.assertEqual(
                dict_,
                {"class": None, "sensor": None, "devices": []},
            )

        for key in (SZ_KLASS, SZ_SENSOR):
            self.assertRaises(
                vol.error.MultipleInvalid, ZONE_SCHEMA, {key: "_invalid_"}
            )

            self.assertEqual(
                ZONE_SCHEMA({key: None}),
                {SZ_KLASS: None, SZ_DEVICES: [], SZ_SENSOR: None},
            )

        self.assertEqual(
            ZONE_SCHEMA({SZ_KLASS: RADIATOR_VALVE}),
            {SZ_KLASS: RADIATOR_VALVE, SZ_DEVICES: [], SZ_SENSOR: None},
        )

        self.assertEqual(
            ZONE_SCHEMA({SZ_SENSOR: "34:111111"}),
            {SZ_KLASS: None, SZ_DEVICES: [], SZ_SENSOR: "34:111111"},
        )

        for val in (
            None,
            ["_invalid_"],
            "13:111111",
        ):  # NOTE: should be a *list* of device_ids
            self.assertRaises(vol.error.MultipleInvalid, ZONE_SCHEMA, {SZ_DEVICES: val})

        for val in ([], ["13:111111"], ["13:222222", "13:111111"]):
            self.assertEqual(
                ZONE_SCHEMA({SZ_DEVICES: val}),
                {SZ_KLASS: None, SZ_DEVICES: val, SZ_SENSOR: None},
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

        self.assertEqual(schema, self.gwy.schema)


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
