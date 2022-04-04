#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import asyncio
import json
import unittest

import voluptuous as vol
from common import GWY_CONFIG, TEST_DIR  # noqa: F401

from ramses_rf import Gateway
from ramses_rf.helpers import shrink
from ramses_rf.schema import (
    DHW_SCHEMA,
    SZ_ACTUATORS,
    SZ_DHW_VALVE,
    SZ_DHW_VALVE_HTG,
    SZ_KLASS,
    SZ_SENSOR,
    ZONE_SCHEMA,
    load_schema,
)

# from random import shuffle


SCHEMA_DIR = f"{TEST_DIR}/schema"
LOG_FILES = (
    "schema_000",
    "schema_001",
    "schema_002",
)
JSN_FILES = ("schema_100",)  # , "schema_109")

RADIATOR_VALVE = "radiator_valve"


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
            {SZ_SENSOR: None, SZ_DHW_VALVE: None, SZ_DHW_VALVE_HTG: None},
        ):
            self.assertEqual(
                dict_, {"sensor": None, "hotwater_valve": None, "heating_valve": None}
            )

        for key in (SZ_SENSOR, SZ_DHW_VALVE, SZ_DHW_VALVE_HTG):
            self.assertRaises(vol.error.MultipleInvalid, DHW_SCHEMA, {key: "99:000000"})
            self.assertEqual(
                DHW_SCHEMA({key: None}),
                {SZ_SENSOR: None, SZ_DHW_VALVE: None, SZ_DHW_VALVE_HTG: None},
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
            {SZ_KLASS: None, SZ_ACTUATORS: [], SZ_SENSOR: None},
        ):
            self.assertEqual(dict_, {"class": None, "sensor": None, "actuators": []})

        for key in (SZ_KLASS, SZ_SENSOR):
            self.assertRaises(
                vol.error.MultipleInvalid, ZONE_SCHEMA, {key: "99:000000"}
            )
            self.assertEqual(
                ZONE_SCHEMA({key: None}),
                {SZ_KLASS: None, SZ_ACTUATORS: [], SZ_SENSOR: None},
            )

        self.assertEqual(
            ZONE_SCHEMA({SZ_KLASS: RADIATOR_VALVE}),
            {SZ_KLASS: RADIATOR_VALVE, SZ_ACTUATORS: [], SZ_SENSOR: None},
        )

        self.assertEqual(
            ZONE_SCHEMA({SZ_SENSOR: "34:111111"}),
            {SZ_KLASS: None, SZ_ACTUATORS: [], SZ_SENSOR: "34:111111"},
        )

        for val in (
            None,
            ["_invalid_"],
            "13:111111",
        ):  # NOTE: should be a *list* of device_ids
            self.assertRaises(
                vol.error.MultipleInvalid, ZONE_SCHEMA, {SZ_ACTUATORS: val}
            )

        for val in ([], ["13:111111"], ["13:222222", "13:111111"]):
            self.assertEqual(
                ZONE_SCHEMA({SZ_ACTUATORS: val}),
                {SZ_KLASS: None, SZ_ACTUATORS: val, SZ_SENSOR: None},
            )


class TestSchemaDiscovery(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def _proc_log_file(self, f_name):
        with open(f"{SCHEMA_DIR}/{f_name}.log") as f:
            self.gwy = Gateway(
                None, input_file=f, config=GWY_CONFIG, loop=self._asyncioTestLoop
            )
            await self.gwy.start()

        with open(f"{SCHEMA_DIR}/{f_name}.json") as f:
            schema = json.load(f)

        # print(json.dumps(schema, indent=4))
        # print(json.dumps(self.gwy.schema, indent=4))

        self.assertEqual(self.gwy.schema, schema)

        # self.assertEqual(
        #     json.dumps(shrink(self.gwy.schema), indent=4),
        #     json.dumps(shrink(schema), indent=4),
        # )

        # print("***")
        # schema, packets = self.gwy._get_state(include_expired=True)
        # shuffle(packets)
        # self.gwy._set_state(packets, clear_state=True)
        # print("ZZZ")

    async def _test_from_log_files(self):
        for f_name in LOG_FILES:
            self.gwy = None
            await self._proc_log_file(f_name)


class TestSchemaLoad(unittest.TestCase):

    gwy = Gateway(None, config=GWY_CONFIG, loop=asyncio.get_event_loop())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None

    def _proc_jsn_file(self, f_name):

        with open(f"{SCHEMA_DIR}/{f_name}.json") as f:
            schema = json.load(f)

        load_schema(self.gwy, **schema)

        print(json.dumps(schema, indent=4))
        print(json.dumps(self.gwy.schema, indent=4))

        self.assertEqual(
            shrink(schema),
            shrink(self.gwy.schema),
        )

    def test_from_jsn_files(self):
        for f_name in JSN_FILES:
            self._proc_jsn_file(f_name)


if __name__ == "__main__":
    unittest.main()
