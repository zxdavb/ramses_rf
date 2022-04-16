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
from common import GWY_CONFIG, TEST_DIR, shuffle_dict  # noqa: F401

from ramses_rf import Gateway
from ramses_rf.helpers import shrink
from ramses_rf.schema import (
    SCHEMA_DHW,
    SCHEMA_ZON,
    SZ_ACTUATORS,
    SZ_DHW_VALVE,
    SZ_HTG_VALVE,
    SZ_KLASS,
    SZ_SENSOR,
    load_schema,
)

SCHEMA_DIR = f"{TEST_DIR}/schemas"

JSN_FILES = (
    "schema_100",
    "schema_101",
    "schema_102",
    "schema_103",
    "schema_104",
    "schema_105",
    "schema_108",
)
LOG_FILES = (
    "schema_201",
    "schema_202",
    "schema_210",
    "schema_211",
    "schema_212",
    "schema_213",
    "schema_000",
    "schema_001",
    "schema_002",
)

RADIATOR_VALVE = "radiator_valve"


class TestSchemaBits(unittest.TestCase):
    def _test_system_schema(self):
        """Test the DHW schema.

        dhw:
            sensor: 07:777777
            hotwater_valve: 13:111111
            heating_valve: 13:222222
        """

        # self.assertEqual(True, False)

        for dict_ in (
            SCHEMA_DHW({}),
            {SZ_SENSOR: None, SZ_DHW_VALVE: None, SZ_HTG_VALVE: None},
        ):
            self.assertEqual(
                dict_, {"sensor": None, "hotwater_valve": None, "heating_valve": None}
            )

        for key in (SZ_SENSOR, SZ_DHW_VALVE, SZ_HTG_VALVE):
            self.assertRaises(vol.error.MultipleInvalid, SCHEMA_DHW, {key: "99:000000"})
            self.assertEqual(
                SCHEMA_DHW({key: None}),
                {SZ_SENSOR: None, SZ_DHW_VALVE: None, SZ_HTG_VALVE: None},
            )

    def _test_SCHEMA_ZON(self):
        """Test the zone schema.

        '01':
            class: radiator_valve
            sensor: 22:032844
            actuators:
            - 04:111111
            - 04:222222
        """

        for dict_ in (
            SCHEMA_ZON({}),
            {SZ_KLASS: None, SZ_ACTUATORS: [], SZ_SENSOR: None},
        ):
            self.assertEqual(dict_, {"class": None, "sensor": None, "actuators": []})

        for key in (SZ_KLASS, SZ_SENSOR):
            self.assertRaises(vol.error.MultipleInvalid, SCHEMA_ZON, {key: "99:000000"})
            self.assertEqual(
                SCHEMA_ZON({key: None}),
                {SZ_KLASS: None, SZ_ACTUATORS: [], SZ_SENSOR: None},
            )

        self.assertEqual(
            SCHEMA_ZON({SZ_KLASS: RADIATOR_VALVE}),
            {SZ_KLASS: RADIATOR_VALVE, SZ_ACTUATORS: [], SZ_SENSOR: None},
        )

        self.assertEqual(
            SCHEMA_ZON({SZ_SENSOR: "34:111111"}),
            {SZ_KLASS: None, SZ_ACTUATORS: [], SZ_SENSOR: "34:111111"},
        )

        for val in (
            None,
            ["_invalid_"],
            "13:111111",
        ):  # NOTE: should be a *list* of device_ids
            self.assertRaises(
                vol.error.MultipleInvalid, SCHEMA_ZON, {SZ_ACTUATORS: val}
            )

        for val in ([], ["13:111111"], ["13:222222", "13:111111"]):
            self.assertEqual(
                SCHEMA_ZON({SZ_ACTUATORS: val}),
                {SZ_KLASS: None, SZ_ACTUATORS: val, SZ_SENSOR: None},
            )


class TestSchemaDiscovery(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    # def setUp(self):
    #     logging.basicConfig(level=logging.DEBUG)
    #     logging.getLogger().setLevel(logging.DEBUG)

    #     logging.disable(logging.DEBUG)

    async def _proc_log_file(self, f_name):
        with open(f"{SCHEMA_DIR}/{f_name}.log") as f:
            self.gwy = Gateway(
                None, input_file=f, config=GWY_CONFIG, loop=self._asyncioTestLoop
            )
            await self.gwy.start()

        with open(f"{SCHEMA_DIR}/{f_name}.json") as f:
            schema = json.load(f)

        # print(json.dumps(self.gwy.schema, indent=4))
        # print(json.dumps(schema, indent=4))

        self.assertEqual(
            json.dumps(shrink(self.gwy.schema), indent=4),
            json.dumps(shrink(schema), indent=4),
        )

        # self.assertEqual(
        #     shrink(schema),
        #     shrink(self.gwy.schema),
        # )

        self.gwy.serial_port = "/dev/null"  # HACK: needed to pause engine
        schema, packets = self.gwy._get_state(include_expired=True)
        packets = shuffle_dict(packets)
        await self.gwy._set_state(packets, clear_state=True)

        self.assertEqual(
            shrink(schema),
            shrink(self.gwy.schema),
        )

    async def test_from_log_files(self):
        for f_name in LOG_FILES:
            self.gwy = None
            await self._proc_log_file(f_name)


class TestSchemaLoad(unittest.IsolatedAsyncioTestCase):

    gwy = Gateway("/dev/null", config=GWY_CONFIG, loop=asyncio.get_event_loop())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None

        self.gwy.config.disable_sending = True

    async def _proc_jsn_file(self, f_name):

        with open(f"{SCHEMA_DIR}/{f_name}.json") as f:
            schema = json.load(f)

        load_schema(self.gwy, **schema)

        # print(json.dumps(schema, indent=4))
        # print(json.dumps(self.gwy.schema, indent=4))

        self.assertEqual(
            shrink(schema),
            shrink(self.gwy.schema),
        )

        # HACK: await self.gwy._set_state({}, clear_state=True)
        self.gwy._tcs = None
        self.gwy.devices = []
        self.gwy.device_by_id = {}

    async def test_from_jsn_files(self):
        for f_name in JSN_FILES:
            await self._proc_jsn_file(f_name)

        # print(*self.gwy._tasks)
        # await asyncio.gather(*self.gwy._tasks)


if __name__ == "__main__":
    unittest.main()
