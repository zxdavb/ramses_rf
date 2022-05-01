#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import voluptuous as vol

from ramses_rf.schema import (
    SCHEMA_DHW,
    SCHEMA_ZON,
    SZ_ACTUATORS,
    SZ_CLASS,
    SZ_DHW_VALVE,
    SZ_HTG_VALVE,
    SZ_SENSOR,
)
from tests.common import assert_raises

RADIATOR_VALVE = "radiator_valve"


def test_system_schema():
    """Test the DHW schema.

    dhw:
        sensor: 07:777777
        hotwater_valve: 13:111111
        heating_valve: 13:222222
    """

    for dict_ in (
        SCHEMA_DHW({}),
        {SZ_SENSOR: None, SZ_DHW_VALVE: None, SZ_HTG_VALVE: None},
    ):
        assert dict_ == {SZ_SENSOR: None, "hotwater_valve": None, "heating_valve": None}

    for key in (SZ_SENSOR, SZ_DHW_VALVE, SZ_HTG_VALVE):
        assert_raises(vol.error.MultipleInvalid, SCHEMA_DHW, {key: "99:000000"})
        assert SCHEMA_DHW({key: None}) == {
            SZ_SENSOR: None,
            SZ_DHW_VALVE: None,
            SZ_HTG_VALVE: None,
        }


def test_zone_schema():
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
        {SZ_CLASS: None, SZ_SENSOR: None, SZ_ACTUATORS: []},
    ):
        assert dict_ == {SZ_CLASS: None, SZ_SENSOR: None, SZ_ACTUATORS: []}

    for key in (SZ_CLASS, SZ_SENSOR):
        assert_raises(vol.error.MultipleInvalid, SCHEMA_ZON, {key: "99:000000"})
        assert SCHEMA_ZON({key: None}) == {
            SZ_CLASS: None,
            SZ_SENSOR: None,
            SZ_ACTUATORS: [],
        }

    assert SCHEMA_ZON({SZ_CLASS: RADIATOR_VALVE}) == {
        SZ_CLASS: RADIATOR_VALVE,
        SZ_SENSOR: None,
        SZ_ACTUATORS: [],
    }

    assert SCHEMA_ZON({SZ_SENSOR: "34:111111"}) == {
        SZ_CLASS: None,
        SZ_ACTUATORS: [],
        SZ_SENSOR: "34:111111",
    }

    for val in (
        None,
        "_invalid_",
        "13:111111",
    ):  # NOTE: should be a *list* of device_ids
        assert_raises(vol.error.MultipleInvalid, SCHEMA_ZON, {SZ_ACTUATORS: val})

    for val in ([], ["13:111111"], ["13:222222", "13:111111"]):
        assert SCHEMA_ZON({SZ_ACTUATORS: val}) == {
            SZ_CLASS: None,
            SZ_ACTUATORS: val,
            SZ_SENSOR: None,
        }
