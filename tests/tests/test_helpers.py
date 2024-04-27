#!/usr/bin/env python3
"""RAMSES RF - Test the various helper APIs."""

# TODO: add test for ramses_tx.frame.pkt_header()

from typing import Any

from ramses_rf.const import DEV_ROLE_MAP, DEV_TYPE_MAP
from ramses_rf.helpers import deep_merge
from ramses_tx.const import attr_dict_factory

from .helpers import assert_raises


def test_merge_dicts() -> None:
    """Deep merge a src dict (precident) into a dst dict and return the result."""

    src: dict[str, Any]
    dst: dict[str, Any]
    out: dict[str, Any]

    src = {"top": {"deep": {"in_both": "1", "in_src": "dog"}}}
    dst = {"top": {"deep": {"in_both": "9", "in_dst": "cat"}}}
    out = {"top": {"deep": {"in_both": "1", "in_src": "dog", "in_dst": "cat"}}}
    assert out == deep_merge(src, dst)

    assert out != dst
    assert out == deep_merge(src, dst, _dc=True)
    assert out == dst

    src = {"top": {"deep": {"in_both": [0, 1]}}}
    dst = {"top": {"deep": {"in_both": [0, 9]}}}
    out = {"top": {"deep": {"in_both": [0, 1, 9]}}}
    assert out == deep_merge(src, dst)

    src = {"top": {"deep": {"in_both": "non-list"}}}
    dst = {"top": {"deep": {"in_both": [0, 9]}}}
    out = {"top": {"deep": {"in_both": "non-list"}}}
    assert out == deep_merge(src, dst)

    src = {"top": {"deep": {"in_both": [0, 1]}}}
    dst = {"top": {"deep": {"in_both": "non-list"}}}
    out = {"top": {"deep": {"in_both": [0, 1]}}}
    assert out == deep_merge(src, dst)


def test_attrdict_class() -> None:
    _ = attr_dict_factory(MAIN_DICT, attr_table=ATTR_DICT)

    assert_raises(KeyError, DEV_TYPE_MAP.slug, "_rubbish_")
    assert_raises(KeyError, DEV_TYPE_MAP.slug, None)
    # assert DEV_TYPE_MAP.slug(None), "DEV")

    try:
        DEV_ROLE_MAP["_08"]
    except KeyError:
        pass
    else:
        assert False

    assert DEV_ROLE_MAP.DHW == "0D"
    assert DEV_ROLE_MAP._0D == "dhw_sensor"
    assert DEV_ROLE_MAP.DHW_SENSOR == "0D"

    assert DEV_ROLE_MAP["RAD"] == "rad_actuator"
    assert DEV_ROLE_MAP["08"] == "rad_actuator"
    assert DEV_ROLE_MAP["rad_actuator"] == "08"

    assert DEV_ROLE_MAP._hex("SEN") == "04"
    assert_raises(KeyError, DEV_ROLE_MAP._hex, "04")  # aka: DEV_ROLE_MAP._hex("04")
    assert DEV_ROLE_MAP._hex("zone_sensor") == "04"

    assert_raises(KeyError, DEV_ROLE_MAP._hex, "_rubbish_")
    assert_raises(KeyError, DEV_ROLE_MAP._hex, None)

    assert DEV_ROLE_MAP._str("OUT") == "out_sensor"
    assert DEV_ROLE_MAP._str("0C") == "out_sensor"
    assert_raises(KeyError, DEV_ROLE_MAP._str, "out_sensor")

    assert_raises(KeyError, DEV_ROLE_MAP._str, "_rubbish_")
    assert_raises(KeyError, DEV_ROLE_MAP._str, None)

    assert_raises(KeyError, DEV_ROLE_MAP.slug, "RFG")  # aka: DEV_ROLE_MAP.slug("RFG")
    assert DEV_ROLE_MAP.slug("10") == "RFG"
    assert DEV_ROLE_MAP.slug("remote_gateway") == "RFG"

    assert_raises(KeyError, DEV_ROLE_MAP.slug, "_rubbish_")
    assert_raises(KeyError, DEV_ROLE_MAP.slug, None)

    assert (
        "HTG" not in DEV_ROLE_MAP
        and "0E" in DEV_ROLE_MAP
        and "heating_relay" not in DEV_ROLE_MAP
    )
    assert (
        "DHW" not in DEV_ROLE_MAP.values()
        and "0D" not in DEV_ROLE_MAP.values()
        and "dhw_sensor" in DEV_ROLE_MAP.values()
    )

    assert (
        "DHW" in DEV_ROLE_MAP.slugs()
        and "0D" not in DEV_ROLE_MAP.slugs()
        and "dhw_sensor" not in DEV_ROLE_MAP.slugs()
    )

    assert DEV_ROLE_MAP.SLUGS, MAIN_SLUGS
    assert DEV_ROLE_MAP.HEAT_DEVICES == ("00", "04", "08", "09", "0A", "0B", "11")


MAIN_DICT = {
    "ACT": {"00": "zone_actuator"},
    "SEN": {"04": "zone_sensor"},
    "RAD": {"08": "rad_actuator"},
    "UFH": {"09": "ufh_actuator"},
    "VAL": {"0A": "val_actuator"},
    "MIX": {"0B": "mix_actuator"},
    "OUT": {"0C": "out_sensor"},
    "DHW": {"0D": "dhw_sensor"},
    "HTG": {"0E": "hotwater_valve"},
    "HT1": {None: "heating_valve"},
    "APP": {"0F": "appliance_control"},
    "RFG": {"10": "remote_gateway"},
    "ELE": {"11": "ele_actuator"},
}
ATTR_DICT = {
    "HEAT_DEVICES": ("08", "09", "0A", "0B", "11"),
}
MAIN_SLUGS = tuple(sorted(MAIN_DICT.keys()))
