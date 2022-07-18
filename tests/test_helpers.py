#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the various helper APIs.
"""

# TODO: add test for ramses_rf.protocol.frame.pkt_header()

from ramses_rf.const import DEV_ROLE_MAP, DEV_TYPE_MAP
from ramses_rf.protocol.const import attr_dict_factory
from ramses_rf.protocol.helpers import (
    bool_from_hex,
    bool_to_hex,
    double_from_hex,
    double_to_hex,
    dtm_from_hex,
    dtm_to_hex,
    dts_from_hex,
    dts_to_hex,
)
from ramses_rf.protocol.packet import Packet
from ramses_rf.system.zones import _transform
from tests.common import gwy  # noqa: F401
from tests.common import TEST_DIR, assert_raises

WORK_DIR = f"{TEST_DIR}/helpers"


def test_pkt_addr_parser(gwy):  # noqa: F811
    def proc_log_line(gwy, pkt_line):
        if "#" not in pkt_line:
            return

        pkt_line, pkt_dict = pkt_line.split("#", maxsplit=1)

        if not pkt_line[27:].strip():
            return

        pkt = Packet.from_file(gwy, pkt_line[:26], pkt_line[27:])

        assert (pkt.src.id, pkt.dst.id) == eval(pkt_dict)

    with open(f"{WORK_DIR}/pkt_addrs.log") as f:
        while line := (f.readline()):
            if line.strip():
                proc_log_line(gwy, line)


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
        "HTG" not in DEV_ROLE_MAP.keys()
        and "0E" in DEV_ROLE_MAP.keys()
        and "heating_relay" not in DEV_ROLE_MAP.keys()
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


def test_demand_transform() -> None:
    assert [x[1] for x in TRANSFORMS] == [_transform(x[0]) for x in TRANSFORMS]


def test_field_parsers() -> None:
    for val in ("FF", "00", "C8"):
        assert val == bool_to_hex(bool_from_hex(val))

    for val in ("7FFF", "0000", "0001", "0010", "0100", "1000"):
        assert val == double_to_hex(double_from_hex(val))
        assert val == double_to_hex(double_from_hex(val, factor=100), factor=100)

    for val in (
        "FF" * 6,
        "FF" * 7,
        "00141B0A07E3",
        "00110E0507E5",
        "0400041C0A07E3",
    ):
        assert val == dtm_to_hex(dtm_from_hex(val), incl_seconds=(len(val) == 14))

    for val in ("00000000007F",):
        assert val == dts_to_hex(dts_from_hex(val))


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


TRANSFORMS = [
    (0.000, 0),
    (0.220, 0),
    (0.230, 0),
    (0.260, 0),
    # (0.295, 0),  # needs confirming
    (0.300, 0),
    # (0.305, 0),  # needs confirming
    (0.310, 0.01),
    (0.340, 0.03),
    (0.350, 0.04),
    (0.370, 0.05),
    (0.380, 0.06),
    (0.390, 0.07),
    (0.400, 0.08),
    (0.410, 0.08),
    (0.420, 0.09),
    (0.430, 0.10),
    (0.450, 0.11),
    (0.470, 0.13),
    (0.480, 0.14),
    (0.530, 0.17),
    (0.540, 0.18),
    (0.550, 0.19),
    (0.560, 0.20),
    (0.575, 0.21),
    (0.610, 0.23),
    (0.620, 0.24),
    (0.650, 0.26),
    (0.660, 0.27),
    (0.680, 0.29),
    (0.690, 0.29),
    # (0.695, 0.30),  # needs confirming
    (0.700, 0.30),
    # (0.705, 0.31),  # needs confirming
    (0.720, 0.35),
    (0.740, 0.39),
    (0.760, 0.44),
    (0.770, 0.46),
    (0.790, 0.51),
    (0.800, 0.53),
    (0.820, 0.58),
    (0.830, 0.60),
    (0.840, 0.63),
    (0.930, 0.84),
    (0.950, 0.88),
    # (0.995, 0.99),  # needs confirming
    (1.000, 1.0),
]
