#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the various helper APIs.
"""

import unittest

from common import GWY_CONFIG, TEST_DIR  # noqa: F401

from ramses_rf.const import DEV_CLASS_MAP
from ramses_rf.protocol.const import attr_dict_factory
from ramses_rf.zones import _transform


class TestClasses(unittest.TestCase):
    def test_attrdict(self) -> None:
        _ = attr_dict_factory(MAIN_DICT, attr_table=ATTR_DICT)

        try:
            DEV_CLASS_MAP["_08"]
        except KeyError:
            self.assertTrue(True)
        else:
            self.assertTrue(False)

        self.assertEqual(DEV_CLASS_MAP.DHW, "0D")
        self.assertEqual(DEV_CLASS_MAP._0D, "dhw_sensor")
        self.assertEqual(DEV_CLASS_MAP.DHW_SENSOR, "0D")

        self.assertEqual(DEV_CLASS_MAP["RAD"], "rad_actuator")
        self.assertEqual(DEV_CLASS_MAP["08"], "rad_actuator")
        self.assertEqual(DEV_CLASS_MAP["rad_actuator"], "08")

        self.assertEqual(DEV_CLASS_MAP._hex("SEN"), "04")
        self.assertRaises(KeyError, DEV_CLASS_MAP._hex, "04")
        self.assertEqual(DEV_CLASS_MAP._hex("zone_sensor"), "04")

        self.assertEqual(DEV_CLASS_MAP._str("OUT"), "out_sensor")
        self.assertEqual(DEV_CLASS_MAP._str("0C"), "out_sensor")
        self.assertRaises(KeyError, DEV_CLASS_MAP._str, "out_sensor")

        self.assertRaises(KeyError, DEV_CLASS_MAP.slug, "RFG")
        self.assertEqual(DEV_CLASS_MAP.slug("10"), "RFG")
        self.assertRaises(KeyError, DEV_CLASS_MAP.slug, "remote_gateway")

        self.assertTrue(
            "HTG" not in DEV_CLASS_MAP.keys()
            and "0E" in DEV_CLASS_MAP.keys()
            and "heating_relay" not in DEV_CLASS_MAP.keys()
        )
        self.assertTrue(
            "DHW" not in DEV_CLASS_MAP.values()
            and "0D" not in DEV_CLASS_MAP.values()
            and "dhw_sensor" in DEV_CLASS_MAP.values()
        )

        self.assertTrue(
            "DHW" in DEV_CLASS_MAP.slugs()
            and "0D" not in DEV_CLASS_MAP.slugs()
            and "dhw_sensor" not in DEV_CLASS_MAP.slugs()
        )

        self.assertEqual(DEV_CLASS_MAP.SLUGS, MAIN_SLUGS)
        self.assertEqual(
            DEV_CLASS_MAP.HEAT_DEVICES, ("00", "04", "08", "09", "0A", "0B", "11")
        )


class TestHelpers(unittest.TestCase):
    def test_transform(self) -> None:
        self.assertEqual(
            [x[1] for x in TRANSFORMS], [_transform(x[0]) for x in TRANSFORMS]
        )


MAIN_DICT = {
    "ACT": {"00": "zone_actuator"},
    "SEN": {"04": "zone_sensor"},
    "RAD": {"08": "rad_actuator"},
    "UFH": {"09": "ufh_actuator"},
    "VAL": {"0A": "val_actuator"},
    "MIX": {"0B": "mix_actuator"},
    "OUT": {"0C": "out_sensor"},
    "DHW": {"0D": "dhw_sensor"},
    "HTG": {"0E": "heating_relay"},
    "APP": {"0F": "system_relay"},
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

if __name__ == "__main__":
    unittest.main()
