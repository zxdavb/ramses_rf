#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the various helper APIs.
"""

import unittest

from ramses_rf.zones import _transform

GWY_CONFIG = {}


class TestApisBase(unittest.IsolatedAsyncioTestCase):
    def test_transform(self) -> None:
        self.assertEqual(
            [x[1] for x in TRANSFORMS], [_transform(x[0]) for x in TRANSFORMS]
        )


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
