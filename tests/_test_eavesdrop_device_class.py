#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test eavesdropping of a device class.
"""

import unittest
from datetime import datetime as dt
from random import shuffle

from common import GWY_CONFIG, TEST_DIR  # noqa: F401

from ramses_rf import Gateway


class DeviceClass(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.maxDiff = None
        self.gwy = None

    async def test_000(self):

        self.gwy = Gateway("/dev/null", config={}, loop=self._asyncioTestLoop)
        self.assertEqual({d.id: d._SLUG for d in self.gwy.devices}, {})

        await self.gwy._set_state(
            {dt.now().isoformat(): f"... {p}" for p in PACKET_SRC}
        )
        self.assertEqual({d.id: d._SLUG for d in self.gwy.devices}, DEVICE_KLASS)  #

        await self.gwy._set_state({})
        self.assertEqual({d.id: d._SLUG for d in self.gwy.devices}, {})

        # shuffle(PACKET_SRC)

        # await self.gwy._set_state(
        #     {dt.now().isoformat(): f"... {p}" for p in PACKET_SRC}
        # )
        # self.assertEqual({d.id: d._SLUG for d in self.gwy.devices}, DEVICE_KLASS)

        # shuffle(PACKET_SRC)

        # await self.gwy._set_state(
        #     {dt.now().isoformat(): f"... {p}" for p in PACKET_SRC}
        # )
        # self.assertEqual({d.id: d._SLUG for d in self.gwy.devices}, DEVICE_KLASS)


PACKET_SRC = [
    # " I --- --:------ --:------ 01:111111 1060 003 00FF01",
    # " I --- --:------ --:------ 01:111111 22F3 003 000014",
    " I --- --:------ --:------ 42:111111 1060 003 00FF01",
    " I --- --:------ --:------ 42:111111 22F3 003 000014",

    # " I --- --:------ --:------ 02:222222 31E0 003 00000100",
    # " I --- --:------ --:------ 02:222222 22F3 003 000014",
    " I --- --:------ --:------ 52:222222 31E0 003 00000100",
    " I --- --:------ --:------ 52:222222 22F3 003 000014",

    # " I --- --:------ --:------ 04:333333 31E0 003 00000100",
    # " I --- --:------ --:------ 04:333333 31D9 003 000050",
    " I --- --:------ --:------ 24:333333 31E0 003 00000100",
    " I --- --:------ --:------ 24:333333 31D9 003 000050",

    # " I --- 13:444444 13:444444 --:------ 31E0 004 00000100",
    # " I --- 13:444444 --:------ 29:444444 12A0 006 002B06050126",
    " I --- 29:444444 29:444444 --:------ 31E0 004 00000100",
    " I --- 29:444444 --:------ 29:444444 12A0 006 002B06050126",

    # " I --- 07:888888 13:888888 --:------ 1060 004 00FF01",
    # " I --- 07:888888 --:------ 29:888888 12A0 006 002B06050126",
    " I --- 29:888888 29:888888 --:------ 1060 004 00FF01",
    " I --- 29:888888 --:------ 29:888888 12A0 006 002B06050126",

    # " I --- 01:555555 --:------ 01:555555 1060 003 00FF01",
    # " I --- 01:555555 37:999999 --:------ 31E0 004 00000100",
    " I --- 37:555555 --:------ 37:555555 1060 003 00FF01",
    " I --- 37:555555 37:999999 --:------ 31E0 004 00000100",

    # " I --- 02:666666 37:999999 --:------ 31E0 004 00000100",
    # " I --- 02:666666 --:------ 02:666666 1298 003 000247",
    " I --- 37:666666 37:999999 --:------ 31E0 004 00000100",
    " I --- 37:666666 --:------ 37:666666 1298 003 000247",

    # " I --- 07:777777 --:------ 77:777777 1060 003 00FF01",
    # " I --- 07:777777 --:------ 07:777777 1298 003 000247",
    " I --- 37:777777 --:------ 37:777777 1060 003 00FF01",
    " I --- 37:777777 --:------ 37:777777 1298 003 000247",

    " I --- 37:999999 --:------ 37:999999 31DA 029 00C840020434EF7FFF7FFF7FFF7FFFF808EF1801000000EFEF7FFF7FFF",
]
DEVICE_KLASS = {
    "42:111111": "SWI",  # "01:111111": "CTL",
    "52:222222": "SWI",  # "02:222222": "UFC",
    "24:333333": "FAN",  # "04:333333": "TRV",
    "29:444444": "HUM",  # "13:444444": "BDR",
    "37:555555": "HVC",  # "01:555555": "CTL",
    "37:666666": "CO2",  # "02:666666": "UFC",
    "37:777777": "CO2",  # "07:777777": "DHW",
    "29:888888": "HUM",  # "07:888888": "DHW",
    "37:999999": "FAN",
}

if __name__ == "__main__":
    unittest.main()
