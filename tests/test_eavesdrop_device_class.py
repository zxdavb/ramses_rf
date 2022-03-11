#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import logging
import unittest
from datetime import datetime as dt
from random import shuffle

from ramses_rf import Gateway

logging.disable(logging.WARNING)


class DeviceClass(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.gwy = None

    async def test_000(self):

        self.gwy = Gateway("/dev/null", config={}, loop=self._asyncioTestLoop)
        self.assertEqual({d.id: d._klass for d in self.gwy.devices}, {})

        await self.gwy._set_state(
            {dt.now().isoformat(): f"... {p}" for p in PACKET_SRC}, clear_state=True
        )
        self.assertEqual({d.id: d._klass for d in self.gwy.devices}, DEVICE_KLASS)

        await self.gwy._set_state({}, clear_state=True)
        self.assertEqual({d.id: d._klass for d in self.gwy.devices}, {})

        shuffle(PACKET_SRC)

        await self.gwy._set_state(
            {dt.now().isoformat(): f"... {p}" for p in PACKET_SRC}, clear_state=True
        )
        self.assertEqual({d.id: d._klass for d in self.gwy.devices}, DEVICE_KLASS)

        shuffle(PACKET_SRC)

        await self.gwy._set_state(
            {dt.now().isoformat(): f"... {p}" for p in PACKET_SRC}, clear_state=True
        )
        self.assertEqual({d.id: d._klass for d in self.gwy.devices}, DEVICE_KLASS)


PACKET_SRC = [
    # " I --- --:------ --:------ 02:153424 1060 003 00FF01  # breaks things",
    " I --- --:------ --:------ 02:153424 22F3 003 000014",
    " I --- --:------ --:------ 02:153426 31E0 003 00000100",
    " I --- --:------ --:------ 02:153426 22F3 003 000014",
    " I --- --:------ --:------ 20:001468 31D9 003 000050",
    " I --- 29:146052 29:146052 --:------ 31E0 004 00000100",
    " I --- 29:146052 --:------ 29:146052 12A0 006 002B06050126",
    " I --- 37:258500 --:------ 37:258500 1060 003 00FF01",
    " I --- 37:258500 37:261128 --:------ 31E0 004 00000100",
    " I --- 37:258565 37:261128 --:------ 31E0 004 00000100",
    " I --- 37:258565 --:------ 37:258565 1298 003 000247",
    " I --- 37:258566 --:------ 37:258566 1298 003 000247",
    " I --- 37:258567 --:------ 37:258567 1060 003 00FF01",
    " I --- 37:258567 37:261128 --:------ 22F1 003 000507",
    " I --- 37:261128 --:------ 37:261128 31DA 029 00C840020434EF7FFF7FFF7FFF7FFFF808EF1801000000EFEF7FFF7FFF",
]
DEVICE_KLASS = {
    "02:153424": "SWI",
    "02:153426": "SWI",
    "20:001468": "FAN",
    "29:146052": "HUM",
    "37:258500": "DEV",
    "37:258565": "CO2",
    "37:258566": "CO2",
    "37:258567": "SWI",
    "37:261128": "FAN",
}

if __name__ == "__main__":
    unittest.main()
