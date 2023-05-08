#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the gwy Addr detection and the Gateway.send_cmd API from '18:000730'.
"""

import asyncio
from unittest.mock import patch

import pytest

from ramses_rf import Command, Device, Gateway
from tests_rf.virtual_rf import HgiFwTypes, VirtualRf

MIN_GAP_BETWEEN_WRITES = 1
DEFAULT_MAX_SLEEP = 0.005

GWY_ID_ = "18:111111"

CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}


CMDS_COMMON = (  # test command strings
    r" I --- 18:000730 --:------ 18:000730 30C9 003 000666",
    f" I --- 18:000730 --:------ {GWY_ID_} 30C9 003 000777",
    f" I --- {GWY_ID_} --:------ 18:000730 30C9 003 000888",
    f" I --- {GWY_ID_} --:------ {GWY_ID_} 30C9 003 000999",
    r"RQ --- 18:000730 63:262142 --:------ 10E0 001 00",
    f"RQ --- {GWY_ID_} 63:262142 --:------ 10E0 001 00",
)
PKTS_NATIVE = (  # expected packet strings
    f" I --- {GWY_ID_} --:------ {GWY_ID_} 30C9 003 000666",
    f" I --- {GWY_ID_} --:------ {GWY_ID_} 30C9 003 000777",
    f" I --- {GWY_ID_} --:------ {GWY_ID_} 30C9 003 000888",
    f" I --- {GWY_ID_} --:------ {GWY_ID_} 30C9 003 000999",
    f"RQ --- {GWY_ID_} 63:262142 --:------ 10E0 001 00",
    f"RQ --- {GWY_ID_} 63:262142 --:------ 10E0 001 00",
)
PKTS_EVOFW3 = (  # expected packet strings
    f" I --- {GWY_ID_} --:------ 18:000730 30C9 003 000666",  # exception from pkt layer: There is more than one HGI80-compatible gateway: Blacklisting a Foreign gateway (or is it HVAC?): 18:000730 (Active gateway: 18:111111), configure the known_list/block_list as required (consider enforcing a known_list)
    f" I --- {GWY_ID_} --:------ {GWY_ID_} 30C9 003 000777",
    f" I --- {GWY_ID_} --:------ 18:000730 30C9 003 000888",  # exception from pkt layer: There is more than one HGI80-compatible gateway: Blacklisting a Foreign gateway (or is it HVAC?): 18:000730 (Active gateway: 18:111111), configure the known_list/block_list as required (consider enforcing a known_list)
    f" I --- {GWY_ID_} --:------ {GWY_ID_} 30C9 003 000999",
    f"RQ --- {GWY_ID_} 63:262142 --:------ 10E0 001 00",
    f"RQ --- {GWY_ID_} 63:262142 --:------ 10E0 001 00",
)


async def _alert_is_impersonating(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


async def assert_devices(
    gwy: Gateway, devices: list[Device], max_sleep: int = DEFAULT_MAX_SLEEP
):
    for _ in range(int(max_sleep / 0.001)):
        await asyncio.sleep(0.001)
        if len(gwy.devices) == len(devices):
            break
    assert sorted(d.id for d in gwy.devices) == sorted(devices)


async def assert_expected_pkt(
    gwy: Gateway, expected_frame: str, max_sleep: int = DEFAULT_MAX_SLEEP
):
    for _ in range(int(max_sleep / 0.001)):
        await asyncio.sleep(0.001)
        if gwy._this_msg and str(gwy._this_msg._pkt) == expected_frame:
            break
    assert str(gwy._this_msg._pkt) == expected_frame


def pytest_generate_tests(metafunc):
    def id_fnc(param):
        return param._name_

    metafunc.parametrize("test_idx", range(len(CMDS_COMMON)))  # , ids=id_fnc)


@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    _alert_is_impersonating,
)
@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def _test_hgi_addr(fw_version, cmd_str, pkt_str):
    """Check the virtual RF network behaves as expected (device discovery)."""

    rf = VirtualRf(1)
    rf.set_gateway(rf.ports[0], GWY_ID_, fw_version=fw_version)

    gwy_0 = Gateway(rf.ports[0], **CONFIG)  # , known_list={GWY_ID_: {"class": "HGI"}})
    assert gwy_0.devices == []
    assert gwy_0.hgi is None

    await gwy_0.start()
    await assert_devices(gwy_0, [GWY_ID_])
    assert gwy_0.hgi.id == GWY_ID_

    gwy_0.send_cmd(Command(cmd_str, qos={"retries": 0}))
    await assert_expected_pkt(gwy_0, pkt_str)

    await gwy_0.stop()
    await rf.stop()


@pytest.mark.xdist_group(name="serial")
async def test_hgi_addr_evofw3(test_idx):
    """Check the virtual RF network behaves as expected (device discovery)."""

    await _test_hgi_addr(
        HgiFwTypes.EVOFW3, CMDS_COMMON[test_idx], PKTS_NATIVE[test_idx]
    )


@pytest.mark.xdist_group(name="serial")
async def test_hgi_addr_native_WIP(test_idx):
    """Check the virtual RF network behaves as expected (device discovery)."""

    if test_idx not in (0, 2):  # TODO: FIXME
        await _test_hgi_addr(
            HgiFwTypes.NATIVE, CMDS_COMMON[test_idx], PKTS_EVOFW3[test_idx]
        )
        return

    try:
        await _test_hgi_addr(
            HgiFwTypes.NATIVE, CMDS_COMMON[test_idx], PKTS_EVOFW3[test_idx]
        )
    except AssertionError:
        return
    assert False
