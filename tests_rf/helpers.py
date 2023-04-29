#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import json
import logging
import warnings
from pathlib import Path
from typing import Callable, TypeVar
from unittest.mock import patch

from serial.serialutil import SerialException
from serial.tools import list_ports

from ramses_rf import Command, Device, Gateway
from ramses_rf.device import Fakeable
from ramses_rf.schemas import SCH_GLOBAL_CONFIG
from ramses_rf.system import System
from tests_rf.mock import CTL_ID, MOCKED_PORT, MockDeviceCtl, MockGateway
from tests_rf.virtual_rf import VirtualRF

# import tracemalloc
# tracemalloc.start()

warnings.filterwarnings("ignore", category=DeprecationWarning)

DEBUG_MODE = False
DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

if DEBUG_MODE:
    import debugpy

    if not debugpy.is_client_connected():
        debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))
        print(f"Debugger listening on {DEBUG_ADDR}:{DEBUG_PORT}, waiting for client...")
        debugpy.wait_for_client()

logging.disable(logging.WARNING)  # usu. WARNING


TEST_DIR = Path(__file__).resolve().parent

test_ports = {MOCKED_PORT: MockGateway}
if ports := [
    c for c in list_ports.comports() if c.device[-7:-1] in ("ttyACM", "ttyUSB")
]:
    test_ports[ports[0].device] = Gateway

rf_test_failed = False  # global


def abort_if_rf_test_fails(fnc):
    """Abort all non-mocked RF tests once any such test raises a SerialException."""

    async def check_serial_port(test_port, *args, **kwargs):
        if test_port[0] == MOCKED_PORT:
            await fnc(test_port, *args, **kwargs)
            return

        global rf_test_failed
        if rf_test_failed:
            raise SerialException

        try:
            await fnc(test_port, *args, **kwargs)
        except SerialException:
            rf_test_failed = True
            raise

    return check_serial_port


def find_test_tcs(gwy: Gateway) -> System:
    if isinstance(gwy, MockGateway):
        return gwy.system_by_id[CTL_ID]
    systems = [s for s in gwy.systems if s.id != CTL_ID]
    return systems[0] if systems else gwy.system_by_id[CTL_ID]


async def load_test_gwy(
    port_name, gwy_class, config_file: str, devices=None, **kwargs
) -> Gateway:
    """Create a system state from a packet log (using an optional configuration)."""

    config = SCH_GLOBAL_CONFIG({k: v for k, v in kwargs.items() if k[:1] != "_"})

    try:
        with open(config_file) as f:
            config.update(json.load(f))
    except (FileNotFoundError, TypeError):  # TypeError if config_file is None
        pass

    config = SCH_GLOBAL_CONFIG(config)

    gwy: Gateway | MockGateway = gwy_class(port_name, **config)
    await gwy.start(start_discovery=False)  # may: SerialException

    # with patch(
    #     "ramses_rf.protocol.transport.serial_for_url",
    #     return_value=MockSerial(gwy.ser_name, loop=gwy._loop),
    # ):
    #     await gwy.start(start_discovery=False)  # may: SerialException

    if hasattr(  # TODO: move out of this routine
        gwy.pkt_transport.serial, "mock_devices"
    ):  # needs ser instance, so after gwy.start()
        gwy.pkt_transport.serial.mock_devices = (
            [MockDeviceCtl(gwy, CTL_ID)] if devices is None else devices
        )

    return gwy


# Helpers for Virtual RF


MIN_GAP_BETWEEN_WRITES = 0

CONFIG = {
    "config": {
        "disable_discovery": True,
        "enforce_known_list": False,
    }
}


class FakeableDevice(Device, Fakeable):
    _gwy: Gateway  # for mypy typing


_Device = TypeVar("_Device", bound="FakeableDevice")


def make_device_fakeable(dev: Device) -> None:
    """If a Device is not Fakeable, make it so."""

    class FakeableDevice(dev.__class__, Fakeable):
        pass

    dev.__class__ = FakeableDevice
    setattr(dev, "_faked", None)
    setattr(dev, "_context", None)
    setattr(dev, "_1fc9_state", {})


async def _stifle_impersonation_alerts(self, cmd: Command) -> None:
    """Stifle impersonation alerts when testing."""
    pass


@patch(
    "ramses_rf.protocol.transport.PacketProtocolPort._alert_is_impersonating",
    _stifle_impersonation_alerts,
)
@patch("ramses_rf.protocol.transport._MIN_GAP_BETWEEN_WRITES", MIN_GAP_BETWEEN_WRITES)
async def _test_binding_wrapper(
    fnc: Callable, supp_schema: dict, resp_schema: dict, codes: tuple
):
    rf = VirtualRF(2)
    await rf.start()

    gwy_0 = Gateway(rf.ports[0], **CONFIG, **supp_schema)
    gwy_1 = Gateway(rf.ports[1], **CONFIG, **resp_schema)

    await gwy_0.start()
    await gwy_1.start()

    supplicant = gwy_0.device_by_id[supp_schema["orphans_hvac"][0]]
    respondent = gwy_1.device_by_id[resp_schema["orphans_hvac"][0]]

    if not isinstance(respondent, Fakeable):  # likely respondent is not fakeable...
        make_device_fakeable(respondent)

    await fnc(supplicant, respondent, codes)

    await gwy_0.stop()
    await gwy_1.stop()
    await rf.stop()
