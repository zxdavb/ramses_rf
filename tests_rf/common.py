#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser."""

import json
import logging
import warnings
from pathlib import Path

from serial.tools import list_ports

from ramses_rf.schemas import SCH_GLOBAL_GATEWAY
from ramses_rf.system import System
from tests_rf.mock import CTL_ID, MOCKED_PORT, MockDeviceCtl

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

if ports := [
    c for c in list_ports.comports() if c.device[-7:-1] in ("ttyACM", "ttyUSB")
]:
    from ramses_rf import Gateway

    SERIAL_PORT = ports[0].device

else:
    from tests_rf.mock import MockGateway as Gateway

    SERIAL_PORT = MOCKED_PORT


def find_test_tcs(gwy: Gateway) -> System:
    if SERIAL_PORT == MOCKED_PORT:
        return gwy.system_by_id["01:000730"]
    systems = [s for s in gwy.systems if s.id != "01:000730"]
    return systems[0] if systems else gwy.system_by_id["01:000730"]


async def load_test_gwy_alt(config_file: str, **kwargs) -> Gateway:
    """Create a system state from a packet log (using an optional configuration)."""

    kwargs = SCH_GLOBAL_GATEWAY({k: v for k, v in kwargs.items() if k[:1] != "_"})

    try:
        with open(config_file) as f:
            config = json.load(f)
    except FileNotFoundError:
        config = {}

    if config:
        kwargs.update(config)

    gwy = Gateway(SERIAL_PORT, **kwargs)
    await gwy.start(start_discovery=False)  # may: SerialException

    if hasattr(
        gwy.pkt_transport.serial, "mock_devices"
    ):  # needs ser instance, so after gwy.start()
        gwy.pkt_transport.serial.mock_devices = [MockDeviceCtl(gwy, CTL_ID)]

    return gwy
