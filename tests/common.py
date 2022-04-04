#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import logging
import os

TEST_DIR = f"{os.path.dirname(__file__)}"

GWY_CONFIG = {}

DEBUG_MODE = False
DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

if DEBUG_MODE:
    import debugpy

    if not debugpy.is_client_connected():
        debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))
        print(f"Debugger listening on {DEBUG_ADDR}:{DEBUG_PORT}, waiting for client...")
        debugpy.wait_for_client()

logging.disable(logging.WARNING)
