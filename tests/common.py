#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

import asyncio
import json
import logging
import warnings
from pathlib import Path
from random import shuffle

from ramses_rf import Gateway
from ramses_rf.helpers import shrink

# TEST_DIR = f"{os.path.dirname(__file__)}"
TEST_DIR = Path(__file__).resolve().parent

GWY_CONFIG = {}

DEBUG_MODE = False
DEBUG_ADDR = "0.0.0.0"
DEBUG_PORT = 5678

warnings.filterwarnings("ignore", category=DeprecationWarning)

if DEBUG_MODE:
    import debugpy

    if not debugpy.is_client_connected():
        debugpy.listen(address=(DEBUG_ADDR, DEBUG_PORT))
        print(f"Debugger listening on {DEBUG_ADDR}:{DEBUG_PORT}, waiting for client...")
        debugpy.wait_for_client()

logging.disable(logging.WARNING)  # usu. WARNING


def assert_expected(actual, expected: dict = None) -> None:

    if expected is not None:
        assert shrink(actual) == shrink(expected)


def assert_expected_set(gwy, expected) -> None:

    assert_expected(gwy.schema, expected.get("schema"))
    assert_expected(gwy.known_list, expected.get("known_list"))
    assert_expected(gwy.params, expected.get("params"))
    # sert_expected(gwy.status, expected.get("status"))


async def load_test_system(dir_name, config: dict = None) -> Gateway:

    try:
        with open(f"{dir_name}/config.json") as f:
            kwargs = json.load(f)
    except FileNotFoundError:
        kwargs = {"config": {}}

    if config:
        kwargs.update(config)

    with open(f"{dir_name}/packet.log") as f:
        gwy = Gateway(
            None,
            input_file=f,
            loop=asyncio.get_event_loop(),
            **kwargs,
        )
        await gwy.start()

    return gwy


def load_expected_results(dir_name) -> dict:

    try:
        with open(f"{dir_name}/schema.json") as f:
            schema = json.load(f)
    except FileNotFoundError:
        schema = None

    try:
        with open(f"{dir_name}/known_list.json") as f:
            known_list = json.load(f).get("known_list")
    except FileNotFoundError:
        known_list = None

    try:
        with open(f"{dir_name}/params.json") as f:
            params = json.load(f)
    except FileNotFoundError:
        params = None

    try:
        with open(f"{dir_name}/status.json") as f:
            status = json.load(f)
    except FileNotFoundError:
        status = None

    # TODO: do known_list, status
    return {
        "schema": schema,
        "known_list": known_list,
        "params": params,
        "status": status,
    }


def shuffle_dict(old_dict) -> dict:
    keys = list(old_dict.keys())
    shuffle(keys)
    new_dict = dict()
    for key in keys:
        new_dict.update({key: old_dict[key]})
    return new_dict
