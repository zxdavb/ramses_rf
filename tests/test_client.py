#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the client.
"""
import pytest

from client import MONITOR, PARSE, cli

DEFAULT_CLI_CONFIG = {
    "debug_mode": 0,
    "restore_schema": None,
    "restore_state": None,
    "long_format": False,
    "print_state": 0,
    "show_schema": False,
    "show_params": False,
    "show_status": False,
    "show_knowns": False,
    "show_traits": False,
    "show_crazys": False,
    "exec_cmd": None,
    "exec_scr": None,
    "poll_devices": None,
}

DEFAULT_LIB_CONFIG = {
    "config": {"reduce_processing": 0, "evofw_flag": None, "disable_discovery": False},
    "serial_port": None,
    "packet_log": None,
}


TESTS_MONITOR = (  # can't use "-z"
    (
        ["client.py", "monitor", "/dev/ttyUSB0"],
        MONITOR,
        DEFAULT_CLI_CONFIG,
        DEFAULT_LIB_CONFIG | {"serial_port": "/dev/ttyUSB0"},
    ),
    (
        ["client.py", "monitor", "/dev/ttyUSB0", "-x", "RQ 01:123456 1F09 00"],
        MONITOR,
        DEFAULT_CLI_CONFIG | {"exec_cmd": "RQ 01:123456 1F09 00"},
        DEFAULT_LIB_CONFIG | {"serial_port": "/dev/ttyUSB0"},
    ),
)

TESTS_PARSE = (  # can't use "-z"
    (
        ["client.py", "parse"],
        PARSE,
        DEFAULT_CLI_CONFIG,
        DEFAULT_LIB_CONFIG | {"serial_port": "/dev/ttyUSB0"},
    ),
)


@pytest.mark.parametrize("index", range(len(TESTS_MONITOR)))
def test_client_monitor(monkeypatch, index, tests=TESTS_MONITOR):

    monkeypatch.setattr("sys.argv", tests[index][0])
    cmd_string, lib_config, cli_config = cli(standalone_mode=False)

    assert cmd_string == tests[index][1]
    assert cli_config == tests[index][2]
    assert lib_config == tests[index][3]


@pytest.mark.parametrize("index", range(len(TESTS_PARSE)))
def test_client_parse(monkeypatch, index, tests=TESTS_PARSE):

    monkeypatch.setattr("sys.argv", tests[index][0])
    cmd_string, lib_config, cli_config = cli(standalone_mode=False)

    assert cmd_string == tests[index][1]
    # assert cli_config == tests[index][2]
    # assert lib_config == tests[index][3]
