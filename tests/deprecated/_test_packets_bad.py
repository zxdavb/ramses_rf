#!/usr/bin/env python3
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Test the Schema processor.
"""

from pathlib import Path, PurePath

import pytest

from ramses_rf import Gateway
from ramses_rf.helpers import shrink
from tests.helpers import TEST_DIR  # noqa: F401

WORK_DIR = f"{TEST_DIR}/logs"

SCHEMA_EMPTY = {"known_list": {}, "main_tcs": None, "orphans": []}


def pytest_generate_tests(metafunc: pytest.Metafunc):
    def id_fnc(param: Path) -> str:
        return PurePath(param).name
    metafunc.parametrize("f_name", Path(WORK_DIR).glob("*.log"), ids=id_fnc)


async def test_log_file(f_name: Path):
    with open(f_name) as f:
        gwy = Gateway(None, input_file=f, config={})
        await gwy.start()

    assert shrink(gwy.schema) == shrink(SCHEMA_EMPTY)

    await gwy.stop()
