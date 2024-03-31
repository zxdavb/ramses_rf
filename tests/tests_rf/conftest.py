#!/usr/bin/env python3
#
"""Fixtures for testing."""

import logging
from collections.abc import AsyncGenerator
from typing import TypeAlias
from unittest.mock import patch

import pytest
import serial as ser  # type: ignore[import-untyped]
from serial.tools.list_ports import comports  # type: ignore[import-untyped]

from ramses_rf import Gateway
from ramses_rf.device import HgiGateway
from ramses_tx import exceptions as exc
from ramses_tx.address import HGI_DEVICE_ID
from ramses_tx.schemas import DeviceIdT
from tests_rf.virtual_rf import HgiFwTypes, VirtualRf

#
PortStrT: TypeAlias = str

_LOGGER = logging.getLogger(__name__)


_global_failed_ports: list[str] = []


#######################################################################################


# pytestmark = pytest.mark.asyncio(scope="function")  # needed?


@pytest.fixture(autouse=True)
def patches_for_tests(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("ramses_tx.protocol._DBG_DISABLE_IMPERSONATION_ALERTS", True)
    monkeypatch.setattr("ramses_tx.transport._DBG_DISABLE_DUTY_CYCLE_LIMIT", True)
    monkeypatch.setattr("ramses_tx.transport.MINIMUM_WRITE_GAP", 0)


#######################################################################################


@pytest.fixture()  # )  # scope="module")
async def rf(request: pytest.FixtureRequest) -> AsyncGenerator[VirtualRf, None]:
    """Utilize a virtual evofw3-compatible gateway."""

    rf = VirtualRf(2)

    try:
        yield rf
    finally:
        await rf.stop()


@pytest.fixture()  # scope="module")
def fake_evofw3_port(request: pytest.FixtureRequest, rf: VirtualRf) -> PortStrT | None:
    """Utilize a virtual evofw3-compatible gateway."""

    gwy_dev_id: DeviceIdT = request.getfixturevalue("gwy_dev_id")

    rf.set_gateway(rf.ports[0], gwy_dev_id, fw_type=HgiFwTypes.EVOFW3)

    # with patch("ramses_tx.transport.comports", rf.comports):
    return rf.ports[0]


@pytest.fixture()  # scope="module")
def fake_ti3410_port(request: pytest.FixtureRequest, rf: VirtualRf) -> PortStrT | None:
    """Utilize a virtual HGI80-compatible gateway."""

    gwy_dev_id: DeviceIdT = request.getfixturevalue("gwy_dev_id")

    rf.set_gateway(rf.ports[0], gwy_dev_id, fw_type=HgiFwTypes.HGI_80)

    # with patch("ramses_tx.transport.comports", rf.comports):
    return rf.ports[0]


@pytest.fixture()  # scope="session")  # TODO: remove HACK, below
async def real_evofw3_port() -> PortStrT | None:  # type: ignore[return]
    """Utilize an actual evofw3-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "evofw3" in p.product]

    if port_names:
        return port_names[0]

    if [p.device for p in comports() if p.name == "ttyACM0"]:  # HACK: evofw3-esp
        _LOGGER.warning("Assuming /dev/ttyACM0 is evofw3-compatible")
        return "/dev/ttyACM0"

    pytest.skip("No evofw3-based gateway device found")


@pytest.fixture()  # scope="session")
async def real_ti3410_port() -> PortStrT | None:  # type: ignore[return]
    """Utilize an actual HGI80-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "TUSB3410" in p.product]

    if port_names:
        return port_names[0]

    pytest.skip("No ti3410-based gateway device found")


#######################################################################################


@pytest.fixture()  # scope="module")
async def fake_evofw3(
    fake_evofw3_port: PortStrT, request: pytest.FixtureRequest, rf: VirtualRf
):
    """Utilize a virtual evofw3-compatible gateway."""

    gwy_config: dict = request.getfixturevalue("gwy_config")
    gwy_dev_id = request.getfixturevalue("gwy_dev_id")

    with patch("ramses_tx.transport.comports", rf.comports):
        gwy = Gateway(fake_evofw3_port, **gwy_config)
        assert gwy.hgi is None and gwy.devices == []

        await gwy.start()
        assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id == gwy_dev_id
        assert gwy._protocol._is_evofw3 is True

        try:
            yield gwy
        finally:
            await gwy.stop()


@pytest.fixture()  # scope="module")
async def fake_ti3410(
    fake_ti3410_port: PortStrT, request: pytest.FixtureRequest, rf: VirtualRf
):
    """Utilize a virtual HGI80-compatible gateway."""

    gwy_config: dict = request.getfixturevalue("gwy_config")
    gwy_dev_id = request.getfixturevalue("gwy_dev_id")

    with patch("ramses_tx.transport.comports", rf.comports):
        gwy = Gateway(fake_ti3410_port, **gwy_config)
        assert gwy.hgi is None and gwy.devices == []

        await gwy.start()
        assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id == gwy_dev_id
        assert gwy._protocol._is_evofw3 is False

        try:
            yield gwy
        finally:
            await gwy.stop()


@pytest.fixture()  # scope="module")
async def real_evofw3(real_evofw3_port: PortStrT, request: pytest.FixtureRequest):
    """Utilize an actual evofw3-compatible gateway."""

    global _global_failed_ports

    gwy_config: dict = request.getfixturevalue("gwy_config")

    try:
        gwy = Gateway(real_evofw3_port, **gwy_config)
    except (ser.SerialException, exc.TransportSerialError) as err:
        _global_failed_ports.append(real_evofw3_port)
        pytest.xfail(str(err))  # not skip, as we'd determined port exists, above

    assert gwy.hgi is None and gwy.devices == []

    await gwy.start()
    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id not in (None, HGI_DEVICE_ID)
    assert gwy._protocol._is_evofw3 is True

    try:
        yield gwy
    finally:
        await gwy.stop()


@pytest.fixture()  # scope="module")
async def real_ti3410(real_ti3410_port: PortStrT, request: pytest.FixtureRequest):
    """Utilize an actual HGI80-compatible gateway."""

    global _global_failed_ports

    gwy_config: dict = request.getfixturevalue("gwy_config")

    try:
        gwy = Gateway(real_ti3410_port, **gwy_config)
    except (ser.SerialException, exc.TransportSerialError) as err:
        _global_failed_ports.append(real_ti3410_port)
        pytest.xfail(str(err))  # not skip, as we'd determined port exists, above

    assert gwy.hgi is None and gwy.devices == []

    await gwy.start()
    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id not in (None, HGI_DEVICE_ID)
    gwy._protocol._is_evofw3 = False  # HACK: FIXME (should not be needed)
    assert gwy._protocol._is_evofw3 is False

    try:
        yield gwy
    finally:
        await gwy.stop()
