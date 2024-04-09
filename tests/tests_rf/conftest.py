#!/usr/bin/env python3
#
"""Fixtures for testing."""

import logging
from collections.abc import AsyncGenerator
from typing import Final, NoReturn, TypeAlias
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

SZ_GWY_CONFIG: Final = "gwy_config"
SZ_GWY_DEV_ID: Final = "gwy_dev_id"

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
async def rf() -> AsyncGenerator[VirtualRf, None]:
    """Utilize a virtual evofw3-compatible gateway."""

    rf = VirtualRf(2)

    try:
        yield rf
    finally:
        await rf.stop()


@pytest.fixture()  # scope="module")
def fake_evofw3_port(request: pytest.FixtureRequest, rf: VirtualRf) -> PortStrT | None:
    """Utilize a virtual evofw3-compatible gateway."""

    gwy_dev_id: DeviceIdT = request.getfixturevalue(SZ_GWY_DEV_ID)

    rf.set_gateway(rf.ports[0], gwy_dev_id, fw_type=HgiFwTypes.EVOFW3)

    # with patch("ramses_tx.transport.comports", rf.comports):
    return rf.ports[0]


@pytest.fixture()  # scope="module")
def fake_ti3410_port(request: pytest.FixtureRequest, rf: VirtualRf) -> PortStrT | None:
    """Utilize a virtual HGI80-compatible gateway."""

    gwy_dev_id: DeviceIdT = request.getfixturevalue(SZ_GWY_DEV_ID)

    rf.set_gateway(rf.ports[0], gwy_dev_id, fw_type=HgiFwTypes.HGI_80)

    # with patch("ramses_tx.transport.comports", rf.comports):
    return rf.ports[0]


@pytest.fixture()  # scope="session")  # TODO: remove HACK, below
async def mqtt_evofw3_port() -> PortStrT:
    """Utilize an actual evofw3-compatible gateway."""

    # TODO: add a test & pytest.skip() if no MQTT broker is available

    return "mqtt://mqtt_username:mqtt_passw0rd@127.0.0.1"


@pytest.fixture()  # scope="session")  # TODO: remove HACK, below
async def real_evofw3_port() -> PortStrT | NoReturn:
    """Utilize an actual evofw3-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "evofw3" in p.product]

    if port_names:
        return port_names[0]

    if devices := [
        p.device for p in comports() if p.name[:6] == "ttyACM"
    ]:  # HACK: evofw3-esp
        _LOGGER.warning(f"Assuming {devices[0]} is evofw3-compatible")
        return devices[0]

    pytest.skip("No evofw3-based gateway device found")


@pytest.fixture()  # scope="session")
async def real_ti3410_port() -> PortStrT | NoReturn:
    """Utilize an actual HGI80-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "TUSB3410" in p.product]

    if port_names:
        return port_names[0]

    pytest.skip("No ti3410-based gateway device found")


#######################################################################################


async def _gateway(gwy_port: PortStrT, gwy_config: dict) -> Gateway:
    """Instantiate a gateway."""

    gwy = Gateway(gwy_port, **gwy_config)

    assert gwy.hgi is None and gwy.devices == []

    await gwy.start()
    return gwy


async def _fake_gateway(gwy_port: PortStrT, gwy_config: dict, rf: VirtualRf) -> Gateway:
    """Wrapper to instantiate a virtual gateway."""

    with patch("ramses_tx.transport.comports", rf.comports):
        gwy = await _gateway(gwy_port, gwy_config)

    gwy._transport._extra["virtual_rf"] = rf
    return gwy


async def _real_gateway(gwy_port: PortStrT, gwy_config: dict) -> Gateway | NoReturn:  # type: ignore[return]
    """Wrapper to instantiate a physical gateway."""

    global _global_failed_ports

    if gwy_port in _global_failed_ports:
        pytest.skip(f"Port {gwy_port} previously failed")

    try:
        return await _gateway(gwy_port, gwy_config)
    except (ser.SerialException, exc.TransportSerialError) as err:
        _global_failed_ports.append(gwy_port)
        pytest.xfail(str(err))  # not skip, as we had determined port exists elsewhere


@pytest.fixture()  # scope="module")
async def fake_evofw3(
    fake_evofw3_port: PortStrT, request: pytest.FixtureRequest, rf: VirtualRf
) -> AsyncGenerator[Gateway, None]:
    """Utilize a virtual evofw3-compatible gateway (discovered by fake_evofw3_port)."""

    gwy_config: dict = request.getfixturevalue(SZ_GWY_CONFIG)
    gwy_dev_id: DeviceIdT = request.getfixturevalue(SZ_GWY_DEV_ID)

    gwy = await _fake_gateway(fake_evofw3_port, gwy_config, rf)

    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id == gwy_dev_id
    assert gwy._protocol._is_evofw3 is True

    try:
        yield gwy
    finally:
        await gwy.stop()


@pytest.fixture()  # scope="module")
async def fake_ti3410(
    fake_ti3410_port: PortStrT, request: pytest.FixtureRequest, rf: VirtualRf
) -> AsyncGenerator[Gateway, None]:
    """Utilize a virtual HGI80-compatible gateway (discovered by fake_ti3410_port)."""

    gwy_config: dict = request.getfixturevalue(SZ_GWY_CONFIG)
    gwy_dev_id: DeviceIdT = request.getfixturevalue(SZ_GWY_DEV_ID)

    gwy = await _fake_gateway(fake_ti3410_port, gwy_config, rf)

    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id == gwy_dev_id
    assert gwy._protocol._is_evofw3 is False

    try:
        yield gwy
    finally:
        await gwy.stop()


@pytest.fixture()  # scope="module")
async def mqtt_evofw3(
    mqtt_evofw3_port: PortStrT, request: pytest.FixtureRequest
) -> AsyncGenerator[Gateway, None]:
    """Utilize an actual evofw3-compatible gateway (discovered by mqtt_evofw3_port)."""

    gwy_config: dict = request.getfixturevalue(SZ_GWY_CONFIG)

    gwy = await _real_gateway(mqtt_evofw3_port, gwy_config)

    gwy.get_device(gwy._protocol.hgi_id)  # HACK: not instantiated: no puzzle pkts sent

    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id not in (None, HGI_DEVICE_ID)
    assert gwy._protocol._is_evofw3 is True

    try:
        yield gwy
    finally:
        await gwy.stop()


@pytest.fixture()  # scope="module")
async def real_evofw3(
    real_evofw3_port: PortStrT, request: pytest.FixtureRequest
) -> AsyncGenerator[Gateway, None]:
    """Utilize an actual evofw3-compatible gateway (discovered by real_evofw3_port)."""

    gwy_config: dict = request.getfixturevalue(SZ_GWY_CONFIG)

    gwy = await _real_gateway(real_evofw3_port, gwy_config)

    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id not in (None, HGI_DEVICE_ID)
    assert gwy._protocol._is_evofw3 is True

    try:
        yield gwy
    finally:
        await gwy.stop()


@pytest.fixture()  # scope="module")
async def real_ti3410(
    real_ti3410_port: PortStrT, request: pytest.FixtureRequest
) -> AsyncGenerator[Gateway, None]:
    """Utilize an actual HGI80-compatible gateway (discovered by real_ti3410_port)."""

    gwy_config: dict = request.getfixturevalue(SZ_GWY_CONFIG)

    gwy = await _real_gateway(real_ti3410_port, gwy_config)

    assert isinstance(gwy.hgi, HgiGateway) and gwy.hgi.id not in (None, HGI_DEVICE_ID)
    assert gwy._protocol._is_evofw3 is False

    try:
        yield gwy
    finally:
        await gwy.stop()
