"""Fixtures for testing."""

import pytest
from serial.tools.list_ports import comports

from tests_rf.virtual_rf import HgiFwTypes, VirtualRf

TST_ID_ = "18:222222"  # a gateway id


# pytestmark = pytest.mark.asyncio(scope="session")  # needed?


@pytest.fixture(autouse=True)
def patches_for_tests(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("ramses_tx.protocol._DBG_DISABLE_IMPERSONATION_ALERTS", True)
    monkeypatch.setattr("ramses_tx.transport._DBG_DISABLE_DUTY_CYCLE_LIMIT", True)
    monkeypatch.setattr("ramses_tx.transport.MINIMUM_WRITE_GAP", 0)


@pytest.fixture(scope="session")
async def rf():
    """Utilize a virtual evofw3-compatible gateway."""

    rf = VirtualRf(2)

    try:
        yield rf
    finally:
        await rf.stop()


@pytest.fixture(scope="session")
async def fake_evofw3_port(rf: VirtualRf):
    """Utilize a virtual evofw3-compatible gateway."""

    rf.set_gateway(rf.ports[0], TST_ID_, fw_type=HgiFwTypes.EVOFW3)

    # with patch("ramses_tx.transport.comports", rf.comports):
    yield rf.ports[0]


@pytest.fixture(scope="session")
async def fake_ti3410_port(rf: VirtualRf):
    """Utilize a virtual HGI80-compatible gateway."""

    rf.set_gateway(rf.ports[0], TST_ID_, fw_type=HgiFwTypes.HGI_80)

    # with patch("ramses_tx.transport.comports", rf.comports):
    yield rf.ports[0]


@pytest.fixture(scope="session")  # TODO: remove HACK, below
async def real_evofw3_port():
    """Utilize an actual evofw3-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "evofw3" in p.product]

    if port_names:
        return port_names[0]

    if [p.device for p in comports() if p.name == "ttyACM0"]:  # HACK: evofw3-esp
        return "/dev/ttyACM0"

    pytest.skip("No evofw3-based gateway device found")


@pytest.fixture(scope="session")
async def real_ti3410_port():
    """Utilize an actual HGI80-compatible gateway."""

    port_names = [p.device for p in comports() if p.product and "TUSB3410" in p.product]

    if port_names:
        return port_names[0]

    pytest.skip("No ti3410-based gateway device found")
