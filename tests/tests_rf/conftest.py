"""Fixtures for testing."""

import pytest


@pytest.fixture(autouse=True)
def patches_for_tests(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("ramses_tx.protocol._DBG_DISABLE_IMPERSONATION_ALERTS", True)
    monkeypatch.setattr("ramses_tx.transport._DBG_DISABLE_DUTY_CYCLE_LIMIT", True)
    monkeypatch.setattr("ramses_tx.transport.MINIMUM_WRITE_GAP", 0)
