import os
import pytest
from config.settings import config

@pytest.fixture(autouse=True)
def configure_test_mode(monkeypatch):
    """
    Enforces strict test execution mode across all tests in windows-telemetry.
    Prevents unit tests from probing or mutating genuine live host Windows Event Logs.
    """
    monkeypatch.setenv("TGAM_EXECUTION_MODE", "TEST")
    monkeypatch.setenv("EXECUTION_MODE", "TEST")
    orig_mode = getattr(config, "execution_mode", "PRODUCTION")
    config.execution_mode = "TEST"
    yield
    config.execution_mode = orig_mode
