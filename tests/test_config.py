"""Tests for core configuration and database modules."""

from pathlib import Path

import pytest

from backrooms.core.config import ConfigManager
from backrooms.core.exceptions import ConfigurationError
from backrooms.core.models import Port, PortState, ServiceProtocol


def test_default_config(tmp_path: Path) -> None:
    manager = ConfigManager(tmp_path / "nope.yaml")
    manager.load()
    assert manager.settings.scan.timeout == 1.0
    assert manager.settings.scan.threads == 100


def test_invalid_config_rejected(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text("scan:\n  timeout: -5\n", encoding="utf-8")
    manager = ConfigManager(cfg)
    with pytest.raises(ConfigurationError):
        manager.load()


def test_model_serialization() -> None:
    port = Port(port=22, state=PortState.OPEN, protocol=ServiceProtocol.TCP, service="ssh")
    data = port.model_dump()
    assert data["port"] == 22
    assert data["state"] == "open"
    restored = Port.model_validate(data)
    assert restored.service == "ssh"
