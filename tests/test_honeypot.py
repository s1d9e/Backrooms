"""Tests for the honeypot module (no Docker daemon required)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from backrooms.core.exceptions import ConfigurationError
from backrooms.honeypot.config import load_honeypot_config
from backrooms.honeypot.ids.detector import IdsCorrelator
from backrooms.honeypot.ids.logger import IdsLogger, classify_command
from backrooms.honeypot.manager import HoneypotManager
from backrooms.honeypot.models import (
    DecoySpec,
    HoneypotConfig,
    ServiceType,
)


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "honeypot.yaml"
    path.write_text(content, encoding="utf-8")
    return path


VALID_YAML = """
network: "172.28.0.0/16"
subnet: "172.28.0.0/24"
decoys:
  - name: dc01
    hostname: DC01-CORP
    services: [ssh, http]
  - name: web-prod
    hostname: web-prod
    services: [http]
labyrinth:
  max_hops: 4
ids:
  enabled: true
"""


def test_load_config_valid(tmp_path: Path) -> None:
    cfg = load_honeypot_config(write_config(tmp_path, VALID_YAML))
    assert len(cfg.decoys) == 2
    assert cfg.decoys[0].services == [ServiceType.SSH, ServiceType.HTTP]
    assert cfg.labyrinth.max_hops == 4
    assert cfg.ids.enabled is True


def test_load_config_duplicate_decoys(tmp_path: Path) -> None:
    cfg = load_honeypot_config(
        write_config(
            tmp_path,
            """
network: "172.28.0.0/16"
decoys:
  - name: dc01
    hostname: DC01-CORP
    services: [ssh, http]
  - name: other
    hostname: other
    services: [http]
  - name: dc01
    hostname: DC01-CORP-CLONE
    services: [ssh]
""",
        )
    )
    names = [d.name for d in cfg.decoys]
    assert names == ["dc01", "other"]
    assert cfg.decoys[0].hostname == "DC01-CORP-CLONE"  # last wins


def test_load_config_missing_decoys(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_honeypot_config(write_config(tmp_path, "network: 172.28.0.0/16\n"))


def test_load_config_invalid_type(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_honeypot_config(write_config(tmp_path, "decoys: not-a-list\n"))


def test_model_enforces_decoys() -> None:
    with pytest.raises(ValidationError):
        HoneypotConfig(decoys=[])


def test_model_service_defaults() -> None:
    spec = DecoySpec(name="x", hostname="x")
    assert spec.services == [ServiceType.HTTP]
    assert spec.ssh_port == 2222


def test_ids_logger_roundtrip(tmp_path: Path) -> None:
    cfg = HoneypotConfig(decoys=[DecoySpec(name="a", hostname="a")])
    logger = IdsLogger(settings=cfg.ids, db_path=tmp_path / "ids.db")
    eid = logger.log("dc01", "connection", source_ip="10.0.0.5")
    assert eid >= 0
    hist = logger.history()
    assert len(hist) == 1
    assert hist[0]["decoy"] == "dc01"
    assert hist[0]["source_ip"] == "10.0.0.5"
    logger.close()


def test_ids_logger_alerts(tmp_path: Path) -> None:
    cfg = HoneypotConfig(decoys=[DecoySpec(name="a", hostname="a")])
    logger = IdsLogger(settings=cfg.ids, db_path=tmp_path / "ids.db")
    logger.log("dc01", "lateral_movement", detail="x")
    logger.log("dc01", "connection", detail="x")
    # Settings default alert list matches lateral_movement
    assert any(e["kind"] == "lateral_movement" for e in logger.alerts())
    logger.close()


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("sudo cat /etc/shadow", "privilege_escalation"),
        ("chmod 777 /etc/passwd", "privilege_escalation"),
        ("ssh root@10.0.0.2", "lateral_movement"),
        ("nc -lvp 4444", "lateral_movement"),
        ("mimikatz sekurlsa::logonpasswords", "credential_dumping"),
        ("ls -la", None),
    ],
)
def test_classify_command(command: str, expected: str | None) -> None:
    assert classify_command(command) == expected


def test_correlator_spread(tmp_path: Path) -> None:
    config = HoneypotConfig(decoys=[DecoySpec(name="a", hostname="a")])
    logger = IdsLogger(settings=config.ids, db_path=tmp_path / "ids.db")
    corr = IdsCorrelator(settings=config.ids, logger=logger)
    corr.track_connection("dc01", "10.0.0.5")
    corr.track_connection("web-prod", "10.0.0.5")
    assert any(
        e["kind"] == "lateral_movement" and e["source_ip"] == "10.0.0.5"
        for e in logger.history()
    )


def test_manager_holds_config() -> None:
    config = HoneypotConfig(decoys=[DecoySpec(name="a", hostname="a")])
    manager = HoneypotManager(config)
    assert manager.config is config
