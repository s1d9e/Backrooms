"""Load and validate honeypot YAML configuration."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from backrooms.core.exceptions import ConfigurationError
from backrooms.honeypot.models import HoneypotConfig


def load_honeypot_config(path: Path) -> HoneypotConfig:
    """Read a honeypot config file and build a validated config."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Failed to read honeypot config {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigurationError("Honeypot config must be a YAML mapping")

    merged: dict[str, Any] = dict(raw)
    raw_decoys = raw.get("decoys", [])
    if not isinstance(raw_decoys, list):
        raise ConfigurationError("'decoys' must be a list")
    merged["decoys"] = _dedupe_decoys(raw_decoys)

    nested = raw.get("honeypot")
    if isinstance(nested, dict):
        for key in ("network", "subnet", "gateway", "host_ip", "labyrinth", "ids"):
            if key in nested:
                merged[key] = nested[key]

    if not merged.get("decoys"):
        raise ConfigurationError("At least one decoy must be defined in the config")

    try:
        return HoneypotConfig.model_validate(merged)
    except ValidationError as exc:
        raise ConfigurationError(f"Invalid honeypot configuration: {exc}") from exc


def _dedupe_decoys(decoys: list[Any]) -> list[Any]:
    """Remove duplicate decoy definitions by name (last wins)."""
    seen: dict[str, Any] = {}
    for item in decoys:
        if not isinstance(item, dict):
            raise ConfigurationError("Each decoy must be a mapping")
        name = item.get("name")
        if name is None:
            raise ConfigurationError("Each decoy must define a 'name'")
        seen[name] = item
    return list(seen.values())
