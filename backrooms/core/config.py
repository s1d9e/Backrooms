"""Configuration management for Backrooms.

Configuration is loaded from a YAML file (if present) and merged with
defaults. Settings are validated through Pydantic.
"""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from backrooms.core.exceptions import ConfigurationError


class ScanSettings(BaseModel):
    """Default scanner behaviour."""

    threads: int = Field(default=100, ge=1, le=1000)
    timeout: float = Field(default=1.0, ge=0.1)
    retries: int = Field(default=1, ge=0, le=5)


class Settings(BaseModel):
    """Top-level Backrooms settings."""

    scan: ScanSettings = Field(default_factory=ScanSettings)


class ConfigManager:
    """Loads, merges and serves configuration."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path.home() / ".config" / "backrooms" / "config.yaml"
        self._settings = Settings()

    def load(self) -> "ConfigManager":
        """Load config from the configured YAML path, if present."""
        if self.path.exists():
            raw = self._read_yaml(self.path)
            self._settings = self._build_settings(raw)
        return self

    @property
    def settings(self) -> Settings:
        return self._settings

    @staticmethod
    def _read_yaml(path: Path) -> dict[str, Any]:
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except (yaml.YAMLError, OSError) as exc:
            raise ConfigurationError(f"Failed to read config {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigurationError("Config root must be a mapping")
        return data

    @staticmethod
    def _build_settings(data: dict[str, Any]) -> Settings:
        try:
            return Settings.model_validate(data)
        except ValidationError as exc:
            raise ConfigurationError(f"Invalid configuration: {exc}") from exc
