"""Intrusion detection: logging and alerting on honeypot activity."""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backrooms.honeypot.models import IdsSettings


class IdsLogger:
    """Record attacker actions and emit alerts.

    Events are persisted to a SQLite database so they survive restarts
    and can be queried from the CLI and TUI.
    """

    def __init__(self, settings: IdsSettings, db_path: Path | None = None) -> None:
        self.settings = settings
        self.path = db_path or Path.home() / ".local" / "share" / "backrooms" / "ids.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                decoy TEXT NOT NULL,
                source_ip TEXT,
                kind TEXT NOT NULL,
                detail TEXT
            );
            """
        )
        self._conn.commit()

    def log(
        self,
        decoy: str,
        kind: str,
        detail: str = "",
        source_ip: str | None = None,
    ) -> int:
        """Record a single event; returns the new event id."""
        if not self.settings.enabled:
            return -1
        now = datetime.now(UTC).isoformat()
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO events (timestamp, decoy, source_ip, kind, detail) "
                "VALUES (?, ?, ?, ?, ?)",
                (now, decoy, source_ip, kind, detail),
            )
        return int(cur.lastrowid or -1)

    def alerts(self) -> list[dict[str, Any]]:
        """Return events whose kind matches the configured alert list."""
        if not self.settings.alert_on:
            return []
        placeholders = ", ".join("?" for _ in self.settings.alert_on)
        query = "SELECT * FROM events WHERE kind IN (" + placeholders + ") ORDER BY id DESC LIMIT 500"  # noqa: S608 - only literal '?' markers
        with self._conn:
            rows = self._conn.execute(query, self.settings.alert_on).fetchall()
        return [dict(row) for row in rows]

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent events overall."""
        with self._conn:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "IdsLogger":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def alert_kinds() -> tuple[str, ...]:
    return ("privilege_escalation", "lateral_movement", "credential_dumping")


def classify_command(command: str) -> str | None:
    """Classify a shell command heuristic into an alert kind, if relevant."""
    lowered = command.lower()
    if any(token in lowered for token in ("sudo", "su", "chmod 777", "/etc/shadow", "passwd")):
        return "privilege_escalation"
    if any(token in lowered for token in ("scp ", "ssh ", "wget", "curl", "netcat", "nc -", "psexec")):
        return "lateral_movement"
    if any(token in lowered for token in ("mimikatz", "sam", "shutdown", "lynis", "hashcat", "john")):
        return "credential_dumping"
    return None
