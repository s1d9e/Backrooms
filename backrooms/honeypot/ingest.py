"""Ingest decoy container logs and feed the labyrinth tracker.

Decoys emit one JSON object per line (stdout). This module reads those
logs, parses them, and forwards meaningful events to the IdsLogger and
LabyrinthTracker — turning container output into a live attacker map.
"""

import json
import time
from typing import Any

from backrooms.honeypot.ids.logger import IdsLogger
from backrooms.honeypot.labyrinth import LabyrinthTracker
from backrooms.honeypot.manager import HoneypotManager


def parse_line(raw: str) -> dict[str, Any] | None:
    """Parse a single JSON log line emitted by a decoy."""
    stripped = raw.strip()
    if not stripped or not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if not data.get("kind") or not data.get("host"):
        return None
    return data


def ingest_events(
    manager: HoneypotManager,
    tracker: LabyrinthTracker,
    logger: IdsLogger | None = None,
) -> int:
    """Pull current logs from all decoys and forward events.

    Returns the number of events processed. Only kinds that carry attacker
    intent (connection and protocol events) advance the labyrinth session.
    """
    logger = logger or (tracker.logger if tracker else None)
    processed = 0
    kinds = {"connection", "ssh_handshake", "http", "telnet", "ftp", "smb", "mysql", "postgres"}

    for status in manager.status():
        decoy_name = status.spec.name
        try:
            logs = manager.logs(decoy_name, tail=500)
        except Exception:  # noqa: BLE001, S112 - tolerate a failing decoy
            continue

        for raw in logs.splitlines():
            event = parse_line(raw)
            if event is None:
                continue
            processed += 1
            if logger is None:
                continue
            source = str(event.get("src") or "")
            kind = str(event.get("kind") or "")
            detail = str(event.get("detail") or "")

            logger.log(decoy_name, kind, detail=detail, source_ip=source or None)
            if tracker is not None and kind in kinds:
                tracker.record_hit(decoy_name, source or "unknown", service=kind)
    return processed


def wait_and_ingest(
    manager: HoneypotManager,
    tracker: LabyrinthTracker,
    logger: IdsLogger | None = None,
    interval: float = 2.0,
    iterations: int | None = None,
) -> None:
    """Poll container logs on a timer until interrupted (Ctrl+C) or iterations."""
    import itertools

    counter = itertools.count(1) if iterations is None else range(iterations)
    for i in counter:
        count = ingest_events(manager, tracker, logger)
        tracker.evict_stale()
        if i % 5 == 0:
            now = time.strftime("%H:%M:%S")
            print(f"[{now}] ingested {count} events, {len(tracker.sessions())} attacker sessions")
        time.sleep(interval)
