"""Intrusion detection — anomaly correlation across decoys.

Wraps IdsLogger and adds cross-decoy correlation (a single source IP
hitting several decoys is flagged as lateral movement).
"""

from backrooms.honeypot.ids.logger import IdsLogger
from backrooms.honeypot.models import IdsSettings


class IdsCorrelator:
    """Pairs a logger with cross-decoy correlation."""

    def __init__(self, settings: IdsSettings, logger: IdsLogger | None = None) -> None:
        self.settings = settings
        self.logger = logger or IdsLogger(settings)

    def track_connection(self, decoy: str, source_ip: str) -> None:
        """Log a connection and alert on multi-decoy spread."""
        self.logger.log(decoy, "connection", source_ip=source_ip)
        recent = self.logger.history(limit=250)
        touched = {e.get("decoy") for e in recent if e.get("source_ip") == source_ip}
        decoy_names = {str(name) for name in touched if name is not None}
        if len(decoy_names) > 1:
            detail = f"{source_ip} touched decoys: {', '.join(sorted(decoy_names))}"
            self.logger.log("labyrinth", "lateral_movement", detail=detail, source_ip=source_ip)
