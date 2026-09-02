"""Labyrinth logic: tracking attackers as they wander the decoy maze.

When an attacker connects to a decoy, the tracker records a hop in a
per-source-IP session. If the attacker keeps touching decoys, the session
grows into a path; revisiting the same decoy (ungerne) or exceeding the
hop budget marks the attacker as *lost in the backrooms*.
"""

import time
from dataclasses import dataclass, field

from backrooms.core.exceptions import BackroomsError
from backrooms.honeypot.ids.logger import IdsLogger
from backrooms.honeypot.models import IdsSettings, LabyrinthSettings


class LabyrinthError(BackroomsError):
    """Raised on invalid labyrinth operations."""


@dataclass
class Hop:
    """A single decoy contact within an attacker session."""

    decoy: str
    timestamp: float
    service: str = ""

    @property
    def at(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))


@dataclass
class HopResult:
    """Outcome of recording a hop."""

    hop_index: int
    loop_detected: bool = False
    max_hops_reached: bool = False
    redirect: str | None = None


@dataclass
class AttackerSession:
    """State for a single attacker (source IP) in the maze."""

    source_ip: str
    hops: list[Hop] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_decoy: str | None = None

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    @property
    def path(self) -> list[str]:
        return [hop.decoy for hop in self.hops]

    @property
    def lost(self) -> bool:
        return bool(
            self.hops
            and self.hop_count > 1
            and len(set(self.path)) < self.hop_count
        )


class LabyrinthTracker:
    """Tracks attacker sessions and detects maze loops."""

    def __init__(
        self,
        settings: LabyrinthSettings,
        logger: IdsLogger | None = None,
        decoy_names: list[str] | None = None,
    ) -> None:
        self.settings = settings
        self.logger = logger or IdsLogger(IdsSettings())
        self.decoy_names = decoy_names or []
        self._sessions: dict[str, AttackerSession] = {}

    def record_hit(
        self,
        decoy: str,
        source_ip: str,
        service: str = "",
        timestamp: float | None = None,
    ) -> HopResult:
        """Record that `source_ip` contacted `decoy`, advancing the maze path."""
        if not decoy:
            raise LabyrinthError("decoy name must not be empty")
        if not source_ip:
            raise LabyrinthError("source_ip must not be empty")

        session = self._session_for(source_ip, timestamp)
        if session.last_decoy == decoy:
            session.last_seen = timestamp or time.time()
            return HopResult(hop_index=len(session.hops))

        hop = Hop(decoy=decoy, timestamp=timestamp or time.time(), service=service)
        session.hops.append(hop)
        session.last_decoy = decoy
        session.last_seen = hop.timestamp

        hop_index = len(session.hops)
        loop_detected = session.lost
        if session.hop_count > self.settings.max_hops:
            self._alert(source_ip, "labyrinth_loop", self._path_summary(session))
            return HopResult(
                hop_index=hop_index,
                max_hops_reached=True,
                redirect=session.hops[-2].decoy if hop_index > 1 else None,
            )

        if loop_detected:
            self._alert(source_ip, "labyrinth_loop", self._path_summary(session))
            return HopResult(
                hop_index=hop_index,
                loop_detected=True,
                redirect=session.hops[-2].decoy if hop_index > 1 else None,
            )

        if hop_index < self.settings.max_hops:
            next_decoy = self._next_decoy(session)
            if next_decoy:
                return HopResult(hop_index=hop_index, redirect=next_decoy)
        return HopResult(hop_index=hop_index)

    def sessions(self) -> list[AttackerSession]:
        """Live sessions, newest first."""
        return sorted(
            self._sessions.values(), key=lambda s: s.last_seen, reverse=True
        )

    def session(self, source_ip: str) -> AttackerSession | None:
        return self._sessions.get(source_ip)

    def evict_stale(self, timeout: float | None = None) -> None:
        """Drop sessions idle longer than the timeout (default: config or 15min)."""
        limit = timeout if timeout is not None else self.settings.session_timeout
        now = time.time()
        expired = [
            key
            for key, session in self._sessions.items()
            if now - session.last_seen > limit
        ]
        for key in expired:
            del self._sessions[key]

    def reset(self) -> None:
        self._sessions.clear()

    def _session_for(self, source_ip: str, timestamp: float | None) -> AttackerSession:
        self.evict_stale()
        if source_ip not in self._sessions:
            self._sessions[source_ip] = AttackerSession(source_ip=source_ip)
        return self._sessions[source_ip]

    def _next_decoy(self, session: AttackerSession) -> str | None:
        """Pick the decoy the attacker should be redirected toward (no repeat)."""
        if not self.decoy_names:
            return None
        visited = set(session.path)
        for decoy in self.decoy_names:
            if decoy not in visited:
                return decoy
        return None

    @staticmethod
    def _path_summary(session: AttackerSession) -> str:
        return " -> ".join(session.path)

    def _alert(self, source_ip: str, kind: str, detail: str) -> None:
        self.logger.log("labyrinth", kind, detail=detail, source_ip=source_ip)


def build_tracker(settings: LabyrinthSettings) -> LabyrinthTracker:
    """Construct a tracker wired to a fresh logger."""
    return LabyrinthTracker(settings)
