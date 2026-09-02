"""Tests for the labyrinth tracker and log ingestion."""

from pathlib import Path

import pytest

from backrooms.honeypot.ids.logger import IdsLogger
from backrooms.honeypot.ingest import ingest_events, parse_line
from backrooms.honeypot.labyrinth import LabyrinthError, LabyrinthTracker
from backrooms.honeypot.manager import DecoyStatus, HoneypotManager
from backrooms.honeypot.models import DecoySpec, HoneypotConfig, LabyrinthSettings


def make_tracker(
    tmp_path: Path, max_hops: int = 5
) -> tuple[LabyrinthTracker, IdsLogger]:
    config = HoneypotConfig.model_validate(
        {
            "decoys": [{"name": "a", "hostname": "a"}],
            "labyrinth": {"max_hops": max_hops},
        }
    )
    logger = IdsLogger(config.ids, db_path=tmp_path / "ids.db")
    tracker = LabyrinthTracker(config.labyrinth, logger, decoy_names=["a"])
    return tracker, logger


def test_new_hop_starts_session() -> None:
    tracker = LabyrinthTracker(LabyrinthSettings())
    result = tracker.record_hit("dc01", "10.0.0.5", service="ssh")
    assert result.hop_index == 1
    session = tracker.session("10.0.0.5")
    assert session is not None
    assert session.path == ["dc01"]


def test_consecutive_duplicate_ignored() -> None:
    tracker = LabyrinthTracker(LabyrinthSettings())
    tracker.record_hit("dc01", "10.0.0.5")
    result = tracker.record_hit("dc01", "10.0.0.5")
    assert result.hop_index == 1  # duplicate does not advance the maze
    session = tracker.session("10.0.0.5")
    assert session is not None
    assert session.hop_count == 1


def test_loop_detected_on_revisit() -> None:
    tracker = LabyrinthTracker(LabyrinthSettings(max_hops=5))
    tracker.record_hit("a", "1.2.3.4")
    tracker.record_hit("b", "1.2.3.4")
    tracker.record_hit("c", "1.2.3.4")
    result = tracker.record_hit("a", "1.2.3.4")  # revisit -> loop
    assert result.loop_detected is True
    session = tracker.session("1.2.3.4")
    assert session is not None
    assert session.lost is True


def test_max_hops_reached() -> None:
    tracker = LabyrinthTracker(LabyrinthSettings(max_hops=3))
    tracker.record_hit("a", "9.9.9.9")
    tracker.record_hit("b", "9.9.9.9")
    tracker.record_hit("c", "9.9.9.9")
    result = tracker.record_hit("d", "9.9.9.9")
    assert result.max_hops_reached is True


def test_redirect_points_elsewhere() -> None:
    tracker = LabyrinthTracker(LabyrinthSettings(max_hops=5), decoy_names=["a", "b", "c"])
    tracker.record_hit("a", "1.2.3.4")
    result = tracker.record_hit("b", "1.2.3.4")
    assert result.redirect is not None
    assert result.redirect == "c"
    assert result.redirect != "b"


def test_redirect_none_without_decoy_list() -> None:
    tracker = LabyrinthTracker(LabyrinthSettings(max_hops=5))
    assert tracker.record_hit("a", "1.2.3.4").redirect is None


def test_session_eviction() -> None:
    settings = LabyrinthSettings(max_hops=5, session_timeout=60)
    tracker = LabyrinthTracker(settings)
    tracker.record_hit("a", "1.2.3.4", timestamp=1000)
    tracker.evict_stale(timeout=0)
    assert tracker.session("1.2.3.4") is None


def test_empty_source_rejected() -> None:
    tracker = LabyrinthTracker(LabyrinthSettings())
    with pytest.raises(LabyrinthError):
        tracker.record_hit("a", "")


@pytest.mark.parametrize(
    ("line", "expected_kind"),
    [
        ('{"ts": 1, "host": "x", "kind": "connection", "detail": "tcp/22", "src": "1.2.3.4"}', "connection"),
        ('{"host": "x", "kind": "ssh_handshake", "detail": ""} ', "ssh_handshake"),
        ("garbage not json", None),
        ("", None),
    ],
)
def test_parse_line(line: str, expected_kind: str | None) -> None:
    event = parse_line(line)
    assert (event is None) == (expected_kind is None)
    if event is not None:
        assert event["kind"] == expected_kind


def test_ingest_feeds_tracker(tmp_path: Path) -> None:
    config = HoneypotConfig(
        decoys=[{"name": "a", "hostname": "a"}],
        labyrinth={"max_hops": 5},
    )
    spec = DecoySpec(name="a", hostname="a")

    class FakeManager(HoneypotManager):
        def status(self):
            return [DecoyStatus(spec=spec, container_id="x", status="running")]

        def logs(self, name: str, tail: int = 200) -> str:
            return (
                '{"ts": 1, "host": "a", "kind": "connection", "detail": "tcp/22", "src": "1.2.3.4"}\n'
                '{"ts": 2, "host": "a", "kind": "ssh_handshake", "detail": "", "src": "1.2.3.4"}\n'
                "not-a-log-line\n"
            )

    tracker, logger = make_tracker(tmp_path)
    manager = FakeManager(config)
    count = ingest_events(manager, tracker, logger)
    assert count == 2  # valid JSON lines only
    session = tracker.session("1.2.3.4")
    assert session is not None
    assert session.hop_count == 1  # both events are one "hop" against decoy a
