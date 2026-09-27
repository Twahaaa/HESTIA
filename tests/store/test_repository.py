import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hestia.contracts import Session
from hestia.datasets.profiles import DatasetProfile
from hestia.ingestion.collector import collect_source
from hestia.store.repository import EvidenceRepository, SourceCollisionError


def _collection(tmp_path: Path, content: str = ""):
    path = tmp_path / "auth.log"
    path.write_text(
        content
        or "Jan  1 00:00:00 host sshd[1]: Accepted password for user from 10.0.0.1 port 22 ssh2\n"
    )
    profile = DatasetProfile(
        dataset_id="fixture",
        source_path="fixture/auth.log",
        default_year=2025,
        timezone="UTC",
        timezone_provenance="fixture",
        timestamp_uncertainty="none",
        annotation_coverage="complete",
    )
    return collect_source(path, profile)


def test_schema_has_foreign_keys_indexes_candidates_and_no_labels(tmp_path: Path) -> None:
    repository = EvidenceRepository(tmp_path / "evidence.sqlite3")
    repository.initialize()
    with sqlite3.connect(repository.path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        # H3 adds the case-run tables at schema version 2 and H4 the workspace
        # tables at version 3; the H1 evidence tables are unchanged and must all
        # still be present.
        assert tables == {
            "sources",
            "events",
            "parse_failures",
            "sessions",
            "session_events",
            "unmatched_events",
            "runs",
            "candidates",
            "agent_runs",
            "agent_steps",
            "agent_reports",
            "analyst_dispositions",
            "agent_run_requests",
            "agent_run_interruptions",
            "agent_grounding_failures",
        }
        columns = {
            row[1] for table in tables for row in connection.execute(f"PRAGMA table_info({table})")
        }
        assert not {column for column in columns if "label" in column.lower()}
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert connection.execute("PRAGMA foreign_key_list(events)").fetchall()
        indexes = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
        assert "idx_events_source_time" in indexes
        assert "idx_session_events_event" in indexes


def test_import_is_idempotent_and_preserves_raw_evidence(tmp_path: Path) -> None:
    repository = EvidenceRepository(tmp_path / "evidence.sqlite3")
    repository.initialize()
    collection = _collection(tmp_path)
    assert repository.import_source(collection) is True
    assert repository.import_source(collection) is False
    assert repository.table_counts()["events"] == 1
    with sqlite3.connect(repository.path) as connection:
        payload = connection.execute("SELECT event_json FROM events").fetchone()[0]
        assert '"raw_timestamp":"Jan  1 00:00:00"' in payload
        assert '"raw_line":"Jan  1 00:00:00' in payload


def test_content_collision_is_rejected(tmp_path: Path) -> None:
    repository = EvidenceRepository(tmp_path / "evidence.sqlite3")
    repository.initialize()
    repository.import_source(_collection(tmp_path))
    changed = _collection(
        tmp_path,
        "Jan  1 00:00:01 host sshd[1]: Invalid user other from 10.0.0.2\n",
    )
    with pytest.raises(SourceCollisionError):
        repository.import_source(changed)


def test_source_import_rolls_back_as_one_transaction(tmp_path: Path) -> None:
    repository = EvidenceRepository(tmp_path / "evidence.sqlite3")
    repository.initialize()
    collection = _collection(tmp_path)
    bad_session = Session(
        session_id="bad",
        source="fixture/auth.log",
        src_ip="10.0.0.1",
        user="user",
        events=["missing-event"],
        start_time=datetime(2025, 1, 1, tzinfo=UTC),
        end_time=datetime(2025, 1, 1, tzinfo=UTC),
        event_count=1,
        gap_seconds=60,
        host="host",
    )
    with pytest.raises(ValueError, match="outside its source"):
        repository.import_source(collection, [bad_session])
    assert repository.table_counts()["sources"] == 0
    assert repository.table_counts()["events"] == 0


def test_foreign_keys_are_enabled_on_repository_connections(tmp_path: Path) -> None:
    repository = EvidenceRepository(tmp_path / "evidence.sqlite3")
    repository.initialize()
    with repository._connect() as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_historical_queries_are_strict_and_source_qualified(tmp_path: Path) -> None:
    repository = EvidenceRepository(tmp_path / "evidence.sqlite3")
    repository.initialize()
    collection = _collection(
        tmp_path,
        "Jan  1 00:00:00 host sshd[1]: Accepted password for user from 10.0.0.1 port 22 ssh2\n"
        "Jan  1 00:10:00 host sshd[2]: Accepted password for user from 10.0.0.1 port 22 ssh2\n",
    )
    events = [item.event for item in collection.events]
    sessions = [
        Session(
            session_id=f"session-{index}",
            source="fixture/auth.log",
            src_ip=event.src_ip,
            user=event.user,
            events=[event.event_id],
            start_time=event.timestamp,
            end_time=event.timestamp,
            event_count=1,
            gap_seconds=60,
            host=event.host,
        )
        for index, event in enumerate(events)
    ]
    repository.import_source(collection, sessions)

    history = tuple(
        repository.iter_historical_sessions(
            as_of=sessions[1].start_time,
            exclude_session_id=sessions[1].session_id,
        )
    )
    assert [item.session.session_id for item in history] == ["session-0"]
    assert history[0].evidence_ref.startswith("fixture:fixture/auth.log:")
