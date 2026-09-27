"""Round-trip tests for frozen data contracts."""

from datetime import datetime
from pathlib import Path

import pytest

from hestia.contracts import (
    Event,
    LabelRecord,
    ParseFailure,
    Session,
    event_from_json,
    event_to_json,
    events_from_parquet,
    events_to_parquet,
    sessions_from_parquet,
    sessions_to_parquet,
)


@pytest.fixture
def sample_event() -> Event:
    """Return a representative Event for tests."""
    return Event(
        event_id="evt-001",
        source="auth.log",
        line_no=42,
        timestamp=datetime(2024, 1, 15, 8, 30, 0),
        host="server01",
        process="sshd",
        pid=1234,
        event_type="ssh_auth_success",
        src_ip="192.168.1.10",
        src_port=52144,
        user="alice",
        target_user=None,
        method="password",
        key_fingerprint=None,
        session_id=None,
        command=None,
        tty=None,
        pwd=None,
        uid=None,
        ruser=None,
        success=True,
        new_account=None,
        added_group=None,
        message="Accepted password for alice from 192.168.1.10",
        raw_message="Jan 15 08:30:00 server01 sshd[1234]: Accepted password for alice from 192.168.1.10",
    )


@pytest.fixture
def sample_session() -> Session:
    """Return a representative Session for tests."""
    return Session(
        session_id="sess-001",
        source="auth.log",
        src_ip="192.168.1.10",
        user="alice",
        events=["evt-001", "evt-002"],
        start_time=datetime(2024, 1, 15, 8, 30, 0),
        end_time=datetime(2024, 1, 15, 8, 35, 0),
        event_count=2,
        gap_seconds=300.0,
        host="server01",
        src_port=52144,
        primary_method="password",
        key_fingerprint=None,
        has_escalation=False,
        has_persistence=False,
        failure_count=0,
    )


@pytest.fixture
def sample_parse_failure() -> ParseFailure:
    """Return a representative ParseFailure for tests."""
    return ParseFailure(
        source="auth.log",
        line_no=99,
        raw_line="??? gibberish line ???",
        reason="Unrecognized format",
        timestamp=datetime(2024, 1, 15, 9, 0, 0),
    )


@pytest.fixture
def sample_label() -> LabelRecord:
    """Return a representative LabelRecord for tests."""
    return LabelRecord(
        source="auth.log",
        line_no=42,
        attack=True,
        attack_family="brute_force",
        technique_ids=["T1110"],
    )


def test_event_roundtrip_json(sample_event: Event) -> None:
    """Event round-trips through JSON."""
    json_str = event_to_json(sample_event)
    restored = event_from_json(json_str)
    assert restored == sample_event


def test_event_roundtrip_parquet(sample_event: Event, tmp_path: Path) -> None:
    """Event round-trips through Parquet."""
    path = tmp_path / "events.parquet"
    events_to_parquet([sample_event], path)
    restored = events_from_parquet(path)
    assert restored == [sample_event]


def test_events_parquet_empty(tmp_path: Path) -> None:
    """Empty Event list produces a readable Parquet file."""
    path = tmp_path / "empty_events.parquet"
    events_to_parquet([], path)
    restored = events_from_parquet(path)
    assert restored == []


def test_session_roundtrip_json(sample_session: Session) -> None:
    """Session round-trips through JSON."""
    json_str = sample_session.model_dump_json()
    restored = Session.model_validate_json(json_str)
    assert restored == sample_session


def test_session_roundtrip_parquet(sample_session: Session, tmp_path: Path) -> None:
    """Session round-trips through Parquet."""
    path = tmp_path / "sessions.parquet"
    sessions_to_parquet([sample_session], path)
    restored = sessions_from_parquet(path)
    assert restored == [sample_session]


def test_sessions_parquet_empty(tmp_path: Path) -> None:
    """Empty Session list produces a readable Parquet file."""
    path = tmp_path / "empty_sessions.parquet"
    sessions_to_parquet([], path)
    restored = sessions_from_parquet(path)
    assert restored == []


def test_parse_failure_roundtrip_json(sample_parse_failure: ParseFailure) -> None:
    """ParseFailure round-trips through JSON."""
    json_str = sample_parse_failure.model_dump_json()
    restored = ParseFailure.model_validate_json(json_str)
    assert restored == sample_parse_failure


def test_label_record_roundtrip_json(sample_label: LabelRecord) -> None:
    """LabelRecord round-trips through JSON."""
    json_str = sample_label.model_dump_json()
    restored = LabelRecord.model_validate_json(json_str)
    assert restored == sample_label


def test_event_optional_fields_none() -> None:
    """Event tolerates omitted optional fields."""
    event = Event(
        event_id="evt-002",
        source="auth.log",
        line_no=43,
        timestamp=datetime(2024, 1, 15, 8, 31, 0),
        host="server01",
        process="sshd",
        event_type="connection_closed",
        message="Disconnected",
        raw_message="Disconnected from user",
    )
    assert event.pid is None
    assert event.src_ip is None
    assert event.src_port is None
    assert event.user is None
    assert event.target_user is None
    assert event.method is None
    assert event.key_fingerprint is None
    assert event.command is None
    assert event.success is None


def test_event_sudo_roundtrip() -> None:
    """A sudo event with new fields round-trips through JSON and Parquet."""
    event = Event(
        event_id="evt-003",
        source="auth.log",
        line_no=55,
        timestamp=datetime(2024, 1, 15, 8, 42, 1),
        host="server01",
        process="sudo",
        pid=2345,
        event_type="sudo_command",
        src_ip=None,
        src_port=None,
        user="alice",
        target_user="root",
        method=None,
        key_fingerprint=None,
        session_id=None,
        command="/bin/bash",
        tty="pts/1",
        pwd="/home/alice",
        uid=None,
        ruser=None,
        success=True,
        new_account=None,
        added_group=None,
        message="alice ran /bin/bash as root",
        raw_message="jdoe : TTY=pts/1 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash",
    )
    assert Event.model_validate_json(event.model_dump_json()) == event


def test_session_derived_flags_roundtrip(sample_session: Session, tmp_path: Path) -> None:
    """Session derived flags and summary fields round-trip through Parquet."""
    session = sample_session.model_copy(
        update={"has_escalation": True, "has_persistence": True, "failure_count": 5}
    )
    path = tmp_path / "session_flags.parquet"
    sessions_to_parquet([session], path)
    restored = sessions_from_parquet(path)
    assert restored == [session]
    assert restored[0].has_escalation is True
    assert restored[0].has_persistence is True
    assert restored[0].failure_count == 5
