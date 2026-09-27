"""Tests for reversible tokenization sanitization."""

from datetime import datetime

from hestia.contracts import Event, Session
from hestia.ingestion.sanitize import Sanitizer, sanitize_events


def _sample_event(user: str = "alice", src_ip: str = "10.0.0.1") -> Event:
    return Event(
        event_id="evt-1",
        source="auth.log",
        line_no=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0),
        host="server01",
        process="sshd",
        event_type="ssh_auth_success",
        src_ip=src_ip,
        user=user,
        message="login",
        raw_message="raw login line",
    )


def test_sanitize_reversible() -> None:
    """Sanitizing and desanitizing yields the original event."""
    event = _sample_event()
    sanitizer = Sanitizer()
    sanitized = sanitizer.sanitize_event(event)
    assert sanitized.user != "alice"
    assert sanitized.src_ip != "10.0.0.1"
    assert sanitized.host != "server01"
    restored = sanitizer.desanitize_event(sanitized)
    assert restored == event


def test_same_value_same_token() -> None:
    """Identical values get identical tokens."""
    event1 = _sample_event(user="alice")
    event2 = _sample_event(user="alice", src_ip="10.0.0.2")
    sanitizer = Sanitizer()
    s1 = sanitizer.sanitize_event(event1)
    s2 = sanitizer.sanitize_event(event2)
    assert s1.user == s2.user
    assert s1.src_ip != s2.src_ip


def test_different_values_different_tokens() -> None:
    """Different values get different tokens."""
    event1 = _sample_event(user="alice")
    event2 = _sample_event(user="bob")
    sanitizer = Sanitizer()
    s1 = sanitizer.sanitize_event(event1)
    s2 = sanitizer.sanitize_event(event2)
    assert s1.user != s2.user


def test_map_persistence() -> None:
    """to_dict / from_dict preserves the mapping."""
    event = _sample_event()
    sanitizer = Sanitizer()
    sanitized = sanitizer.sanitize_event(event)
    mapping = sanitizer.to_dict()
    restored_sanitizer = Sanitizer.from_dict(mapping)
    restored = restored_sanitizer.desanitize_event(sanitized)
    assert restored == event


def test_sanitize_events_returns_sanitizer() -> None:
    """sanitize_events returns both sanitized events and the sanitizer."""
    events = [_sample_event(user="alice"), _sample_event(user="bob")]
    sanitized, sanitizer = sanitize_events(events)
    assert len(sanitized) == 2
    assert sanitizer.to_dict()


def test_sanitize_session() -> None:
    """Sessions can be sanitized and retain event_id ordering."""
    session = Session(
        session_id="sess-1",
        source="auth.log",
        src_ip="10.0.0.1",
        user="alice",
        events=["evt-1"],
        start_time=datetime(2024, 1, 1, 0, 0, 0),
        end_time=datetime(2024, 1, 1, 0, 0, 1),
        event_count=1,
        gap_seconds=300.0,
        host="server01",
    )
    sanitizer = Sanitizer()
    sanitized = sanitizer.sanitize_session(session)
    assert sanitized.user != "alice"
    assert sanitized.src_ip != "10.0.0.1"
    assert sanitized.host != "server01"
    assert sanitized.session_id == session.session_id
    assert sanitized.events == session.events


def test_none_values_preserved() -> None:
    """None values are not tokenized."""
    event = _sample_event()
    event_none = event.model_copy(update={"src_ip": None})
    sanitizer = Sanitizer()
    sanitized = sanitizer.sanitize_event(event_none)
    assert sanitized.src_ip is None
    restored = sanitizer.desanitize_event(sanitized)
    assert restored == event_none
