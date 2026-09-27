"""Tests for statistical sessionization."""

from datetime import datetime

import pytest

from hestia.contracts import Event
from hestia.ingestion.sessionization import (
    SessionizeError,
    fit_gap_threshold,
    sessionize_events,
)


def _event(
    event_id: str,
    timestamp: datetime,
    src_ip: str | None = "10.0.0.1",
    user: str | None = "alice",
    event_type: str = "ssh_auth_success",
    method: str | None = "password",
    success: bool | None = True,
) -> Event:
    return Event(
        event_id=event_id,
        source="auth.log",
        line_no=1,
        timestamp=timestamp,
        host="host01",
        process="sshd",
        event_type=event_type,
        src_ip=src_ip,
        src_port=12345,
        user=user,
        method=method,
        success=success,
        message="",
        raw_message="",
    )


def test_gap_fit_on_normal_only() -> None:
    """Fitting on synthetic gaps returns a positive threshold."""
    gaps = [1.0, 2.0, 3.0, 4.0, 5.0, 100.0]
    threshold = fit_gap_threshold(gaps, method="knee")
    assert threshold > 0.0


def test_gap_fit_percentile() -> None:
    """Percentile method returns a value above the bulk and within the tail."""
    gaps = [1.0] * 95 + [100.0] * 5
    threshold = fit_gap_threshold(gaps, method="percentile")
    assert 1.0 < threshold <= 100.0


def test_gap_fit_mean_plus_std() -> None:
    """Mean+2std method returns a positive threshold."""
    gaps = [1.0, 2.0, 3.0]
    threshold = fit_gap_threshold(gaps, method="mean_plus_std")
    assert threshold > 0.0


def test_sessions_group_by_src_ip_user() -> None:
    """Different (src_ip, user) pairs become separate sessions."""
    events = [
        _event("evt-1", datetime(2024, 1, 1, 0, 0, 0), src_ip="10.0.0.1", user="alice"),
        _event("evt-2", datetime(2024, 1, 1, 0, 0, 1), src_ip="10.0.0.2", user="bob"),
    ]
    sessions, quarantine = sessionize_events(events, gap_seconds=300.0)
    assert len(sessions) == 2
    assert not quarantine


def test_gap_splits_session() -> None:
    """Two events far apart in the same group become two sessions."""
    events = [
        _event("evt-1", datetime(2024, 1, 1, 0, 0, 0), src_ip="10.0.0.1", user="alice"),
        _event("evt-2", datetime(2024, 1, 1, 1, 0, 0), src_ip="10.0.0.1", user="alice"),
    ]
    sessions, quarantine = sessionize_events(events, gap_seconds=300.0)
    assert len(sessions) == 2
    assert not quarantine


def test_missing_user_or_ip_goes_to_quarantine() -> None:
    """Events missing user or src_ip are returned as quarantine."""
    events = [
        _event("evt-1", datetime(2024, 1, 1, 0, 0, 0), src_ip="10.0.0.1", user="alice"),
        _event("evt-2", datetime(2024, 1, 1, 0, 0, 1), src_ip="10.0.0.1", user=None),
        _event("evt-3", datetime(2024, 1, 1, 0, 0, 2), src_ip=None, user="bob"),
    ]
    sessions, quarantine = sessionize_events(events, gap_seconds=300.0)
    assert len(sessions) == 1
    assert len(quarantine) == 2
    assert {event.event_id for event in quarantine} == {"evt-2", "evt-3"}


def test_session_event_ids_preserve_order() -> None:
    """Events within a session are ordered by timestamp."""
    events = [
        _event("evt-2", datetime(2024, 1, 1, 0, 0, 1), src_ip="10.0.0.1", user="alice"),
        _event("evt-1", datetime(2024, 1, 1, 0, 0, 0), src_ip="10.0.0.1", user="alice"),
    ]
    sessions, _ = sessionize_events(events, gap_seconds=300.0)
    assert len(sessions) == 1
    assert sessions[0].events == ["evt-1", "evt-2"]


def test_session_derived_flags() -> None:
    """Sessions derive escalation, persistence, and failure flags."""
    events = [
        _event("evt-1", datetime(2024, 1, 1, 0, 0, 0), src_ip="10.0.0.1", user="alice"),
        Event(
            event_id="evt-2",
            source="auth.log",
            line_no=2,
            timestamp=datetime(2024, 1, 1, 0, 0, 1),
            host="host01",
            process="sudo",
            event_type="sudo_command",
            src_ip="10.0.0.1",
            user="alice",
            target_user="root",
            command="/bin/bash",
            success=True,
            message="",
            raw_message="",
        ),
    ]
    sessions, _ = sessionize_events(events, gap_seconds=300.0)
    assert len(sessions) == 1
    assert sessions[0].has_escalation is True
    assert sessions[0].has_persistence is False


def test_sessionize_requires_gap_or_fit() -> None:
    """sessionize_events raises if neither gap_seconds nor fit_on is given."""
    events = [_event("evt-1", datetime(2024, 1, 1, 0, 0, 0))]
    with pytest.raises(SessionizeError):
        sessionize_events(events)
