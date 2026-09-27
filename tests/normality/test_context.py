"""Visibly synthetic mechanics tests for leakage-safe historical context."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hestia.contracts import Event, Session
from hestia.normality.context import (
    HistoricalSessionEvidence,
    materialize_context_snapshot,
)


def _synthetic_evidence(
    session_id: str,
    when: datetime,
    *,
    user: str = "synthetic-alice",
    src_ip: str = "192.0.2.10",
    host: str = "synthetic-host-a",
) -> HistoricalSessionEvidence:
    event = Event(
        event_id=f"event-{session_id}",
        source="synthetic-source",
        line_no=1,
        timestamp=when,
        host=host,
        process="sshd",
        event_type="ssh_auth_success",
        src_ip=src_ip,
        user=user,
        success=True,
        message="synthetic",
        raw_message="synthetic",
    )
    session = Session(
        session_id=session_id,
        source="synthetic-source",
        src_ip=src_ip,
        user=user,
        events=[event.event_id],
        start_time=when,
        end_time=when,
        event_count=1,
        gap_seconds=300,
        host=host,
    )
    return HistoricalSessionEvidence(session, (event,), f"synthetic:{session_id}")


class _SyntheticRepository:
    def __init__(self, evidence: tuple[HistoricalSessionEvidence, ...]) -> None:
        self.evidence = evidence
        self.query: tuple[datetime, str] | None = None

    def iter_historical_sessions(self, *, as_of: datetime, exclude_session_id: str):
        self.query = (as_of, exclude_session_id)
        return self.evidence


def test_materializes_real_historical_counts_as_of_start_without_current_session() -> None:
    start = datetime(2026, 1, 2, 12, tzinfo=UTC)
    old = _synthetic_evidence("old", start - timedelta(days=2), host="synthetic-host-b")
    recent = _synthetic_evidence("recent", start - timedelta(hours=1))
    repository = _SyntheticRepository((old, recent))
    current = _synthetic_evidence("current", start).session

    snapshot = materialize_context_snapshot(
        repository,
        current,
        deployment_timezone="UTC",
        auth_frequency_window=timedelta(hours=24),
    )

    assert repository.query == (start, "current")
    assert snapshot.context.auth_frequency_window_count == 1
    assert snapshot.context.user_observation_count == 2
    assert snapshot.context.src_ip_observation_count == 2
    assert snapshot.context.host_observation_count == 1
    assert snapshot.context.distinct_hosts_for_user == 2
    assert snapshot.context.distinct_users_for_src_ip == 1
    assert snapshot.context.distinct_users_for_host == 1
    assert snapshot.context.distinct_src_ips_for_host == 1
    assert snapshot.context.user_first_seen is False
    assert snapshot.evidence_refs == ("synthetic:old", "synthetic:recent")


def test_rejects_repository_current_or_future_leakage_instead_of_ignoring_it() -> None:
    start = datetime(2026, 1, 2, 12, tzinfo=UTC)
    current = _synthetic_evidence("current", start).session

    with pytest.raises(ValueError, match="Current session"):
        materialize_context_snapshot(
            _SyntheticRepository((_synthetic_evidence("current", start),)),
            current,
            deployment_timezone="UTC",
        )

    with pytest.raises(ValueError, match="future"):
        materialize_context_snapshot(
            _SyntheticRepository((_synthetic_evidence("future", start + timedelta(seconds=1)),)),
            current,
            deployment_timezone="UTC",
        )


def test_empty_history_produces_truthful_first_seen_counts_not_fabricated_history() -> None:
    current = _synthetic_evidence("current", datetime(2026, 1, 2, tzinfo=UTC)).session
    context = materialize_context_snapshot(
        _SyntheticRepository(()), current, deployment_timezone="UTC"
    ).context

    assert context.user_first_seen is True
    assert context.src_ip_first_seen is True
    assert context.host_first_seen is True
    assert context.user_observation_count == 0
    assert context.auth_frequency_window_count == 0
