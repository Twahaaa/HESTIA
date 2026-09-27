"""Leakage-safe materialization of historical feature context."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from hestia.contracts import Event, Session
from hestia.normality.models import MaterializedFeatureContext


@dataclass(frozen=True)
class HistoricalSessionEvidence:
    """One closed historical session returned by an integration repository."""

    session: Session
    events: tuple[Event, ...]
    evidence_ref: str


class HistoricalEvidenceRepository(Protocol):
    """Minimal read protocol required by context materialization."""

    def iter_historical_sessions(
        self,
        *,
        as_of: datetime,
        exclude_session_id: str,
    ) -> Iterable[HistoricalSessionEvidence]:
        """Yield closed sessions whose events are strictly historical at ``as_of``."""


@dataclass(frozen=True)
class MaterializedContextSnapshot:
    """Feature context and the historical evidence used to derive it."""

    context: MaterializedFeatureContext
    evidence_refs: tuple[str, ...]
    as_of: datetime


def materialize_context_snapshot(
    repository: HistoricalEvidenceRepository,
    session: Session,
    *,
    deployment_timezone: str,
    auth_frequency_window: timedelta = timedelta(hours=24),
) -> MaterializedContextSnapshot:
    """Compute all historical counts as of the current session's start.

    The repository remains responsible for efficient indexed retrieval. This layer
    validates the boundary so an integration bug cannot silently leak the current or
    future evidence into a feature vector.
    """
    if session.start_time.tzinfo is None:
        raise ValueError("Session start_time must be timezone-aware")
    if auth_frequency_window <= timedelta(0):
        raise ValueError("auth_frequency_window must be positive")

    history = tuple(
        repository.iter_historical_sessions(
            as_of=session.start_time,
            exclude_session_id=session.session_id,
        )
    )
    if len({item.session.session_id for item in history}) != len(history):
        raise ValueError("Repository returned duplicate historical sessions")
    if len({item.evidence_ref for item in history}) != len(history):
        raise ValueError("Repository returned duplicate historical evidence references")
    for item in history:
        _validate_historical_evidence(item, session)

    user_history = tuple(
        item for item in history if session.user is not None and item.session.user == session.user
    )
    src_ip_history = tuple(
        item
        for item in history
        if session.src_ip is not None and item.session.src_ip == session.src_ip
    )
    host_history = tuple(
        item for item in history if session.host is not None and item.session.host == session.host
    )
    window_start = session.start_time - auth_frequency_window
    auth_frequency = sum(
        event.event_type.startswith("ssh_auth_")
        and window_start <= event.timestamp < session.start_time
        for item in user_history
        for event in item.events
    )

    context = MaterializedFeatureContext(
        deployment_timezone=deployment_timezone,
        auth_frequency_window_count=auth_frequency,
        user_first_seen=not user_history,
        src_ip_first_seen=not src_ip_history,
        host_first_seen=not host_history,
        user_observation_count=len(user_history),
        src_ip_observation_count=len(src_ip_history),
        host_observation_count=len(host_history),
        distinct_hosts_for_user=len(
            {item.session.host for item in user_history if item.session.host is not None}
        ),
        distinct_users_for_src_ip=len(
            {item.session.user for item in src_ip_history if item.session.user is not None}
        ),
        distinct_users_for_host=len(
            {item.session.user for item in host_history if item.session.user is not None}
        ),
        distinct_src_ips_for_host=len(
            {item.session.src_ip for item in host_history if item.session.src_ip is not None}
        ),
    )
    return MaterializedContextSnapshot(
        context=context,
        evidence_refs=tuple(sorted({item.evidence_ref for item in history})),
        as_of=session.start_time,
    )


def materialize_feature_context(
    repository: HistoricalEvidenceRepository,
    session: Session,
    *,
    deployment_timezone: str,
    auth_frequency_window: timedelta = timedelta(hours=24),
) -> MaterializedFeatureContext:
    """Return only the materialized feature contract for feature extraction."""
    return materialize_context_snapshot(
        repository,
        session,
        deployment_timezone=deployment_timezone,
        auth_frequency_window=auth_frequency_window,
    ).context


def _validate_historical_evidence(
    evidence: HistoricalSessionEvidence,
    current_session: Session,
) -> None:
    historical = evidence.session
    if not evidence.evidence_ref:
        raise ValueError("Historical evidence requires a stable evidence_ref")
    if historical.session_id == current_session.session_id:
        raise ValueError("Current session appeared in its own historical context")
    if historical.start_time.tzinfo is None or historical.end_time.tzinfo is None:
        raise ValueError("Historical session bounds must be timezone-aware")
    if historical.end_time > current_session.start_time:
        raise ValueError("Repository returned current or future evidence")
    if not evidence.events:
        raise ValueError("Historical context requires closed sessions with events")
    if tuple(historical.events) != tuple(event.event_id for event in evidence.events):
        raise ValueError("Historical event membership is inconsistent")
    if historical.event_count != len(evidence.events):
        raise ValueError("Historical event_count is inconsistent")
    if any(event.timestamp.tzinfo is None for event in evidence.events):
        raise ValueError("Historical events must be timezone-aware")
    if any(
        current.timestamp < previous.timestamp
        for previous, current in zip(evidence.events, evidence.events[1:], strict=False)
    ):
        raise ValueError("Historical events are not in stored chronological order")
    if (
        evidence.events[0].timestamp != historical.start_time
        or evidence.events[-1].timestamp != historical.end_time
    ):
        raise ValueError("Historical session is not closed over its events")
    if any(event.source != historical.source for event in evidence.events):
        raise ValueError("Historical event source is inconsistent")
    if any(event.timestamp >= current_session.start_time for event in evidence.events):
        raise ValueError("Repository returned a current or future event")


__all__ = [
    "HistoricalEvidenceRepository",
    "HistoricalSessionEvidence",
    "MaterializedContextSnapshot",
    "materialize_context_snapshot",
    "materialize_feature_context",
]
