"""Pure deterministic feature extraction for closed sessions."""

from __future__ import annotations

import math
from collections import Counter
from datetime import UTC
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from hestia.contracts import Event, Session
from hestia.normality.models import MaterializedFeatureContext, SessionFeatures

FEATURE_SCHEMA_VERSION = "1"


def extract_session_features(
    session: Session,
    events: list[Event] | tuple[Event, ...],
    deployment_timezone: str,
    materialized_context: MaterializedFeatureContext,
) -> SessionFeatures:
    """Extract unrounded behavioral inputs from one fully closed Session.

    The supplied Event sequence is authoritative: equal timestamps retain its
    stored order. Historical counts are explicit inputs so this function has no
    store access and is deterministic for a fixed snapshot context.
    """
    ordered_events = tuple(events)
    _validate_closed_session(session, ordered_events)
    try:
        timezone = ZoneInfo(deployment_timezone)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"Unknown deployment timezone: {deployment_timezone!r}") from exc

    start_utc = session.start_time.astimezone(UTC)
    local_hour = session.start_time.astimezone(timezone).hour
    angle = 2.0 * math.pi * local_hour / 24.0
    event_type_counts = Counter(event.event_type for event in ordered_events)
    denominator = len(ordered_events)
    successes = sum(event.success is True for event in ordered_events)
    failures = sum(event.success is False for event in ordered_events)

    return SessionFeatures(
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        session_id=session.session_id,
        deployment_timezone=deployment_timezone,
        login_hour_utc=start_utc.hour,
        login_hour_local=local_hour,
        hour_sin=math.sin(angle),
        hour_cos=math.cos(angle),
        auth_frequency_window_count=materialized_context.auth_frequency_window_count,
        event_count=denominator,
        failure_count=failures,
        failure_proportion=failures / denominator,
        success_proportion=successes / denominator,
        distinct_hosts_in_session=len({event.host for event in ordered_events}),
        event_type_proportions=tuple(
            (event_type, count / denominator)
            for event_type, count in sorted(event_type_counts.items())
        ),
        event_types=tuple(event.event_type for event in ordered_events),
        materialized_context=materialized_context,
    )


def _validate_closed_session(session: Session, events: tuple[Event, ...]) -> None:
    """Reject partial, missing, reordered, or cross-session Event sequences."""
    if not events:
        raise ValueError("A closed Session requires its ordered Events")
    if session.event_count != len(session.events) or session.event_count != len(events):
        raise ValueError("Session event_count and ordered Events must agree")
    if tuple(session.events) != tuple(event.event_id for event in events):
        raise ValueError("Ordered Event membership does not match the Session")
    if any(event.timestamp.tzinfo is None for event in events):
        raise ValueError("Session Events must use timezone-aware timestamps")
    if any(
        current.timestamp < previous.timestamp
        for previous, current in zip(events, events[1:], strict=False)
    ):
        raise ValueError("Session Events must retain nondecreasing stored order")
    if session.start_time.tzinfo is None or session.end_time.tzinfo is None:
        raise ValueError("Session bounds must use timezone-aware timestamps")
    if session.start_time != events[0].timestamp or session.end_time != events[-1].timestamp:
        raise ValueError("Session is not closed over the supplied ordered Events")
    if any(event.source != session.source for event in events):
        raise ValueError("Session Events must come from the Session source")
    if any(event.user != session.user or event.src_ip != session.src_ip for event in events):
        raise ValueError("Session Events must match the Session entity key")


__all__ = [
    "FEATURE_SCHEMA_VERSION",
    "MaterializedFeatureContext",
    "SessionFeatures",
    "extract_session_features",
]
