"""Statistical sessionization owned by the ingestion subsystem."""

from __future__ import annotations

import math
import statistics
import warnings
from collections import defaultdict
from itertools import groupby

from hestia.contracts import Event, Session


class SessionizeError(Exception):
    """Raised when sessionization cannot proceed."""


def _percentile(values: list[float], p: float) -> float:
    """Return the ``p``-th percentile of ``values`` using linear interpolation."""
    if not values:
        raise SessionizeError("Cannot compute percentile of empty gap list")
    if not 0.0 <= p <= 1.0:
        raise ValueError("Percentile must be between 0.0 and 1.0")
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    if n == 1:
        return sorted_vals[0]
    k = (n - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


def _find_knee(sorted_values: list[float]) -> float | None:
    """Find a knee in monotonically increasing ``sorted_values``.

    Uses a simple perpendicular-distance estimator. Returns ``None`` if no
    clear knee is detected.
    """
    n = len(sorted_values)
    if n < 3:
        return None
    min_val, max_val = sorted_values[0], sorted_values[-1]
    if max_val == min_val:
        return None
    max_distance = 0.0
    knee_idx = 0
    for i, value in enumerate(sorted_values):
        x = i / (n - 1)
        y = (value - min_val) / (max_val - min_val)
        distance = abs(y - x)
        if distance > max_distance:
            max_distance = distance
            knee_idx = i
    if max_distance < 0.05:
        return None
    return sorted_values[knee_idx]


def fit_gap_threshold(gaps: list[float], method: str = "knee") -> float:
    """Fit a positive inactivity-gap threshold from inter-event gaps.

    Args:
        gaps: Inter-event gaps in seconds (must be non-empty).
        method: One of ``"knee"``, ``"percentile"``, ``"mean_plus_std"``.

    Returns:
        A positive gap threshold in seconds.

    Raises:
        SessionizeError: If ``gaps`` is empty.
        ValueError: If ``method`` is unknown.
    """
    if not gaps:
        raise SessionizeError("Cannot fit gap threshold on empty gaps")

    threshold: float
    if method == "percentile":
        threshold = _percentile(gaps, 0.95)
    elif method == "knee":
        knee = _find_knee(sorted(gaps))
        if knee is None:
            warnings.warn(
                "No clear knee found; falling back to 95th percentile gap",
                stacklevel=2,
            )
            threshold = _percentile(gaps, 0.95)
        else:
            threshold = knee
    elif method == "mean_plus_std":
        mean = statistics.mean(gaps)
        std = statistics.stdev(gaps) if len(gaps) > 1 else 0.0
        threshold = mean + 2 * std
    else:
        raise ValueError(f"Unknown gap-fit method: {method!r}")

    return max(threshold, 1e-6)


def _compute_gaps(events: list[Event]) -> list[float]:
    """Compute inter-event gaps within each ``(src_ip, user)`` group."""
    gaps: list[float] = []
    valid_events = [
        event for event in events if event.src_ip is not None and event.user is not None
    ]
    sorted_events = sorted(valid_events, key=_group_key)
    for _, group in groupby(sorted_events, key=_group_key):
        group_events = sorted(group, key=lambda event: event.timestamp)
        for prev, curr in zip(group_events, group_events[1:], strict=False):
            gap = (curr.timestamp - prev.timestamp).total_seconds()
            if gap >= 0.0:
                gaps.append(gap)
    return gaps


def _group_key(event: Event) -> tuple[str, str, str | None, str | None]:
    return (event.source, event.host, event.src_ip, event.user)


def _derive_session_fields(events: list[Event]) -> dict[str, object]:
    """Derive summary fields from a list of session events."""
    primary_method: str | None = None
    key_fingerprint: str | None = None
    for event in events:
        if event.event_type == "ssh_auth_success":
            if primary_method is None:
                primary_method = event.method
            if key_fingerprint is None:
                key_fingerprint = event.key_fingerprint

    has_escalation = any(
        event.event_type in {"sudo_command", "su_session_opened"} for event in events
    )
    has_persistence = any(
        event.event_type in {"account_created", "group_member_added", "password_changed"}
        for event in events
    )
    failure_count = sum(1 for event in events if event.success is False)

    return {
        "host": events[0].host,
        "src_port": events[0].src_port,
        "primary_method": primary_method,
        "key_fingerprint": key_fingerprint,
        "has_escalation": has_escalation,
        "has_persistence": has_persistence,
        "failure_count": failure_count,
    }


def sessionize_events(
    events: list[Event],
    gap_seconds: float | None = None,
    fit_on: list[Event] | None = None,
) -> tuple[list[Session], list[Event]]:
    """Group events into ``(src_ip, user)`` sessions bounded by inactivity.

    Args:
        events: Events to sessionize.
        gap_seconds: Inactivity threshold in seconds. If ``None``, fit on
            ``fit_on``.
        fit_on: Normal-only events used to fit the gap threshold when
            ``gap_seconds`` is ``None``.

    Returns:
        Tuple of ``(sessions, quarantine_events)``. Quarantine contains events
        missing ``user`` or ``src_ip``.

    Raises:
        SessionizeError: If neither ``gap_seconds`` nor ``fit_on`` is provided,
            or if gap fitting fails.
    """
    if gap_seconds is None:
        if fit_on is None:
            raise SessionizeError("Either gap_seconds or fit_on must be provided")
        gaps = _compute_gaps(fit_on)
        if gaps:
            gap_seconds = fit_gap_threshold(gaps, method="knee")
        else:
            raise SessionizeError("Normal fitting data has no inter-event gaps")

    if not math.isfinite(gap_seconds) or gap_seconds <= 0:
        raise SessionizeError("Session gap must be positive and finite")

    sessions: list[Session] = []
    quarantine: list[Event] = []
    valid_events: list[Event] = []
    for event in events:
        if event.user is None or event.src_ip is None:
            quarantine.append(event)
        else:
            valid_events.append(event)

    grouped: defaultdict[tuple[str, str, str, str], list[Event]] = defaultdict(list)
    for event in valid_events:
        assert event.src_ip is not None and event.user is not None
        grouped[(event.source, event.host, event.src_ip, event.user)].append(event)

    for (_source, _host, src_ip, user), group in grouped.items():
        group.sort(key=lambda event: event.timestamp)
        current_session: list[Event] = []
        for event in group:
            if not current_session:
                current_session.append(event)
                continue
            gap = (event.timestamp - current_session[-1].timestamp).total_seconds()
            if gap > gap_seconds:
                sessions.append(_build_session(src_ip, user, current_session, gap_seconds))
                current_session = [event]
            else:
                current_session.append(event)
        if current_session:
            sessions.append(_build_session(src_ip, user, current_session, gap_seconds))

    sessions.sort(key=lambda session: (session.start_time, session.session_id))
    return sessions, quarantine


def _build_session(
    src_ip: str | None,
    user: str | None,
    events: list[Event],
    gap_seconds: float,
) -> Session:
    """Build a ``Session`` from a chronologically ordered event group."""
    start_time = events[0].timestamp
    end_time = events[-1].timestamp
    session_id = f"{events[0].source}:{events[0].host}:{src_ip}:{user}:{start_time.isoformat()}"
    summary = _derive_session_fields(events)
    return Session(
        session_id=session_id,
        source=events[0].source,
        src_ip=src_ip,
        user=user,
        events=[event.event_id for event in events],
        start_time=start_time,
        end_time=end_time,
        event_count=len(events),
        gap_seconds=gap_seconds,
        **summary,  # type: ignore[arg-type]
    )


__all__ = ["SessionizeError", "fit_gap_threshold", "sessionize_events"]
