"""Behavior tests for deterministic closed-session features and transitions."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from hestia.contracts import Event, Session
from hestia.normality.features import (
    FEATURE_SCHEMA_VERSION,
    MaterializedFeatureContext,
    extract_session_features,
)
from hestia.normality.transitions import TransitionModel


def _event(
    event_id: str,
    timestamp: datetime,
    event_type: str,
    *,
    host: str = "host-a",
    success: bool | None = True,
) -> Event:
    return Event(
        event_id=event_id,
        source="deployment-a",
        line_no=int(event_id.removeprefix("e")),
        timestamp=timestamp,
        host=host,
        process="sshd",
        event_type=event_type,
        src_ip="192.0.2.10",
        user="alice",
        success=success,
        message=event_type,
        raw_message=event_type,
    )


def _session(events: list[Event]) -> Session:
    return Session(
        session_id="session-1",
        source="deployment-a",
        src_ip="192.0.2.10",
        user="alice",
        events=[event.event_id for event in events],
        start_time=events[0].timestamp,
        end_time=events[-1].timestamp,
        event_count=len(events),
        gap_seconds=300.0,
        host=events[0].host,
        failure_count=sum(event.success is False for event in events),
    )


def test_extracts_typed_deterministic_closed_session_features() -> None:
    start = datetime(2026, 1, 2, 23, 30, tzinfo=UTC)
    events = [
        _event("e1", start, "ssh_auth_failure", success=False),
        _event("e2", start + timedelta(seconds=1), "ssh_auth_success"),
        _event("e3", start + timedelta(seconds=2), "sudo_command", host="host-b"),
    ]
    context = MaterializedFeatureContext(
        auth_frequency_window_count=7,
        user_first_seen=False,
        src_ip_first_seen=True,
        host_first_seen=False,
        user_observation_count=11,
        src_ip_observation_count=3,
        host_observation_count=9,
        distinct_hosts_for_user=4,
        distinct_users_for_src_ip=2,
        distinct_users_for_host=6,
        distinct_src_ips_for_host=5,
    )

    first = extract_session_features(_session(events), events, "Asia/Kolkata", context)
    second = extract_session_features(_session(events), events, "Asia/Kolkata", context)

    assert first == second
    assert first.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert first.login_hour_utc == 23
    assert first.login_hour_local == 5
    assert first.auth_frequency_window_count == 7
    assert first.event_count == 3
    assert first.failure_count == 1
    assert first.failure_proportion == 1 / 3
    assert first.success_proportion == 2 / 3
    assert first.distinct_hosts_in_session == 2
    assert first.event_type_proportions == (
        ("ssh_auth_failure", 1 / 3),
        ("ssh_auth_success", 1 / 3),
        ("sudo_command", 1 / 3),
    )
    assert first.materialized_context == context
    assert first.event_types == (
        "ssh_auth_failure",
        "ssh_auth_success",
        "sudo_command",
    )


def test_rejects_partial_or_inconsistent_sessions_and_missing_events() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    event = _event("e1", now, "ssh_auth_success")
    context = MaterializedFeatureContext()

    partial = _session([event]).model_copy(update={"end_time": now + timedelta(seconds=1)})
    with pytest.raises(ValueError, match="closed"):
        extract_session_features(partial, [event], "UTC", context)

    with pytest.raises(ValueError, match="ordered Events"):
        extract_session_features(_session([event]), [], "UTC", context)

    wrong = _event("e2", now, "sudo_command")
    with pytest.raises(ValueError, match="membership"):
        extract_session_features(_session([event]), [wrong], "UTC", context)

    naive = event.model_copy(update={"timestamp": now.replace(tzinfo=None)})
    with pytest.raises(ValueError, match="timezone-aware"):
        extract_session_features(_session([event]), [naive], "UTC", context)

    with pytest.raises((ValueError, ValidationError)):
        MaterializedFeatureContext(auth_frequency_window_count=-1)


def test_transition_edges_smoothing_and_stable_tied_order() -> None:
    model = TransitionModel(alpha=1.0)
    assert model.score(()).transition_count == 0
    assert model.score(()).has_transitions is False
    singleton = model.score(("ssh_auth_success",))
    assert singleton.transition_count == 0
    assert singleton.mean_negative_log_probability is None
    assert singleton.max_negative_log_probability is None

    model.learn(("ssh_auth_success", "sudo_command", "ssh_auth_success"))
    score = model.score(("ssh_auth_success", "sudo_command", "account_created"))
    assert score.transition_count == 2
    assert score.unseen_transition_count == 1
    assert score.mean_negative_log_probability is not None
    assert score.max_negative_log_probability is not None
    assert score.max_negative_log_probability >= score.mean_negative_log_probability

    tied = datetime(2026, 1, 1, tzinfo=UTC)
    events = [
        _event("e1", tied, "ssh_auth_success"),
        _event("e2", tied, "sudo_command"),
    ]
    features = extract_session_features(
        _session(events), events, "UTC", MaterializedFeatureContext()
    )
    assert features.event_types == ("ssh_auth_success", "sudo_command")


def test_transitions_use_only_canonical_event_types_without_labels_or_verdicts() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    events = [_event("e1", now, "ssh_auth_success")]
    features = extract_session_features(
        _session(events), events, "UTC", MaterializedFeatureContext()
    )

    payload = features.model_dump()
    forbidden = {"attack", "label", "anomaly", "verdict", "composite_score"}
    assert forbidden.isdisjoint(payload)
    assert features.event_types == ("ssh_auth_success",)
    assert math.isfinite(features.hour_sin)
    assert math.isfinite(features.hour_cos)
