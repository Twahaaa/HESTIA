import json
from datetime import UTC, datetime

import pytest

from hestia.mcp.contracts import ToolInputError
from hestia.mcp.history import get_entity_history, get_normality_context


def test_history_is_strictly_before_the_boundary(context):
    late = get_entity_history(
        context, entity_type="host", entity_id="fixture-host", before="2030-01-01T00:00:00+00:00"
    )
    assert late.available and late.entity_session_count >= 2
    assert late.window_end is not None and late.window_end < datetime(2030, 1, 1, tzinfo=UTC)

    early = get_entity_history(
        context, entity_type="host", entity_id="fixture-host", before="2025-01-03T00:00:00+00:00"
    )
    assert early.entity_session_count < late.entity_session_count
    assert all(item.end_time < datetime(2025, 1, 3, tzinfo=UTC) for item in early.items)
    assert early.store_session_denominator >= early.entity_session_count


def test_history_reports_observations_not_severity(context):
    result = get_entity_history(
        context, entity_type="user", entity_id="alice", before="2030-01-01T00:00:00+00:00"
    )
    payload = json.loads(result.model_dump_json())
    assert result.entity_session_count >= 1
    assert "observations" in " ".join(result.notes)
    for banned in ("severity", "risk", "verdict", "label", "malicious"):
        assert banned not in {key.lower() for key in payload}


def test_history_pagination_is_stable(context):
    collected = []
    cursor = None
    while True:
        page = get_entity_history(
            context,
            entity_type="host",
            entity_id="fixture-host",
            before="2030-01-01T00:00:00+00:00",
            cursor=cursor,
            limit=1,
        )
        collected.extend(item.session_id for item in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert len(set(collected)) == len(collected)
    assert len(collected) == page.entity_session_count


def test_unknown_entity_returns_zero_not_an_error(context):
    result = get_entity_history(
        context, entity_type="user", entity_id="nobody", before="2030-01-01T00:00:00+00:00"
    )
    assert result.available and result.entity_session_count == 0 and result.items == ()


def test_history_arguments_are_validated(context):
    with pytest.raises(ToolInputError):
        get_entity_history(
            context, entity_type="process", entity_id="x", before="2030-01-01T00:00:00+00:00"
        )
    with pytest.raises(ToolInputError):
        get_entity_history(
            context, entity_type="user", entity_id="alice", before="2030-01-01T00:00:00"
        )


def test_normality_context_abstains_while_training_is_incomplete(context, session_id):
    result = get_normality_context(context, session_id=session_id)
    assert result.available
    assert result.scores_available is False
    assert result.context is not None
    assert all(model.ready is False for model in result.models)
    assert any(model.warmup_observations == 250 for model in result.models)
    assert result.training_provenance is not None
    assert result.training_provenance.ready is False
    assert "No behavioral model is ready" in " ".join(result.notes)
    assert "Missing labels do not make unlabelled traffic normal." in " ".join(result.notes)


def test_normality_context_is_materialized_before_the_session_start(context, session_id):
    repository = context.repository()
    session = json.loads(repository.read_session(session_id)["session_json"])
    result = get_normality_context(context, session_id=session_id)
    assert result.as_of == datetime.fromisoformat(session["start_time"])
    assert result.historical_session_count == len(
        repository.read_entity_sessions(
            entity_type="host",
            entity_id="fixture-host",
            before=datetime.fromisoformat(session["start_time"]),
        )
    )


def test_normality_context_records_real_training_readiness(context, session_id):
    readiness = context.settings.artifact_root / "preparation" / "readiness.json"
    readiness.parent.mkdir(parents=True, exist_ok=True)
    readiness.write_text(
        json.dumps(
            {
                "ready": False,
                "eligible_training_sessions": 0,
                "reason": "no sessions have explicit normal training eligibility",
                "split_manifest_hash": "c" * 64,
            }
        ),
        encoding="utf-8",
    )
    result = get_normality_context(context, session_id=session_id)
    provenance = result.training_provenance
    assert provenance is not None
    assert provenance.readiness_recorded is True
    assert provenance.eligible_training_sessions == 0
    assert provenance.split_manifest_hash == "c" * 64


def test_normality_context_unavailable_without_a_store(empty_context):
    result = get_normality_context(empty_context, session_id="anything:1")
    assert result.available is False
    assert "prepare-data" in (result.unavailable_reason or "")
