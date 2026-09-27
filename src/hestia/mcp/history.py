"""Entity history and normality-context tools.

Both tools answer "what was already observed before this case started". Every
boundary is exclusive, so a case can never see itself or later evidence. Counts
are observations. They are not severity, and a low count is not suspicion: with
no explicitly eligible normal training data, no model here can score anything,
and this module says so instead of inventing a number.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from hestia.contracts import Session
from hestia.mcp.context import ToolContext, enforce_result_size
from hestia.mcp.contracts import (
    EntityHistoryResult,
    EntityObservation,
    HistoricalContext,
    ModelObservation,
    NormalityContextResult,
    SourceRef,
    ToolInputError,
    TrainingProvenance,
    decode_cursor,
    encode_cursor,
    validate_entity_type,
    validate_identifier,
    validate_instant,
)

_UNAVAILABLE = "the prepared evidence store does not exist; run `hestia prepare-data` first"

_OBSERVATION_NOTE = (
    "Counts are prior observations from prepared evidence only. They are not a "
    "severity, a baseline of normal behavior or a verdict."
)


def _source_ref(row: dict[str, Any], suffix: str) -> SourceRef:
    return SourceRef(
        evidence_ref=f"{row['dataset_id']}:{row['source_path']}:{suffix}",
        dataset_id=str(row["dataset_id"]),
        source_path=str(row["source_path"]),
        source_sha256=str(row["source_hash"]),
    )


def _observation(row: dict[str, Any]) -> EntityObservation:
    session = json.loads(row["session_json"])
    return EntityObservation(
        session_id=str(row["session_id"]),
        dataset_id=str(row["dataset_id"]),
        source_path=str(row["source_path"]),
        host=session.get("host"),
        user=session.get("user"),
        src_ip=session.get("src_ip"),
        start_time=datetime.fromisoformat(session["start_time"]),
        end_time=datetime.fromisoformat(session["end_time"]),
        event_count=int(session["event_count"]),
        failure_count=int(session.get("failure_count", 0)),
        source_ref=_source_ref(row, str(row["session_id"])),
    )


def get_entity_history(
    context: ToolContext,
    *,
    entity_type: str,
    entity_id: str,
    before: str,
    cursor: str | None = None,
    limit: int | None = None,
) -> EntityHistoryResult:
    """Summarize what a user, host or source IP did strictly before ``before``."""
    call = context.begin()
    kind = validate_entity_type(entity_type)
    identifier = validate_identifier(entity_id, field="entity_id")
    boundary = validate_instant(before, field="before")
    if boundary is None:
        raise ToolInputError("before is required and must include a timezone offset")
    page_size = context.page_size(limit)
    after = decode_cursor(cursor, arity=2)
    if not context.evidence_available():
        return EntityHistoryResult(
            request_id=call.request_id, available=False, unavailable_reason=_UNAVAILABLE
        )

    repository = context.repository()
    every = repository.read_entity_sessions(entity_type=kind, entity_id=identifier, before=boundary)
    call.check_deadline()
    sessions = [json.loads(row["session_json"]) for row in every]
    page_rows = repository.read_entity_sessions(
        entity_type=kind,
        entity_id=identifier,
        before=boundary,
        after=(after[0], after[1]) if after is not None else None,
        limit=page_size + 1,
    )
    has_more = len(page_rows) > page_size
    page_rows = page_rows[:page_size]
    items = tuple(_observation(row) for row in page_rows)
    next_cursor = (
        encode_cursor((str(page_rows[-1]["start"]), str(page_rows[-1]["session_id"])))
        if has_more and page_rows
        else None
    )
    starts = [datetime.fromisoformat(row["start"]) for row in every]
    ends = [datetime.fromisoformat(row["end"]) for row in every]
    result = EntityHistoryResult(
        request_id=call.request_id,
        available=True,
        entity_type=kind,
        entity_id=identifier,
        before=boundary,
        window_start=min(starts) if starts else None,
        window_end=max(ends) if ends else None,
        entity_session_count=len(every),
        entity_event_count=sum(int(item["event_count"]) for item in sessions),
        store_session_denominator=repository.count_sessions_before(boundary),
        distinct_hosts=len({item.get("host") for item in sessions if item.get("host")}),
        distinct_users=len({item.get("user") for item in sessions if item.get("user")}),
        distinct_src_ips=len({item.get("src_ip") for item in sessions if item.get("src_ip")}),
        items=items,
        returned=len(items),
        next_cursor=next_cursor,
        source_refs=tuple(item.source_ref for item in items),
        notes=(
            _OBSERVATION_NOTE,
            "The boundary is exclusive: only sessions that closed before it are counted.",
        ),
    )
    return enforce_result_size(
        result, maximum_bytes=context.settings.mcp_max_result_bytes, items_field="items"
    )


def _historical_ref(evidence_ref: str, hashes: dict[str, dict[str, str]]) -> SourceRef:
    """Resolve a ``dataset:path:session`` reference back to its imported digest."""
    dataset_id, source_path, _ = evidence_ref.split(":", 2)
    return SourceRef(
        evidence_ref=evidence_ref,
        dataset_id=dataset_id,
        source_path=source_path,
        source_sha256=hashes.get(dataset_id, {}).get(source_path, ""),
    )


def _training_provenance(artifact_root: Path) -> dict[str, Any]:
    path = artifact_root / "preparation" / "readiness.json"
    if not path.is_file():
        return {
            "readiness_recorded": False,
            "ready": False,
            "reason": "normality training has not been run in this deployment",
            "eligible_training_sessions": None,
            "artifact_count": None,
            "split_manifest_hash": None,
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {
            "readiness_recorded": False,
            "ready": False,
            "reason": "the recorded training readiness could not be read",
            "eligible_training_sessions": None,
            "artifact_count": None,
            "split_manifest_hash": None,
        }
    return {
        "readiness_recorded": True,
        "ready": bool(payload.get("ready")),
        "reason": payload.get("reason"),
        "eligible_training_sessions": payload.get("eligible_training_sessions"),
        "artifact_count": payload.get("artifact_count"),
        "split_manifest_hash": payload.get("split_manifest_hash"),
    }


def _model_observations(artifact_root: Path, session: Session) -> tuple[ModelObservation, ...]:
    from hestia.normality.catalog import list_models

    entities = {"user": session.user, "host": session.host, "src_ip": session.src_ip}
    observations: list[ModelObservation] = []
    for model in list_models(artifact_root):
        if model.get("parent_model_id"):
            continue
        entity_id = entities.get(str(model["entity_kind"]))
        entry = next(
            (item for item in model.get("entities", ()) if item["entity_id"] == entity_id),
            None,
        )
        if entity_id is None:
            reason = "entity identity is unavailable for this session"
            ready, count = False, 0
        elif entry is None:
            reason = model.get("readiness_reason") or "no verified training artifact"
            ready, count = False, 0
        else:
            reason = entry.get("reason")
            ready = bool(entry.get("ready"))
            count = int(entry.get("observation_count", 0))
        observations.append(
            ModelObservation(
                model_id=str(model["model_id"]),
                entity_kind=str(model["entity_kind"]),
                entity_id=entity_id,
                ready=ready,
                readiness_reason=reason,
                observation_count=count,
                warmup_observations=int(model["warmup_observations"]),
            )
        )
    return tuple(observations)


def get_normality_context(
    context: ToolContext, *, session_id: str, deployment_timezone: str = "UTC"
) -> NormalityContextResult:
    """Explain what is known about a session's entities before it started.

    The historical counts are real. The model scores are not produced here: while
    no session has explicit benign training eligibility, every model reports
    not-ready with its reason rather than a number an investigator could mistake
    for a calibrated anomaly score.
    """
    from hestia.normality.context import materialize_context_snapshot

    call = context.begin()
    identifier = validate_identifier(session_id, field="session_id", maximum=1024)
    timezone = validate_identifier(deployment_timezone, field="deployment_timezone", maximum=64)
    if not context.evidence_available():
        return NormalityContextResult(
            request_id=call.request_id, available=False, unavailable_reason=_UNAVAILABLE
        )
    repository = context.repository()
    row = repository.read_session(identifier)
    if row is None:
        return NormalityContextResult(
            request_id=call.request_id,
            available=False,
            unavailable_reason="no prepared session has that identifier",
        )
    session = Session.model_validate_json(row["session_json"])
    snapshot = materialize_context_snapshot(repository, session, deployment_timezone=timezone)
    call.check_deadline()
    provenance = TrainingProvenance(**_training_provenance(context.settings.artifact_root))
    models = _model_observations(context.settings.artifact_root, session)
    refs = snapshot.evidence_refs[: context.settings.mcp_max_evidence_refs]
    hashes: dict[str, dict[str, str]] = {}
    for ref in refs:
        dataset_id = ref.split(":", 2)[0]
        if dataset_id not in hashes:
            hashes[dataset_id] = repository.source_hashes(dataset_id)
    notes = [
        _OBSERVATION_NOTE,
        "All counts are materialized strictly before the session start time.",
    ]
    if not any(model.ready for model in models):
        notes.append(
            "No behavioral model is ready, so no anomaly score is returned. "
            "Missing labels do not make unlabelled traffic normal."
        )
    return NormalityContextResult(
        request_id=call.request_id,
        available=True,
        session_id=session.session_id,
        as_of=snapshot.as_of,
        historical_session_count=len(snapshot.evidence_refs),
        context=HistoricalContext(**snapshot.context.model_dump()),
        models=models,
        training_provenance=provenance,
        scores_available=any(model.ready for model in models),
        truncated=len(refs) < len(snapshot.evidence_refs),
        truncation_reason=(
            f"only the first {len(refs)} of {len(snapshot.evidence_refs)} historical "
            "evidence references are listed"
            if len(refs) < len(snapshot.evidence_refs)
            else None
        ),
        source_refs=tuple(_historical_ref(ref, hashes) for ref in refs),
        notes=tuple(notes),
    )


__all__ = ["get_entity_history", "get_normality_context"]
