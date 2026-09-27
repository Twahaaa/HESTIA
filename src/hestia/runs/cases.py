"""Cases are prepared sessions, addressed by an opaque stable identifier.

A session identifier embeds the source path, host, source IP and user name, so it
is not used in URLs or request logs. The case identifier is a digest of it:
stable across restarts, unique per session, and meaningless on its own.

The queue is ordered by prioritization score only when a ready model produced
one. In this deployment no model is trained, so every case is unscored and the
queue is in time order, which the response says in words.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from hestia.config import Settings
from hestia.store.repository import EvidenceRepository

CASE_ID_PATTERN = re.compile(r"^case-[0-9a-f]{20}$")
#: Upper bound on canonical lines returned with a case. The response says when
#: a session holds more.
CASE_EVENT_LIMIT = 200


@lru_cache(maxsize=65_536)
def case_id_for(session_id: str) -> str:
    return "case-" + hashlib.sha256(session_id.encode()).hexdigest()[:20]


def valid_case_id(case_id: str) -> bool:
    return bool(CASE_ID_PATTERN.fullmatch(case_id))


@dataclass(frozen=True)
class Scoring:
    """Whether a prioritization score can exist at all in this deployment."""

    available: bool
    ready_models: int
    total_models: int
    reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "ready_models": self.ready_models,
            "total_models": self.total_models,
            "reason": self.reason,
            "ordering": "priority score, then time" if self.available else "session start time",
            "note": (
                "A missing score means no ready model scored the case. It is not "
                "evidence that the activity is normal."
            ),
        }


def scoring_status(settings: Settings) -> Scoring:
    from hestia.normality.catalog import list_models

    models = [
        model for model in list_models(settings.artifact_root) if not model["parent_model_id"]
    ]
    ready = [model for model in models if model["ready"]]
    reasons = [model["readiness_reason"] for model in models if not model["ready"]]
    reason = None
    if not ready:
        reason = (
            next((item for item in reasons if item), None) or "no verified model artifact exists"
        )
        reason = f"no behavioural model is ready: {reason}"
    return Scoring(
        available=bool(ready),
        ready_models=len(ready),
        total_models=len(models),
        reason=reason,
    )


def _summary(row: dict[str, Any]) -> dict[str, Any]:
    session = json.loads(str(row["session_json"]))
    return {
        "_session_id": str(row["session_id"]),
        "case_id": case_id_for(str(row["session_id"])),
        "dataset_id": row["dataset_id"],
        "source": row["source_path"],
        "host": session.get("host") or row.get("host") or None,
        "user": session.get("user"),
        "src_ip": session.get("src_ip"),
        "start": session.get("start_time"),
        "end": session.get("end_time"),
        "event_count": int(session.get("event_count") or 0),
        "failure_count": int(session.get("failure_count") or 0),
        "score": row.get("score"),
    }


class CaseCatalog:
    """Read-side view of cases over one evidence store."""

    def __init__(self, settings: Settings, repository: EvidenceRepository) -> None:
        self.settings = settings
        self.repository = repository

    def list_cases(self, *, dataset_id: str | None, limit: int, offset: int) -> dict[str, Any]:
        scoring = scoring_status(self.settings)
        rows = [_summary(row) for row in self.repository.list_case_sessions(dataset_id=dataset_id)]
        if scoring.available:
            rows.sort(key=lambda item: (item["score"] is None, -(item["score"] or 0.0)))
        runs = self.repository.latest_run_states()
        dispositions = self.repository.latest_dispositions()
        page = rows[offset : offset + limit]
        items = []
        for item in page:
            latest = runs.get(item["_session_id"])
            disposition = dispositions.get(item["case_id"])
            items.append(
                {
                    **{
                        key: value
                        for key, value in item.items()
                        if key not in {"score", "_session_id"}
                    },
                    "priority": {
                        "score": item["score"],
                        "scored": item["score"] is not None,
                        "reason": None
                        if item["score"] is not None
                        else (scoring.reason or "no ready model scored this session"),
                    },
                    "latest_run": None
                    if latest is None
                    else {
                        "run_id": latest["run_id"],
                        "state": latest["state"],
                        "fixture": bool(latest["fixture"]),
                        "started_at": latest["started_at"],
                    },
                    "disposition": None
                    if disposition is None
                    else {
                        "disposition": disposition["disposition"],
                        "recorded_at": disposition["recorded_at"],
                    },
                }
            )
        return {
            "items": items,
            "total": len(rows),
            "limit": limit,
            "offset": offset,
            "dataset_id": dataset_id,
            "datasets": self.repository.dataset_ids(),
            "scoring": scoring.as_dict(),
        }

    def _index(self) -> dict[str, str]:
        with self.repository._connect() as connection:  # noqa: SLF001 - read-only id scan
            return {
                case_id_for(str(row["session_id"])): str(row["session_id"])
                for row in connection.execute("SELECT session_id FROM sessions")
            }

    def session_id(self, case_id: str) -> str | None:
        if not valid_case_id(case_id):
            return None
        return self._index().get(case_id)

    def case_detail(self, case_id: str) -> dict[str, Any] | None:
        session_id = self.session_id(case_id)
        if session_id is None:
            return None
        row = self.repository.read_session(session_id)
        if row is None:
            return None
        session = json.loads(str(row["session_json"]))
        events = self.repository.read_session_events(
            session_id, after_ordinal=None, limit=CASE_EVENT_LIMIT
        )
        scoring = scoring_status(self.settings)
        return {
            "case_id": case_id,
            "dataset_id": row["dataset_id"],
            "source": row["source_path"],
            "host": session.get("host"),
            "user": session.get("user"),
            "src_ip": session.get("src_ip"),
            "start": session.get("start_time"),
            "end": session.get("end_time"),
            "event_count": int(session.get("event_count") or 0),
            "failure_count": int(session.get("failure_count") or 0),
            "parsed_attributes": {
                "has_escalation": bool(session.get("has_escalation")),
                "has_persistence": bool(session.get("has_persistence")),
                "primary_method": session.get("primary_method"),
                "note": (
                    "Parsed from the log lines by the session builder. These are "
                    "structural attributes, not a threat assessment."
                ),
            },
            "priority": self._priority(session_id, str(row["dataset_id"]), scoring),
            "scoring": scoring.as_dict(),
            "events": [canonical_line(event) for event in events],
            "events_shown": len(events),
            "events_truncated": int(session.get("event_count") or 0) > len(events),
            "runs": [run_summary(run) for run in self.repository.case_runs_for_session(session_id)],
            "dispositions": self.repository.dispositions_for_case(case_id),
        }

    def _priority(self, session_id: str, dataset_id: str, scoring: Scoring) -> dict[str, Any]:
        score = next(
            (
                row.get("score")
                for row in self.repository.list_case_sessions(dataset_id=dataset_id)
                if row["session_id"] == session_id
            ),
            None,
        )
        return {
            "score": score,
            "scored": score is not None,
            "reason": None
            if score is not None
            else (scoring.reason or "no ready model scored this session"),
        }


def canonical_line(row: dict[str, Any]) -> dict[str, Any]:
    """One stored event as the exact source line plus where it came from."""
    payload = json.loads(str(row["event_json"]))
    event = payload.get("event", {})
    return {
        "event_id": row["event_id"],
        "ordinal": row.get("ordinal"),
        "dataset_id": row["dataset_id"],
        "source": row["source_path"],
        "line_no": int(row["line_no"]),
        "timestamp": row["timestamp"],
        "raw_timestamp": payload.get("raw_timestamp"),
        "line": str(payload.get("raw_line") or event.get("raw_message") or ""),
        "event_type": event.get("event_type"),
        "success": event.get("success"),
        "unmatched": bool(row.get("unmatched")),
        "unmatched_reason": row.get("unmatched_reason"),
    }


def run_outcome(run: dict[str, Any]) -> str:
    """A plain classification of how a run ended, for display."""
    state = str(run["state"])
    if state in {"pending", "running"}:
        return "in_progress"
    if state == "completed":
        return "report_published"
    if state == "cancelled":
        return "cancelled"
    if run.get("interrupted") or run.get("interrupted_from"):
        return "interrupted"
    if run.get("grounding_failed") or run.get("failed_grounding_json"):
        return "grounding_failed"
    reason = str(run.get("incomplete_reason") or "")
    if "budget exhausted" in reason:
        return "budget_exhausted"
    if "provider" in reason or "HESTIA_AGENT" in reason:
        return "provider_unavailable"
    return "failed"


def execution_label(provider: str, model: str, fixture: bool) -> dict[str, Any]:
    if fixture:
        return {
            "kind": "fixture",
            "label": "Fixture run: deterministic scripted analyst, not a live model",
        }
    return {
        "kind": "hosted",
        "label": f"Hosted provider run ({provider} / {model})",
    }


def run_summary(run: dict[str, Any]) -> dict[str, Any]:
    usage = json.loads(str(run.get("usage_json") or "{}"))
    fixture = bool(run["fixture"])
    return {
        "run_id": run["run_id"],
        "state": run["state"],
        "outcome": run_outcome(run),
        "provider": run["provider"],
        "model": run["model"],
        "fixture": fixture,
        "execution": execution_label(str(run["provider"]), str(run["model"]), fixture),
        "started_at": run["started_at"],
        "finished_at": run.get("finished_at"),
        "incomplete_reason": run.get("incomplete_reason"),
        "verdict": run.get("verdict") if run["state"] == "completed" else None,
        "usage": usage,
    }


__all__ = [
    "CASE_EVENT_LIMIT",
    "CASE_ID_PATTERN",
    "CaseCatalog",
    "Scoring",
    "canonical_line",
    "case_id_for",
    "execution_label",
    "run_outcome",
    "run_summary",
    "scoring_status",
    "valid_case_id",
]
