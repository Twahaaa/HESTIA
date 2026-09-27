"""Run state, trace and cancellation. Starting a run lives with its case."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request

from hestia.api.contracts import CancelResponse, RunDetail
from hestia.api.workspace import fail, fail_from, repository_or_fail, service
from hestia.runs.cases import run_summary
from hestia.runs.evidence import RUN_ID_PATTERN
from hestia.runs.service import RunRequestError

#: Arguments that identify the case itself; the trace already belongs to it.
_IMPLICIT_ARGUMENTS = frozenset({"session_id"})


def request_summary(arguments: dict[str, Any]) -> str:
    """A short, readable account of what one tool call asked for."""
    parts = [
        f"{key}={value}"
        for key, value in sorted(arguments.items())
        if key not in _IMPLICIT_ARGUMENTS and value not in (None, "", [], {})
    ]
    text = ", ".join(parts) or "the case session"
    return text if len(text) <= 160 else text[:157] + "…"


def _step(row: dict[str, Any]) -> dict[str, Any]:
    payload = json.loads(str(row["payload_json"]))
    if row["kind"] == "hypothesis":
        return {
            "step": int(row["step"]),
            "kind": "hypothesis",
            "claim": payload.get("claim"),
            "support": list(payload.get("support") or ()),
            "contradictions": list(payload.get("contradictions") or ()),
            "retained": payload.get("retained"),
        }
    handles = list(payload.get("evidence_handles") or ())
    return {
        "step": int(row["step"]),
        "kind": "tool_call",
        "tool": payload.get("tool"),
        "request_summary": request_summary(payload.get("arguments") or {}),
        "available": payload.get("available"),
        "unavailable_reason": payload.get("unavailable_reason"),
        "error": payload.get("error"),
        "returned": payload.get("returned"),
        "evidence_count": len(handles),
        "evidence_handles": handles,
        "duration_ms": payload.get("duration_ms"),
        "started_at": payload.get("started_at"),
        "truncated": payload.get("truncated"),
    }


def run_detail(request: Request, run: dict[str, Any]) -> dict[str, Any]:
    grounding = None
    if run.get("grounding_json"):
        grounding = json.loads(str(run["grounding_json"]))
    elif run.get("failed_grounding_json"):
        grounding = json.loads(str(run["failed_grounding_json"]))
    state = str(run["state"])
    verdict = None
    if state == "completed" and run.get("report_json"):
        verdict = json.loads(str(run["report_json"])).get("verdict")
    return run_summary(run) | {
        "verdict": verdict,
        "case_id": run["case_id"],
        "interrupted": bool(run.get("interrupted_from")),
        "cancel_requested": service(request).cancel_requested(str(run["run_id"])),
        "retry_allowed": state in {"failed", "cancelled"},
        "report_available": state == "completed" and bool(run.get("report_json")),
        "grounding": grounding,
        "steps": [_step(step) for step in run.get("steps", ())],
    }


def read_run_or_fail(request: Request, run_id: str) -> dict[str, Any]:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        fail(404, "run_not_found", "no case run has that identifier")
    run = repository_or_fail(request).read_case_run(run_id)
    if run is None:
        fail(404, "run_not_found", "no case run has that identifier")
    return run


def build_router() -> APIRouter:
    router = APIRouter(prefix="/api/runs", tags=["runs"])

    @router.get("/{run_id}", response_model=RunDetail)
    def get_run(request: Request, run_id: str) -> dict[str, Any]:
        return run_detail(request, read_run_or_fail(request, run_id))

    @router.post("/{run_id}/cancel", response_model=CancelResponse, status_code=202)
    def cancel_run(request: Request, run_id: str) -> dict[str, Any]:
        read_run_or_fail(request, run_id)
        try:
            result = service(request).cancel(run_id)
        except RunRequestError as exc:
            fail_from(exc)
        return result | {
            "note": (
                "The run stops at its next tool boundary or when the model returns, and "
                "ends as cancelled without a report."
            )
        }

    return router


__all__ = ["build_router", "read_run_or_fail", "request_summary", "run_detail"]
