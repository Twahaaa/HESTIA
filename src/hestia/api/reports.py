"""Published reports and one-handle-at-a-time citation resolution."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request

from hestia.api.contracts import EvidenceResolution, ReportView
from hestia.api.runs import read_run_or_fail
from hestia.api.workspace import fail, repository_or_fail, service
from hestia.runs.cases import execution_label
from hestia.runs.evidence import (
    CitationError,
    handle_kind,
    load_local_map,
    mentioned_pseudonyms,
    resolve_citation,
)

VERDICT_NOTES = {
    "insufficient_evidence": (
        "The agent abstained: the retrieved evidence did not support a conclusion."
    ),
    "benign": "The agent's conclusion from the cited evidence. Review before relying on it.",
    "suspicious": "The agent's conclusion from the cited evidence. Review before relying on it.",
    "malicious": "The agent's conclusion from the cited evidence. Review before relying on it.",
}
COVERAGE_NOTES = {
    "known": (
        "The local reference material covered the observed behaviour. Coverage is not "
        "proof that the case is that technique."
    ),
    "potentially_novel": (
        "The local reference corpus did not cover the observed behaviour. This means "
        "limited local reference coverage, not a claim that the attack is new."
    ),
    "uncertain": "Reference coverage could not be established from the retrieved material.",
}
ACTIONS_NOTE = (
    "Recommendations are for analyst review only. Hestia performs no containment or remediation."
)


def build_router() -> APIRouter:
    router = APIRouter(prefix="/api/runs", tags=["reports"])

    @router.get("/{run_id}/report", response_model=ReportView)
    def get_report(request: Request, run_id: str) -> dict[str, Any]:
        run = read_run_or_fail(request, run_id)
        if run["state"] != "completed" or not run.get("report_json"):
            fail(
                409,
                "report_unavailable",
                "only a completed run has a report; this run ended without one"
                if run["state"] in {"failed", "cancelled"}
                else "the run has not finished",
                run_id=run_id,
                state=str(run["state"]),
            )
        report = json.loads(str(run["report_json"]))
        grounding = json.loads(str(run.get("grounding_json") or "{}"))
        local = load_local_map(service(request).settings, run_id)
        findings = []
        for finding in report.get("findings", ()):
            citations = []
            for handle in finding.get("evidence_handles", ()):
                resolvable = local is not None and handle in local.handles
                citations.append(
                    {
                        "handle": handle,
                        "kind": handle_kind(handle),
                        "resolvable": resolvable,
                        "reason": None
                        if resolvable
                        else (
                            "the local handle map for this run is missing"
                            if local is None
                            else "the local map has no entry for this handle"
                        ),
                    }
                )
            findings.append(
                {
                    "statement": finding["statement"],
                    "excerpt": finding.get("excerpt"),
                    "citations": citations,
                }
            )
        texts = [
            report.get("summary", ""),
            *[finding["statement"] for finding in findings],
            *report.get("recommended_actions", ()),
            *report.get("limitations", ()),
        ]
        fixture = bool(run["fixture"])
        return {
            "run_id": run_id,
            "case_id": run["case_id"],
            "schema_version": int(report.get("schema_version", 1)),
            "execution": execution_label(str(run["provider"]), str(run["model"]), fixture),
            "provider": run["provider"],
            "model": run["model"],
            "verdict": report["verdict"],
            "verdict_note": VERDICT_NOTES[report["verdict"]],
            "severity": report["severity"],
            "confidence": float(report["confidence"]),
            "summary": report["summary"],
            "findings": findings,
            "known_or_novel": report["known_or_novel"],
            "known_or_novel_note": COVERAGE_NOTES[report["known_or_novel"]],
            "technique_ids": list(report.get("technique_ids", ())),
            "recommended_actions": list(report.get("recommended_actions", ())),
            "recommended_actions_note": ACTIONS_NOTE,
            "limitations": list(report.get("limitations", ())),
            "grounding": grounding,
            "pseudonyms": mentioned_pseudonyms(texts, local),
            "citations_resolvable": local is not None,
            "citation_note": None
            if local is not None
            else (
                "This run's local handle map is missing, so its citations cannot be "
                "opened. Runs recorded before handle maps were persisted stay that way."
            ),
        }

    @router.get("/{run_id}/evidence/{handle}", response_model=EvidenceResolution)
    def get_evidence(request: Request, run_id: str, handle: str) -> dict[str, Any]:
        run = read_run_or_fail(request, run_id)
        try:
            return resolve_citation(
                service(request).settings, repository_or_fail(request), run, handle
            )
        except CitationError as exc:
            status = 404 if exc.code in {"handle_not_in_run", "evidence_missing"} else 409
            if exc.code == "invalid_handle":
                status = 422
            fail(status, exc.code, exc.message, run_id=run_id)

    return router


__all__ = ["build_router"]
