"""Workspace status and the designated demo reset, plus shared API helpers."""

from __future__ import annotations

from typing import Any, NoReturn

from fastapi import APIRouter, HTTPException, Request

from hestia.api.contracts import ResetRequest, ResetResponse, WorkspaceStatus
from hestia.runs.service import RunRequestError, RunService

HOSTED_NOTE = (
    "A six-case Groq evaluation pilot has run, but hosted workspace completion has not "
    "been acceptance-tested. Fixture runs use a deterministic scripted analyst "
    "and are never presented as a live model."
)


def fail(status: int, code: str, message: str, **extra: Any) -> NoReturn:
    raise HTTPException(status_code=status, detail={"code": code, "message": message, **extra})


def fail_from(exc: RunRequestError) -> NoReturn:
    fail(exc.status, exc.code, exc.message, **exc.extra)


def service(request: Request) -> RunService:
    return request.app.state.runs


def repository_or_fail(request: Request) -> Any:
    repository = service(request).repository()
    if repository is None:
        fail(503, "store_unavailable", "evidence preparation has not been run")
    return repository


def build_router() -> APIRouter:
    router = APIRouter(prefix="/api/workspace", tags=["workspace"])

    @router.get("", response_model=WorkspaceStatus)
    def status(request: Request) -> dict[str, Any]:
        from hestia.agent.budgets import Budget
        from hestia.agent.providers import provider_status
        from hestia.runs.cases import scoring_status
        from hestia.runs.demo import is_demo_workspace

        runs = service(request)
        settings = runs.settings
        store: dict[str, Any] = {"available": False, "schema_version": None, "reason": None}
        active = None
        try:
            repository = runs.repository()
        except Exception as exc:  # noqa: BLE001 - reported, never hidden
            repository = None
            store["reason"] = f"the evidence store could not be opened: {type(exc).__name__}"
        if repository is not None:
            store = {
                "available": True,
                "schema_version": repository.schema_version(),
                "reason": None,
            }
            active = runs.active_run()
        elif store["reason"] is None:
            store["reason"] = "evidence preparation has not been run"
        return {
            "store": store,
            "provider": provider_status(settings).as_dict(),
            "fixture_available": True,
            "hosted_verified": False,
            "hosted_note": HOSTED_NOTE,
            "scoring": scoring_status(settings).as_dict(),
            "active_run": active,
            "recovered_interrupted_runs": len(runs.recovered_run_ids),
            "demo_workspace": is_demo_workspace(settings),
            "fixture_pace_seconds": settings.agent_fixture_pace_seconds,
            "budgets": Budget.from_settings(settings).as_dict(),
            "notes": [
                "One investigation runs at a time.",
                "A run that did not complete has no report.",
                "Analyst dispositions are review records only. They are not training labels "
                "and trigger no containment or remediation.",
            ],
        }

    @router.post("/reset", response_model=ResetResponse)
    def reset(request: Request, body: ResetRequest) -> dict[str, Any]:
        from hestia.runs.demo import DemoWorkspaceError, reset_demo_workspace

        runs = service(request)
        try:
            return reset_demo_workspace(runs.settings)
        except DemoWorkspaceError as exc:
            status = 409 if "active" in str(exc) else 403
            fail(status, "reset_refused", str(exc))

    return router


__all__ = ["build_router", "fail", "fail_from", "repository_or_fail", "service"]
