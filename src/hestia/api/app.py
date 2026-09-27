from __future__ import annotations

import inspect
import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from hestia.config import Settings
from hestia.datasets.catalog import list_datasets
from hestia.normality.catalog import list_models

_PREPARATION_TABLES = {
    "sources": "sources",
    "events": "events",
    "parse_failures": "parse_failures",
    "sessions": "sessions",
    "unmatched_events": "unmatched_events",
}


def _model_catalog(artifact_root: Path) -> list[dict[str, Any]]:
    """Call either the foundation catalog or its artifact-aware H1 interface."""
    parameters = list(inspect.signature(list_models).parameters.values())
    if not parameters:
        return list_models()
    parameter = parameters[0]
    if parameter.kind == inspect.Parameter.KEYWORD_ONLY:
        return list_models(**{parameter.name: artifact_root})
    return list_models(artifact_root)


def _preparation_counts(database: Path) -> tuple[str, dict[str, int]]:
    counts = {name: 0 for name in _PREPARATION_TABLES}
    if not database.is_file():
        return "not_created", counts

    try:
        with sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True) as connection:
            existing = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            for name, table in _PREPARATION_TABLES.items():
                if table in existing:
                    counts[name] = int(
                        connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    )
    except (OSError, sqlite3.Error):
        return "unavailable", {name: 0 for name in _PREPARATION_TABLES}
    return "available", counts


def _readiness_reason(model: dict[str, Any]) -> str:
    reason = model.get("readiness_reason") or model.get("reason") or model.get("status")
    if isinstance(reason, str) and reason:
        return reason.replace("_", " ")
    return "verified training artifact is unavailable"


def _preparation_snapshot(settings: Settings) -> dict[str, Any]:
    database = getattr(
        settings,
        "evidence_db",
        getattr(settings, "evidence_database", settings.artifact_root / "evidence.sqlite3"),
    )
    database_status, counts = _preparation_counts(database)
    models = [
        model
        for model in _model_catalog(settings.artifact_root)
        if not model.get("parent_model_id")
    ]
    ready_models = sum(bool(model.get("ready")) for model in models)
    reasons: list[str] = []
    if database_status == "not_created":
        reasons.append("evidence preparation has not been run")
    elif database_status == "unavailable":
        reasons.append("the evidence store is unavailable")
    elif counts["events"] == 0:
        reasons.append("the evidence store contains no prepared events")
    if counts["sessions"] == 0:
        reasons.append("no complete sessions are available")
    reasons.extend(_readiness_reason(model) for model in models if not model.get("ready"))
    reasons = list(dict.fromkeys(reasons))

    unmatched = counts["unmatched_events"]
    events = counts["events"]
    return {
        "status": database_status,
        "counts": counts,
        "unmatched": {
            "count": unmatched,
            "matched_count": max(events - unmatched, 0),
            "percent_of_events": round(unmatched / events * 100, 1) if events else None,
        },
        "readiness": {
            "ready": not reasons
            and database_status == "available"
            and events > 0
            and bool(models)
            and ready_models == len(models),
            "ready_models": ready_models,
            "total_models": len(models),
            "reasons": reasons,
        },
    }


def _agent_snapshot(settings: Settings) -> dict[str, Any]:
    """Report agent readiness from configuration and stored runs only.

    This never contacts a provider, so the endpoint stays usable with no
    credentials configured and says plainly why the agent is unavailable.
    """
    from hestia.agent.budgets import Budget
    from hestia.agent.providers import provider_status

    status = provider_status(settings)
    unavailable = {
        "available": False,
        "counts": {},
        "total": 0,
        "latest": None,
        "reason": "the evidence store has not been created",
    }
    runs: dict[str, Any] = dict(unavailable)
    database = settings.evidence_database
    if database.is_file():
        try:
            from hestia.store.repository import EvidenceRepository

            runs = {"available": True, **EvidenceRepository(database).case_run_summary()}
        except (OSError, sqlite3.Error):
            runs = dict(unavailable) | {
                "reason": (
                    "the evidence store has no case-run tables yet; run "
                    "`hestia investigate` once to migrate it forward"
                )
            }
    return {
        "provider": status.as_dict(),
        "budgets": Budget.from_settings(settings).as_dict(),
        "runs": runs,
        "notes": [
            "Tool results are redacted before any provider call.",
            "A report is published only when its citations resolve locally.",
            "An incomplete run is never presented as a verdict.",
        ],
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    from hestia.api import cases, reports, runs, workspace
    from hestia.runs.service import RunService

    service = RunService(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Recovery happens before the first request: any run still recorded as
        # active belonged to a worker that no longer exists.
        try:
            service.start()
        except (OSError, sqlite3.Error, RuntimeError) as exc:
            logging.getLogger("hestia.runs").error(
                "case workspace recovery failed: %s", type(exc).__name__
            )
        yield
        service.shutdown()

    app = FastAPI(title="Hestia", version="0.1.0", lifespan=lifespan)
    app.state.runs = service

    @app.get("/api/health")
    def health() -> dict:
        from hestia.agent.providers import provider_status

        status = provider_status(settings)
        return {
            "status": "ok",
            "service": "hestia",
            "agent_status": "configured" if status.configured else "unconfigured",
            "agent_detail": "/api/agent/status",
        }

    @app.get("/api/datasets")
    def datasets() -> dict:
        return {"datasets": list_datasets(settings.data_root)}

    @app.get("/api/normality/models")
    def models() -> dict:
        return {"models": _model_catalog(settings.artifact_root)}

    @app.get("/api/preparation")
    def preparation() -> dict:
        return _preparation_snapshot(settings)

    @app.get("/api/agent/status")
    def agent_status() -> dict:
        return _agent_snapshot(settings)

    app.include_router(workspace.build_router())
    app.include_router(cases.build_router())
    app.include_router(runs.build_router())
    app.include_router(reports.build_router())

    if settings.frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=settings.frontend_dist, html=True), name="frontend")
    return app
