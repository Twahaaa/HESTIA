"""Case queue, case detail, run start and analyst dispositions."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Header, Query, Request, Response

from hestia.api.contracts import (
    CaseDetail,
    CasePage,
    Disposition,
    DispositionRequest,
    RunStartRequest,
    RunStartResponse,
)
from hestia.api.runs import read_run_or_fail, run_detail
from hestia.api.workspace import fail, fail_from, repository_or_fail, service
from hestia.runs.cases import CaseCatalog
from hestia.runs.service import RunRequestError

IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_DATASET = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _catalog(request: Request) -> CaseCatalog:
    runs = service(request)
    return CaseCatalog(runs.settings, repository_or_fail(request))


def _session_or_fail(catalog: CaseCatalog, case_id: str) -> str:
    session_id = catalog.session_id(case_id)
    if session_id is None:
        fail(404, "case_not_found", "no prepared case has that identifier", case_id=case_id)
    return session_id


def build_router() -> APIRouter:
    router = APIRouter(prefix="/api/cases", tags=["cases"])

    @router.get("", response_model=CasePage)
    def list_cases(
        request: Request,
        dataset: Annotated[str | None, Query(max_length=64)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        if dataset is not None and not _DATASET.fullmatch(dataset):
            fail(422, "invalid_dataset", "dataset identifiers are short plain names")
        return _catalog(request).list_cases(dataset_id=dataset, limit=limit, offset=offset)

    @router.get("/{case_id}", response_model=CaseDetail)
    def get_case(request: Request, case_id: str) -> dict[str, Any]:
        detail = _catalog(request).case_detail(case_id)
        if detail is None:
            fail(404, "case_not_found", "no prepared case has that identifier", case_id=case_id)
        return detail

    @router.post("/{case_id}/runs", response_model=RunStartResponse, status_code=202)
    def start_run(
        request: Request,
        response: Response,
        case_id: str,
        body: RunStartRequest,
        idempotency_key: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        if idempotency_key is None or not IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            fail(
                400,
                "idempotency_key_required",
                "send an Idempotency-Key header of 8-128 letters, digits, '-' or '_'",
            )
        catalog = _catalog(request)
        session_id = _session_or_fail(catalog, case_id)
        try:
            run_id, created = service(request).request_run(
                case_id=case_id,
                session_id=session_id,
                idempotency_key=idempotency_key,
                mode=body.mode,
                confirm_hosted=body.confirm_hosted,
            )
        except RunRequestError as exc:
            fail_from(exc)
        if not created:
            response.status_code = 200
        return {"created": created, "run": run_detail(request, read_run_or_fail(request, run_id))}

    @router.post("/{case_id}/dispositions", response_model=Disposition, status_code=201)
    def record_disposition(
        request: Request, case_id: str, body: DispositionRequest
    ) -> dict[str, Any]:
        catalog = _catalog(request)
        session_id = _session_or_fail(catalog, case_id)
        repository = catalog.repository
        if body.run_id is not None:
            run = repository.read_case_run(body.run_id)
            if run is None or run["session_id"] != session_id:
                fail(422, "run_not_in_case", "the referenced run does not belong to this case")
            if body.disposition == "report_disputed" and run["state"] != "completed":
                fail(422, "no_report_to_dispute", "only a published report can be disputed")
        elif body.disposition == "report_disputed":
            fail(422, "run_required", "disputing a report requires the run that produced it")
        recorded_at = datetime.now(UTC)
        record = {
            "disposition_id": uuid.uuid4().hex,
            "case_id": case_id,
            "run_id": body.run_id,
            "disposition": body.disposition,
            "note": body.note.strip(),
            "actor": (body.actor or service(request).settings.analyst_name).strip(),
            "recorded_at": recorded_at.isoformat(),
        }
        repository.record_disposition(
            disposition_id=record["disposition_id"],
            case_id=case_id,
            session_id=session_id,
            run_id=body.run_id,
            disposition=body.disposition,
            note=record["note"],
            actor=record["actor"],
            recorded_at=recorded_at,
        )
        return record

    return router


__all__ = ["IDEMPOTENCY_KEY", "build_router"]
