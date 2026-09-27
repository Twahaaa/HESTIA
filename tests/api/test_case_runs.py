"""Run lifecycle over HTTP: idempotency, one active run, cancellation, recovery."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from workspace_helpers import first_case, start, wait_terminal

from hestia.agent.contracts import CaseInput, CaseRun, RunState
from hestia.api.app import create_app
from hestia.runs.cases import case_id_for
from hestia.store.repository import EvidenceRepository


def test_fixture_run_completes_with_a_labelled_trace_and_report(client):
    case = first_case(client)
    response = start(client, case["case_id"], "demo-run-0001")
    assert response.status_code == 202
    body = response.json()
    assert body["created"] is True
    run = wait_terminal(client, body["run"]["run_id"])
    assert run["state"] == "completed"
    assert run["outcome"] == "report_published"
    assert run["fixture"] is True
    assert run["execution"]["kind"] == "fixture"
    assert "not a live model" in run["execution"]["label"]
    assert run["report_available"] is True and run["retry_allowed"] is False
    tools = [step["tool"] for step in run["steps"] if step["kind"] == "tool_call"]
    assert tools == ["get_session", "get_events", "get_normality_context", "search_attack_patterns"]
    assert any(step["kind"] == "hypothesis" for step in run["steps"])
    events_step = run["steps"][1]
    assert events_step["evidence_count"] == len(events_step["evidence_handles"]) >= 1
    assert "session_id" not in events_step["request_summary"]
    assert run["usage"]["tool_calls"] == 4
    assert run["verdict"] == "insufficient_evidence"

    case_view = client.get(f"/api/cases/{case['case_id']}").json()
    assert case_view["runs"][0]["run_id"] == run["run_id"]
    queue = client.get("/api/cases").json()["items"]
    latest = next(item for item in queue if item["case_id"] == case["case_id"])["latest_run"]
    assert latest["state"] == "completed" and latest["fixture"] is True


def test_idempotent_replay_returns_the_same_run(client):
    case = first_case(client)
    first = start(client, case["case_id"], "same-key-0001")
    second = start(client, case["case_id"], "same-key-0001")
    assert first.status_code == 202 and second.status_code == 200
    assert second.json()["created"] is False
    assert second.json()["run"]["run_id"] == first.json()["run"]["run_id"]
    wait_terminal(client, first.json()["run"]["run_id"])
    third = start(client, case["case_id"], "same-key-0001")
    assert third.status_code == 200
    assert third.json()["run"]["run_id"] == first.json()["run"]["run_id"]


def test_reusing_a_key_for_a_different_request_is_rejected(client):
    items = client.get("/api/cases").json()["items"]
    first = start(client, items[0]["case_id"], "reused-key-01")
    wait_terminal(client, first.json()["run"]["run_id"])
    other = start(client, items[1]["case_id"], "reused-key-01")
    assert other.status_code == 422
    assert other.json()["detail"]["code"] == "idempotency_key_reused"


def test_idempotency_key_is_required_and_validated(client):
    case = first_case(client)
    url = f"/api/cases/{case['case_id']}/runs"
    missing = client.post(url, json={"mode": "fixture"})
    assert missing.status_code == 400
    assert missing.json()["detail"]["code"] == "idempotency_key_required"
    short = client.post(url, json={"mode": "fixture"}, headers={"Idempotency-Key": "abc"})
    assert short.status_code == 400
    extra = client.post(
        url, json={"mode": "fixture", "tool": "x"}, headers={"Idempotency-Key": "valid-key-1"}
    )
    assert extra.status_code == 422


def test_paid_execution_is_never_behind_get(client):
    case = first_case(client)
    assert client.get(f"/api/cases/{case['case_id']}/runs").status_code == 405
    paths = client.app.openapi()["paths"]
    starters = [path for path in paths if path.endswith("/runs") or path.endswith("/cancel")]
    assert starters
    for path in starters:
        assert set(paths[path]) == {"post"}, path


def test_only_one_run_is_active_and_cancellation_leaves_no_report(seeded):
    paced = seeded.model_copy(update={"agent_fixture_pace_seconds": 0.4})
    with TestClient(create_app(paced)) as client:
        items = client.get("/api/cases").json()["items"]
        running = start(client, items[0]["case_id"], "active-key-01").json()["run"]
        run_id = running["run_id"]

        conflict = start(client, items[1]["case_id"], "active-key-02")
        assert conflict.status_code == 409
        detail = conflict.json()["detail"]
        assert detail["code"] == "run_active" and detail["run_id"] == run_id
        same_case = start(client, items[0]["case_id"], "active-key-03")
        assert same_case.status_code == 409
        status = client.get("/api/workspace").json()
        assert status["active_run"]["run_id"] == run_id
        assert status["active_run"]["owned_by_this_process"] is True

        cancel = client.post(f"/api/runs/{run_id}/cancel")
        assert cancel.status_code == 202 and cancel.json()["cancel_requested"] is True
        assert client.get(f"/api/runs/{run_id}").json()["cancel_requested"] is True
        run = wait_terminal(client, run_id)
        assert run["state"] == "cancelled" and run["outcome"] == "cancelled"
        assert run["report_available"] is False and run["retry_allowed"] is True
        assert run["verdict"] is None
        assert "cancelled by the analyst" in run["incomplete_reason"]
        report = client.get(f"/api/runs/{run_id}/report")
        assert report.status_code == 409
        assert report.json()["detail"]["code"] == "report_unavailable"
        again = client.post(f"/api/runs/{run_id}/cancel")
        assert again.status_code == 409 and again.json()["detail"]["code"] == "run_not_active"

        retry = start(client, items[0]["case_id"], "active-key-04")
        assert retry.status_code == 202
        client.post(f"/api/runs/{retry.json()['run']['run_id']}/cancel")
        wait_terminal(client, retry.json()["run"]["run_id"])


def test_trace_is_visible_while_the_run_is_in_progress(seeded):
    import time

    paced = seeded.model_copy(update={"agent_fixture_pace_seconds": 0.3})
    with TestClient(create_app(paced)) as client:
        case = first_case(client)
        run_id = start(client, case["case_id"], "watch-key-01").json()["run"]["run_id"]
        seen_running_steps = 0
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            run = client.get(f"/api/runs/{run_id}").json()
            if run["state"] == "running":
                seen_running_steps = max(seen_running_steps, len(run["steps"]))
                assert run["report_available"] is False and run["verdict"] is None
            if run["state"] in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        assert seen_running_steps >= 1
        assert wait_terminal(client, run_id)["state"] == "completed"


def test_unknown_run_ids_are_not_found(client):
    for run_id in ("0" * 32, "not-a-run", "../../etc/passwd"):
        response = client.get(f"/api/runs/{run_id}")
        assert response.status_code == 404
        assert client.post(f"/api/runs/{run_id}/cancel").status_code in {404, 405}
        assert client.get(f"/api/runs/{run_id}/report").status_code == 404


def test_restart_marks_interrupted_runs_and_allows_retry(seeded):
    repository = EvidenceRepository(seeded.evidence_database)
    repository.initialize()
    session_id = repository.list_case_sessions()[0]["session_id"]
    session = json.loads(repository.read_session(session_id)["session_json"])
    start_time = datetime.fromisoformat(session["start_time"])
    case = CaseInput(
        case_id=case_id_for(session_id),
        session_id=session_id,
        opened_at=datetime.now(UTC),
        session_start=start_time,
        session_end=datetime.fromisoformat(session["end_time"]),
        dataset_id="synthetic-demo",
        history_before=start_time,
    )
    orphan = CaseRun(
        run_id="a" * 32,
        case=case,
        state=RunState.pending,
        provider="fixture",
        model="fixture-analyst",
        fixture=True,
        started_at=datetime.now(UTC),
    )
    repository.request_case_run(orphan, idempotency_key="orphan-key-1", request={})
    repository.save_case_run(orphan.model_copy(update={"state": RunState.running}))

    with TestClient(create_app(seeded)) as client:
        status = client.get("/api/workspace").json()
        assert status["recovered_interrupted_runs"] == 1
        assert status["active_run"] is None
        run = client.get(f"/api/runs/{'a' * 32}").json()
        assert run["state"] == "failed"
        assert run["outcome"] == "interrupted" and run["interrupted"] is True
        assert run["retry_allowed"] is True and run["report_available"] is False
        assert "interrupted" in run["incomplete_reason"]
        retry = start(client, case.case_id, "after-restart-1")
        assert retry.status_code == 202
        assert wait_terminal(client, retry.json()["run"]["run_id"])["state"] == "completed"

    # A second restart finds nothing left to recover and keeps the history.
    with TestClient(create_app(seeded)) as client:
        assert client.get("/api/workspace").json()["recovered_interrupted_runs"] == 0
        assert client.get(f"/api/runs/{'a' * 32}").json()["outcome"] == "interrupted"


def test_configured_mode_without_a_provider_is_unavailable_not_substituted(client):
    case = first_case(client)
    response = start(client, case["case_id"], "configured-01", mode="configured")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "provider_unavailable"
    assert "HESTIA_AGENT_PROVIDER" in response.json()["detail"]["message"]
    assert client.get("/api/workspace").json()["active_run"] is None
