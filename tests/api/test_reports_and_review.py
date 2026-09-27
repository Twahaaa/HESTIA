"""Reports, citation resolution, dispositions, secrets and the demo reset."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from pydantic import SecretStr
from workspace_helpers import first_case, start, wait_terminal

from hestia.agent.contracts import CaseInput
from hestia.agent.fixtures import final_report, tool_call
from hestia.agent.runner import investigate
from hestia.api.app import create_app
from hestia.api.reports import COVERAGE_NOTES
from hestia.config import AgentProvider
from hestia.runs.cases import case_id_for
from hestia.store.repository import EvidenceRepository


def _completed_run(client) -> tuple[dict, dict]:
    case = first_case(client)
    run_id = start(client, case["case_id"], "report-key-01").json()["run"]["run_id"]
    return case, wait_terminal(client, run_id)


def test_report_explains_abstention_coverage_and_resolves_citations(client, seeded):
    case, run = _completed_run(client)
    report = client.get(f"/api/runs/{run['run_id']}/report").json()
    assert report["verdict"] == "insufficient_evidence"
    assert report["severity"] == "none"
    assert "abstained" in report["verdict_note"]
    assert report["execution"]["kind"] == "fixture"
    assert report["known_or_novel"] == "uncertain"
    assert report["known_or_novel_note"] == COVERAGE_NOTES["uncertain"]
    assert "not a claim that the attack is new" in COVERAGE_NOTES["potentially_novel"]
    assert "no containment or" in report["recommended_actions_note"]
    assert report["citations_resolvable"] is True
    assert report["grounding"]["grounded"] is True
    assert any("fixture" in item for item in report["limitations"])
    citations = [c for finding in report["findings"] for c in finding["citations"]]
    assert {c["kind"] for c in citations} == {"session", "event"}
    assert all(c["resolvable"] for c in citations)

    event = next(c for c in citations if c["kind"] == "event")
    resolved = client.get(f"/api/runs/{run['run_id']}/evidence/{event['handle']}").json()
    assert resolved["kind"] == "event"
    [line] = resolved["lines"]
    assert line["source"] == "synthetic-demo/auth.log"
    assert line["line"].startswith("Mar  3 ")
    session = next(c for c in citations if c["kind"] == "session")
    resolved = client.get(f"/api/runs/{run['run_id']}/evidence/{session['handle']}").json()
    assert resolved["session"]["event_count"] == len(resolved["lines"])

    # The map itself is never served: no response contains an uncited handle's
    # mapping or the map's own note, and the map file stays on disk.
    map_file = seeded.redaction_map_root / f"{run['run_id']}.handles.json"
    local = json.loads(map_file.read_text())
    bodies = json.dumps(
        [
            client.get(f"/api/runs/{run['run_id']}").json(),
            report,
            client.get(f"/api/cases/{case['case_id']}").json(),
        ]
    )
    assert "Local-only reverse map" not in bodies
    assert json.dumps(local["handles"]) not in bodies


def test_evidence_resolution_is_bounded_to_the_run(client):
    _, run = _completed_run(client)
    base = f"/api/runs/{run['run_id']}/evidence"
    assert client.get(f"{base}/ev-0000000000").status_code == 404
    assert client.get(f"{base}/ev-0000000000").json()["detail"]["code"] == "handle_not_in_run"
    assert client.get(f"{base}/not-a-handle").status_code == 422
    assert client.get(f"{base}/..%2F..%2Fsecret").status_code in {404, 422}


def test_a_run_without_its_local_map_is_shown_unresolvable(client, seeded):
    _, run = _completed_run(client)
    (seeded.redaction_map_root / f"{run['run_id']}.handles.json").unlink()
    report = client.get(f"/api/runs/{run['run_id']}/report").json()
    assert report["citations_resolvable"] is False
    assert "cannot be opened" in report["citation_note"]
    citation = report["findings"][0]["citations"][0]
    assert citation["resolvable"] is False
    response = client.get(f"/api/runs/{run['run_id']}/evidence/{citation['handle']}")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "map_missing"


async def test_failed_grounding_is_a_first_class_outcome(seeded):
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
    fabricated = final_report(
        verdict="suspicious",
        severity="medium",
        confidence=0.7,
        summary="Cites evidence nobody retrieved.",
        findings=[{"statement": "made up", "evidence_handles": ["ev-ffffffffff"]}],
        known_or_novel="uncertain",
    )
    settings = seeded.model_copy(
        update={"agent_provider": AgentProvider.fixture, "agent_model": "fixture-analyst"}
    )
    run = await investigate(
        settings,
        case,
        fixture_script=[tool_call("get_case_session"), fabricated, fabricated],
        persist=repository.save_case_run,
    )
    assert run.state.value == "failed"
    with TestClient(create_app(seeded)) as client:
        view = client.get(f"/api/runs/{run.run_id}").json()
        assert view["outcome"] == "grounding_failed"
        assert view["grounding"]["grounded"] is False
        assert view["grounding"]["repair_attempted"] is True
        assert view["grounding"]["issues"][0]["kind"] == "uncited_handle"
        assert view["verdict"] is None and view["report_available"] is False
        assert client.get(f"/api/runs/{run.run_id}/report").status_code == 409


def test_dispositions_are_validated_and_survive_restart(seeded):
    with TestClient(create_app(seeded)) as client:
        case, run = _completed_run(client)
        url = f"/api/cases/{case['case_id']}/dispositions"
        disputed = client.post(url, json={"disposition": "report_disputed"})
        assert disputed.status_code == 422
        assert disputed.json()["detail"]["code"] == "run_required"
        assert client.post(url, json={"disposition": "contain_host"}).status_code == 422
        assert (
            client.post(url, json={"disposition": "benign", "actor": "<script>"}).status_code == 422
        )
        other_case = client.get("/api/cases").json()["items"][3]["case_id"]
        wrong = client.post(
            f"/api/cases/{other_case}/dispositions",
            json={"disposition": "inconclusive", "run_id": run["run_id"]},
        )
        assert wrong.status_code == 422
        recorded = client.post(
            url,
            json={
                "disposition": "inconclusive",
                "note": "  Needs host context.  ",
                "run_id": run["run_id"],
            },
        )
        assert recorded.status_code == 201
        body = recorded.json()
        assert body["actor"] == "local-analyst" and body["note"] == "Needs host context."
        client.post(url, json={"disposition": "benign", "actor": "Asha R."})

    with TestClient(create_app(seeded)) as client:
        detail = client.get(f"/api/cases/{case['case_id']}").json()
        assert [d["disposition"] for d in detail["dispositions"]] == ["benign", "inconclusive"]
        assert detail["dispositions"][0]["actor"] == "Asha R."
        queue = client.get("/api/cases").json()["items"]
        latest = next(item for item in queue if item["case_id"] == case["case_id"])
        assert latest["disposition"]["disposition"] == "benign"


def test_no_provider_secret_reaches_any_response(seeded):
    secret = "sk-hestia-test-SECRET-value-0123456789"
    configured = seeded.model_copy(
        update={
            "agent_provider": AgentProvider.groq,
            "agent_model": "example-model",
            "agent_api_key": SecretStr(secret),
        }
    )
    with TestClient(create_app(configured)) as client:
        case = first_case(client)
        refused = start(client, case["case_id"], "hosted-key-01", mode="configured")
        assert refused.status_code == 422
        assert refused.json()["detail"]["code"] == "hosted_confirmation_required"
        assert client.get("/api/workspace").json()["active_run"] is None
        run_id = start(client, case["case_id"], "fixture-key-01").json()["run"]["run_id"]
        wait_terminal(client, run_id)
        responses = [
            client.get("/api/health"),
            client.get("/api/agent/status"),
            client.get("/api/workspace"),
            client.get("/api/cases"),
            client.get(f"/api/cases/{case['case_id']}"),
            client.get(f"/api/runs/{run_id}"),
            client.get(f"/api/runs/{run_id}/report"),
            refused,
        ]
        for response in responses:
            assert secret not in response.text
            assert "api_key" not in response.text
        status = client.get("/api/workspace").json()
        assert status["provider"]["configured"] is True
        assert status["hosted_verified"] is False
        assert "not been acceptance-tested" in status["hosted_note"]


def test_demo_reset_clears_case_activity_and_keeps_evidence(client, seeded):
    case, run = _completed_run(client)
    client.post(f"/api/cases/{case['case_id']}/dispositions", json={"disposition": "benign"})
    before = EvidenceRepository(seeded.evidence_database).table_counts()
    assert client.post("/api/workspace/reset", json={"confirm": "yes"}).status_code == 422
    response = client.post("/api/workspace/reset", json={"confirm": "reset demo workspace"})
    assert response.status_code == 200
    removed = response.json()["removed"]
    assert removed["agent_runs"] == 1 and removed["analyst_dispositions"] == 1
    assert removed["handle_maps"] == 1
    assert EvidenceRepository(seeded.evidence_database).table_counts() == before
    assert client.get(f"/api/runs/{run['run_id']}").status_code == 404
    assert client.get(f"/api/cases/{case['case_id']}").json()["dispositions"] == []


def test_reset_is_refused_outside_a_designated_demo_workspace(client, seeded):
    seeded.demo_marker.unlink()
    response = client.post("/api/workspace/reset", json={"confirm": "reset demo workspace"})
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "reset_refused"
    assert client.get("/api/workspace").json()["demo_workspace"] is False


def test_reset_is_refused_while_a_run_is_active(seeded):
    paced = seeded.model_copy(update={"agent_fixture_pace_seconds": 0.4})
    with TestClient(create_app(paced)) as client:
        run_id = start(client, first_case(client)["case_id"], "reset-key-01").json()["run"]
        response = client.post("/api/workspace/reset", json={"confirm": "reset demo workspace"})
        assert response.status_code == 409
        client.post(f"/api/runs/{run_id['run_id']}/cancel")
        wait_terminal(client, run_id["run_id"])


def test_seeding_refuses_a_store_that_is_not_a_demo(tmp_path, settings):
    import pytest

    from hestia.runs.demo import DemoWorkspaceError, seed_demo_workspace

    EvidenceRepository(settings.evidence_database).initialize()
    with pytest.raises(DemoWorkspaceError):
        seed_demo_workspace(settings)
    assert not settings.demo_marker.exists()
