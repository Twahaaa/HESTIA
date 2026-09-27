"""The case queue and case detail: honest ordering, no invented labels."""

from __future__ import annotations

from fastapi.testclient import TestClient
from workspace_helpers import start

from hestia.api.app import create_app
from hestia.config import Settings

THREAT_WORDS = ("threat", "attack", "malicious", "verdict", "severity", "label")


def test_queue_is_unscored_time_ordered_and_says_why(client):
    page = client.get("/api/cases").json()
    assert page["total"] == 8
    assert page["datasets"] == ["synthetic-demo"]
    assert page["scoring"]["available"] is False
    assert page["scoring"]["ordering"] == "session start time"
    assert "not evidence that the activity is normal" in page["scoring"]["note"]
    starts = [item["start"] for item in page["items"]]
    assert starts == sorted(starts)
    for item in page["items"]:
        assert item["priority"] == {
            "score": None,
            "scored": False,
            "reason": item["priority"]["reason"],
        }
        assert item["priority"]["reason"].startswith("no behavioural model is ready")
        assert item["case_id"].startswith("case-") and len(item["case_id"]) == 25
        assert not any(word in key for key in item for word in THREAT_WORDS)


def test_queue_paginates_and_filters_by_registered_dataset(client):
    first = client.get("/api/cases", params={"limit": 3}).json()
    second = client.get("/api/cases", params={"limit": 3, "offset": 3}).json()
    assert len(first["items"]) == 3 and len(second["items"]) == 3
    assert {i["case_id"] for i in first["items"]}.isdisjoint(
        {i["case_id"] for i in second["items"]}
    )
    assert client.get("/api/cases", params={"dataset": "nope"}).json()["total"] == 0
    assert client.get("/api/cases", params={"dataset": "../etc"}).status_code == 422
    assert client.get("/api/cases", params={"limit": 0}).status_code == 422
    assert client.get("/api/cases", params={"limit": 101}).status_code == 422


def test_case_detail_returns_canonical_source_lines(client):
    case = client.get("/api/cases").json()["items"][1]
    detail = client.get(f"/api/cases/{case['case_id']}").json()
    assert detail["event_count"] == len(detail["events"]) == detail["events_shown"]
    assert detail["events_truncated"] is False
    line = detail["events"][0]
    assert line["source"] == "synthetic-demo/auth.log"
    assert line["line_no"] >= 1
    assert "Failed password for invalid user admin" in line["line"]
    assert "not a threat assessment" in detail["parsed_attributes"]["note"]
    assert detail["priority"]["scored"] is False
    assert detail["runs"] == [] and detail["dispositions"] == []


def test_invalid_and_unknown_case_ids_are_not_found(client):
    for case_id in ("case-zzz", "case-" + "0" * 20, "session"):
        response = client.get(f"/api/cases/{case_id}")
        assert response.status_code == 404, case_id
        assert response.json()["detail"]["code"] == "case_not_found"
    assert client.get("/api/cases/..%2F..%2Fetc").status_code == 404
    response = start(client, "case-" + "0" * 20, "key-unknown-case")
    assert response.status_code == 404


def test_missing_store_is_reported_not_crashed(tmp_path):
    settings = Settings(
        data_root=tmp_path / "data",
        artifact_root=tmp_path / "empty",
        frontend_dist=tmp_path / "no-ui",
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        response = client.get("/api/cases")
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "store_unavailable"
        status = client.get("/api/workspace").json()
        assert status["store"] == {
            "available": False,
            "schema_version": None,
            "reason": "evidence preparation has not been run",
        }
        assert not (tmp_path / "empty" / "evidence.sqlite3").exists()
