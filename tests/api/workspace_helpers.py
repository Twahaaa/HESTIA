"""Helpers shared by the workspace API tests."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

TERMINAL = {"completed", "failed", "cancelled"}


def first_case(client: TestClient, **params: object) -> dict:
    page = client.get("/api/cases", params=params).json()
    return page["items"][0]


def start(client: TestClient, case_id: str, key: str, **body: object):
    return client.post(
        f"/api/cases/{case_id}/runs",
        json={"mode": "fixture", **body},
        headers={"Idempotency-Key": key},
    )


def wait_terminal(client: TestClient, run_id: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["state"] in TERMINAL:
            client.app.state.runs.wait(5)
            return client.get(f"/api/runs/{run_id}").json()
        time.sleep(0.05)
    raise AssertionError(f"run {run_id} did not finish within {timeout}s")
