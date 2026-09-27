import os
import sys

import pytest
from fastapi.testclient import TestClient
from mcp import Client, StdioServerParameters

from hestia.api.app import create_app
from hestia.config import Settings
from hestia.datasets.aitlds import load_aitlds_labels, select_normal_pool
from hestia.datasets.catalog import list_datasets
from hestia.datasets.importer import import_datasets
from hestia.ingestion.parser import parse_line
from hestia.ingestion.sessionization import SessionizeError, sessionize_events
from hestia.mcp.server import create_server


def test_api_reports_empty_data_and_untrained_models(tmp_path):
    with TestClient(
        create_app(
            Settings(
                data_root=tmp_path,
                artifact_root=tmp_path / "artifacts",
                frontend_dist=tmp_path / "no-ui",
            )
        )
    ) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        assert all(
            d["status"] == "not_imported" for d in client.get("/api/datasets").json()["datasets"]
        )
        models = client.get("/api/normality/models").json()["models"]
        assert len([m for m in models if m["parent_model_id"] is None]) == 5
        assert all(m["ready"] is False for m in models)


async def test_mcp_catalog(tmp_path):
    async with Client(create_server(Settings(data_root=tmp_path))) as client:
        tools = await client.list_tools()
        # H2 adds investigative tools; the foundation catalog tools stay available.
        assert {t.name for t in tools.tools} >= {
            "list_datasets",
            "get_dataset_summary",
            "list_normality_models",
        }
        result = await client.call_tool("list_normality_models", {})
        assert not result.is_error
        assert result.structured_content["models"][0]["ready"] is False
        result = await client.call_tool("get_dataset_summary", {"dataset_id": "../../etc/passwd"})
        assert result.is_error


async def test_mcp_stdio(tmp_path):
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "hestia.mcp.server"],
        env={**os.environ, "HESTIA_DATA_ROOT": str(tmp_path)},
    )
    async with Client(server) as client:
        result = await client.call_tool("list_datasets", {})
        assert not result.is_error
        assert len(result.structured_content["datasets"]) == 3


def seed_sources(root):
    for relative in [
        "ait-lds-v2.0/full/gather/host/logs/auth.log",
        "cam-lds/manifestations_filtered/steps/s1/logs/auth.log",
        "loghub-openssh/OpenSSH_2k.log",
    ]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic log\n")


def test_import_is_independent_idempotent_and_detects_corruption(tmp_path):
    source, destination = tmp_path / "source", tmp_path / "data"
    seed_sources(source)
    first = import_datasets(source, destination)
    assert import_datasets(source, destination) == first
    assert all(d["status"] == "available" for d in list_datasets(destination))
    copied = destination / "raw" / first[0].files[0].path
    copied.write_text("changed")
    assert list_datasets(destination)[0]["status"] == "incomplete"
    with pytest.raises(ValueError, match="Conflicting"):
        import_datasets(source, destination)


def test_jsonl_annotations_and_unknown_normality(tmp_path):
    path = tmp_path / "labels"
    path.write_text('{"line": 2, "labels": ["escalate"]}\n')
    labels = load_aitlds_labels(path, expected_source="ait/host/auth.log")
    assert labels[("ait/host/auth.log", 2)].attack
    event = parse_line(
        raw_line="May 30 08:41:22 host sshd[2]: Accepted password for alice from 192.0.2.1 port 22 ssh2",
        source="ait/host/auth.log",
        line_no=1,
        default_year=2022,
    )
    assert select_normal_pool([event], labels) == []
    assert select_normal_pool([event], labels, complete_sources=frozenset([event.source])) == [
        event
    ]


def test_sessions_do_not_merge_sources_or_hosts():
    event = parse_line(
        raw_line="May 30 08:41:22 host sshd[2]: Accepted password for alice from 192.0.2.1 port 22 ssh2",
        source="one",
        line_no=1,
        default_year=2022,
    )
    events = [
        event,
        event.model_copy(update={"source": "two", "event_id": "two:1"}),
        event.model_copy(update={"host": "other", "event_id": "one:2"}),
    ]
    sessions, unmatched = sessionize_events(events, gap_seconds=300)
    assert len(sessions) == 3
    assert len({s.session_id for s in sessions}) == 3
    assert not unmatched
    with pytest.raises(SessionizeError):
        sessionize_events(events, fit_on=[event])
