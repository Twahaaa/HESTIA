"""Protocol-level checks through a real MCP client, in-process and over stdio."""

from __future__ import annotations

import json
import os
import sys

from mcp import Client, StdioServerParameters

from hestia.mcp.contracts import (
    FORBIDDEN_FIELD_NAMES,
    EntityHistoryResult,
    EventPage,
    EventRecord,
    EventResult,
    NormalityContextResult,
    SessionRecord,
    SessionResult,
)
from hestia.mcp.server import create_server

EXPECTED_TOOLS = {
    "get_dataset_summary",
    "get_entity_history",
    "get_event",
    "get_events",
    "get_normality_context",
    "get_session",
    "get_technique",
    "list_datasets",
    "list_normality_models",
    "search_attack_patterns",
    "search_events",
}


def test_runtime_contracts_declare_no_evaluation_labels():
    for model in (
        EventRecord,
        SessionRecord,
        SessionResult,
        EventResult,
        EventPage,
        EntityHistoryResult,
        NormalityContextResult,
    ):
        names = {name.lower() for name in model.model_fields}
        assert not names & FORBIDDEN_FIELD_NAMES, model.__name__


async def test_every_tool_is_registered_read_only(prepared):
    async with Client(create_server(prepared)) as client:
        listed = await client.list_tools()
        assert {tool.name for tool in listed.tools} == EXPECTED_TOOLS
        for tool in listed.tools:
            assert tool.annotations is not None, tool.name
            assert tool.annotations.read_only_hint is True, tool.name
            assert tool.annotations.destructive_hint is False, tool.name
            assert tool.description, tool.name


async def test_tool_output_schemas_are_structured_and_versioned(prepared, session_id):
    async with Client(create_server(prepared)) as client:
        result = await client.call_tool("get_session", {"session_id": session_id})
        assert not result.is_error
        assert result.structured_content["schema_version"] == 1
        assert result.structured_content["request_id"]
        assert result.structured_content["session"]["source_ref"]["source_sha256"]
        payload = json.dumps(result.structured_content).lower()
        for banned in ('"label"', '"attack"', '"verdict"', '"severity"'):
            assert banned not in payload


async def test_tool_errors_are_reported_as_results_not_crashes(prepared):
    async with Client(create_server(prepared)) as client:
        rejected = await client.call_tool("get_dataset_summary", {"dataset_id": "../../etc/passwd"})
        assert rejected.is_error
        naive = await client.call_tool(
            "get_entity_history",
            {"entity_type": "host", "entity_id": "fixture-host", "before": "2025-01-01 00:00:00"},
        )
        assert naive.is_error
        assert "timezone" in naive.content[0].text
        unknown = await client.call_tool("get_session", {"session_id": "fixture/auth.log:absent"})
        assert not unknown.is_error
        assert unknown.structured_content["available"] is False


async def test_unready_and_unavailable_results_are_consumable(prepared, session_id):
    async with Client(create_server(prepared)) as client:
        normality = await client.call_tool("get_normality_context", {"session_id": session_id})
        payload = normality.structured_content
        assert payload["available"] is True
        assert payload["scores_available"] is False
        assert all(model["ready"] is False for model in payload["models"])
        assert payload["training_provenance"]["ready"] is False

        reference = await client.call_tool("search_attack_patterns", {"query": "ssh"})
        assert reference.structured_content["available"] is False
        assert "knowledge-build" in reference.structured_content["unavailable_reason"]


async def test_live_stdio_client_calls_every_registered_tool(prepared, session_id, capfd):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "hestia.mcp.server"],
        env={
            **os.environ,
            "HESTIA_DATA_ROOT": str(prepared.data_root),
            "HESTIA_ARTIFACT_ROOT": str(prepared.artifact_root),
        },
    )
    async with Client(parameters) as client:
        listed = await client.list_tools()
        assert {tool.name for tool in listed.tools} == EXPECTED_TOOLS

        events = await client.call_tool("get_events", {"session_id": session_id, "limit": 1})
        event_id = events.structured_content["items"][0]["event_id"]
        timestamp = events.structured_content["items"][0]["timestamp"]
        calls = {
            "list_datasets": {},
            "list_normality_models": {},
            "get_dataset_summary": {"dataset_id": "ait-auth"},
            "get_session": {"session_id": session_id},
            "get_events": {"session_id": session_id, "limit": 2},
            "get_event": {"event_id": event_id},
            "search_events": {"query": "Accepted", "limit": 2},
            "get_entity_history": {
                "entity_type": "host",
                "entity_id": "fixture-host",
                "before": timestamp,
            },
            "get_normality_context": {"session_id": session_id},
            "search_attack_patterns": {"query": "password"},
            "get_technique": {"technique_id": "T1110.001"},
        }
        assert set(calls) == EXPECTED_TOOLS
        for name, arguments in calls.items():
            result = await client.call_tool(name, arguments)
            assert not result.is_error, (name, result.content)
            assert result.structured_content is not None, name

    captured = capfd.readouterr()
    assert "jsonrpc" not in captured.err
