"""Drive the Hestia MCP server over a real stdio client and print what it returns.

This is the acceptance check a human can re-run: it spawns `hestia mcp` as a
subprocess, lists the registered tools and calls every one of them against
whatever local evidence and reference material the deployment actually has.
Unavailable results are printed as-is; they are a valid outcome, not a failure.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]


def _brief(payload: dict[str, Any] | None, keys: tuple[str, ...]) -> dict[str, Any]:
    if payload is None:
        return {}
    return {key: payload.get(key) for key in keys if key in payload}


async def smoke(data_root: Path, artifact_root: Path) -> int:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "hestia.mcp.server"],
        env={
            **os.environ,
            "HESTIA_DATA_ROOT": str(data_root),
            "HESTIA_ARTIFACT_ROOT": str(artifact_root),
        },
    )
    report: list[dict[str, Any]] = []
    async with Client(parameters) as client:
        listed = await client.list_tools()
        names = sorted(tool.name for tool in listed.tools)
        print(json.dumps({"tools": names}, indent=2))
        read_only = {
            tool.name: bool(tool.annotations and tool.annotations.read_only_hint)
            for tool in listed.tools
        }
        if not all(read_only.values()):
            print(json.dumps({"error": "a tool is not annotated read-only", **read_only}))
            return 1

        datasets = await client.call_tool("list_datasets", {})
        report.append({"tool": "list_datasets", "is_error": datasets.is_error})
        models = await client.call_tool("list_normality_models", {})
        ready = [m["model_id"] for m in models.structured_content["models"] if m["ready"]]
        report.append({"tool": "list_normality_models", "ready_models": ready})
        for dataset in datasets.structured_content["datasets"]:
            summary = await client.call_tool(
                "get_dataset_summary", {"dataset_id": dataset["dataset_id"]}
            )
            report.append(
                {
                    "tool": "get_dataset_summary",
                    "dataset_id": dataset["dataset_id"],
                    "status": summary.structured_content.get("status"),
                }
            )

        found = await client.call_tool("search_events", {"query": "session opened", "limit": 1})
        report.append(
            {
                "tool": "search_events",
                **_brief(found.structured_content, ("available", "returned", "unavailable_reason")),
            }
        )
        session_id = None
        event_id = None
        items = (found.structured_content or {}).get("items") or []
        if items:
            event_id = items[0]["event_id"]
            single = await client.call_tool("get_event", {"event_id": event_id})
            report.append(
                {
                    "tool": "get_event",
                    **_brief(single.structured_content, ("available", "unavailable_reason")),
                }
            )
            host = items[0]["host"]
            history = await client.call_tool(
                "get_entity_history",
                {
                    "entity_type": "host",
                    "entity_id": host,
                    "before": items[0]["timestamp"],
                    "limit": 2,
                },
            )
            report.append(
                {
                    "tool": "get_entity_history",
                    **_brief(
                        history.structured_content,
                        ("available", "entity_session_count", "store_session_denominator"),
                    ),
                }
            )
            observations = (history.structured_content or {}).get("items") or []
            if observations:
                session_id = observations[0]["session_id"]

        if session_id is not None:
            session = await client.call_tool("get_session", {"session_id": session_id})
            report.append(
                {
                    "tool": "get_session",
                    **_brief(session.structured_content, ("available", "unavailable_reason")),
                }
            )
            events = await client.call_tool("get_events", {"session_id": session_id, "limit": 1})
            report.append(
                {
                    "tool": "get_events",
                    **_brief(
                        events.structured_content,
                        ("available", "returned", "next_cursor"),
                    ),
                }
            )
            normality = await client.call_tool("get_normality_context", {"session_id": session_id})
            report.append(
                {
                    "tool": "get_normality_context",
                    **_brief(
                        normality.structured_content,
                        ("available", "scores_available", "historical_session_count"),
                    ),
                    "training_reason": (normality.structured_content or {})
                    .get("training_provenance", {})
                    .get("reason"),
                }
            )
        else:
            report.append({"tool": "get_session", "skipped": "no prepared session was found"})

        reference = await client.call_tool(
            "search_attack_patterns", {"query": "ssh password guessing", "limit": 2}
        )
        report.append(
            {
                "tool": "search_attack_patterns",
                **_brief(
                    reference.structured_content,
                    ("available", "returned", "unavailable_reason"),
                ),
                "top": [
                    item["document_id"]
                    for item in (reference.structured_content or {}).get("items", ())
                ],
            }
        )
        technique = await client.call_tool("get_technique", {"technique_id": "T1110.001"})
        report.append(
            {
                "tool": "get_technique",
                **_brief(
                    technique.structured_content,
                    ("available", "name", "snapshot_version", "unavailable_reason"),
                ),
            }
        )
        missing = await client.call_tool("get_technique", {"technique_id": "T9999"})
        report.append(
            {
                "tool": "get_technique[unknown]",
                **_brief(missing.structured_content, ("available", "unavailable_reason")),
            }
        )
        rejected = await client.call_tool("get_dataset_summary", {"dataset_id": "../../etc/passwd"})
        report.append({"tool": "get_dataset_summary[path]", "is_error": rejected.is_error})
        called = {str(entry["tool"]).split("[", 1)[0] for entry in report}
        uncalled = sorted(set(names) - called)
        # An unprepared deployment cannot reach the evidence tools. That is an
        # honest abstention, not a protocol failure, so report it as skipped.
        prepared = bool(found.structured_content.get("available"))
        report.append({"uncalled_tools" if prepared else "skipped_unprepared_tools": uncalled})

    print(json.dumps(report, indent=2))
    if uncalled and prepared:
        print(
            json.dumps({"error": "some registered tools were never called", "uncalled": uncalled})
        )
        return 1
    if not rejected.is_error:
        print(json.dumps({"error": "a path-shaped dataset id was not rejected"}))
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=ROOT / "data")
    parser.add_argument("--artifact-root", type=Path, default=ROOT / "artifacts")
    args = parser.parse_args()
    return asyncio.run(smoke(args.data_root, args.artifact_root))


if __name__ == "__main__":
    raise SystemExit(main())
