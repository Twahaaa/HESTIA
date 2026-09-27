"""Deterministic scripted analysts for demos and tests.

These are visibly labelled fixtures. They contact nothing, they are stored with
``fixture=True``, and they exist so the investigation pipeline can be exercised
and asserted on without a hosted provider and without inventing a verdict.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

Response = Callable[[Any, Any], Any]


def tool_call(name: str, arguments: dict[str, Any] | None = None) -> Response:
    """Script one tool call."""

    def respond(messages: Any, info: Any) -> Any:
        from pydantic_ai.messages import ModelResponse, ToolCallPart

        return ModelResponse(parts=[ToolCallPart(name, arguments or {})])

    return respond


def final_report(**fields: Any) -> Response:
    """Script the final structured report through the agent's output tool."""

    def respond(messages: Any, info: Any) -> Any:
        from pydantic_ai.messages import ModelResponse, ToolCallPart

        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, fields)])

    return respond


def abstain(summary: str, limitations: tuple[str, ...] = ()) -> Response:
    """Script an honest abstention."""
    return final_report(
        verdict="insufficient_evidence",
        severity="none",
        confidence=0.2,
        summary=summary,
        findings=[],
        known_or_novel="uncertain",
        technique_ids=[],
        recommended_actions=["Have an analyst review the retrieved evidence directly."],
        limitations=list(limitations),
    )


def demo_script() -> list[Response]:
    """The `--fixture-provider` demo: use the tools, then abstain honestly.

    It retrieves the case session and its events, asks for normality context,
    searches reference material, records a hypothesis, and then returns
    insufficient_evidence because this deployment has no trained behavioural
    model. That is the truthful outcome for the current data gate.
    """
    return [
        tool_call("get_case_session"),
        tool_call("get_case_events", {"limit": 10}),
        tool_call("get_normality_context"),
        tool_call("search_reference", {"query": "ssh authentication failure", "limit": 2}),
        tool_call(
            "record_hypothesis",
            {
                "claim": (
                    "The session's authentication outcome cannot be characterised as "
                    "normal or anomalous from the evidence retrieved."
                ),
                "support": ["no behavioural model is ready in this deployment"],
                "contradictions": [],
                "retained": True,
            },
        ),
        abstain(
            summary=(
                "Retrieved the case session, its events, the normality context and "
                "reference material. No behavioural model is trained in this "
                "deployment, so no anomaly score was available and the retrieved "
                "evidence alone does not support a verdict."
            ),
            limitations=(
                "No normality model is ready, so no anomaly score informed this run.",
                "Absence of a score is not evidence that the activity is normal.",
                "This run used the deterministic fixture model, not a hosted provider.",
            ),
        ),
    ]


def _latest_tool_return(messages: Any, tool_name: str) -> dict[str, Any] | None:
    """The most recent structured result the named tool returned in this run."""
    from pydantic_ai.messages import ModelRequest, ToolReturnPart

    for message in reversed(list(messages)):
        if not isinstance(message, ModelRequest):
            continue
        for part in message.parts:
            if (
                isinstance(part, ToolReturnPart)
                and part.tool_name == tool_name
                and isinstance(part.content, dict)
            ):
                return part.content
    return None


def cited_abstention() -> Response:
    """Abstain, citing only handles the earlier tool calls actually returned.

    The findings restate structured fields of the retrieved session and first
    event. Nothing here reads message text or maps any content to a verdict: the
    fixture exists to demonstrate citation handling, and it still abstains.
    """

    def respond(messages: Any, info: Any) -> Any:
        findings: list[dict[str, Any]] = []
        session_result = _latest_tool_return(messages, "get_case_session") or {}
        session = session_result.get("session") if session_result.get("available") else None
        if isinstance(session, dict) and session.get("handle"):
            findings.append(
                {
                    "statement": (
                        f"The case session holds {session.get('event_count', 0)} prepared "
                        f"events, {session.get('failure_count', 0)} of them recorded as "
                        "authentication failures."
                    ),
                    "evidence_handles": [session["handle"]],
                }
            )
        events_result = _latest_tool_return(messages, "get_case_events") or {}
        events = events_result.get("events") or []
        if events and isinstance(events[0], dict) and events[0].get("handle"):
            first = events[0]
            findings.append(
                {
                    "statement": (
                        f"The first retrieved event has type '{first.get('event_type')}' "
                        f"and success={first.get('success')} at {first.get('timestamp')}."
                    ),
                    "evidence_handles": [first["handle"]],
                }
            )
        return final_report(
            verdict="insufficient_evidence",
            severity="none",
            confidence=0.2,
            summary=(
                "Scripted fixture analyst. It retrieved the case session, its events, "
                "the normality context and reference material, restated two retrieved "
                "facts with citations, and abstained: no behavioural model is trained "
                "in this deployment and the retrieved evidence alone does not support "
                "a verdict."
            ),
            findings=findings,
            known_or_novel="uncertain",
            technique_ids=[],
            recommended_actions=["Have an analyst review the cited evidence directly."],
            limitations=[
                "This run used the deterministic fixture model, not a hosted provider.",
                "No normality model is ready, so no anomaly score informed this run.",
                "Absence of a score is not evidence that the activity is normal.",
            ],
        )(messages, info)

    return respond


def paced(script: list[Response], seconds: float) -> list[Response]:
    """Delay each scripted turn so a demo can be watched while it runs.

    The delay happens in the framework's executor thread, before the scripted
    response, and is labelled demo pacing wherever it is configured.
    """
    if seconds <= 0:
        return script

    def delayed(response: Response) -> Response:
        def respond(messages: Any, info: Any) -> Any:
            import time

            time.sleep(seconds)
            return response(messages, info)

        return respond

    return [delayed(item) for item in script]


def workspace_demo_script(pace_seconds: float = 0.0) -> list[Response]:
    """The case workspace's fixture run: same tools as the CLI demo, cited abstention."""
    script = demo_script()[:-1] + [cited_abstention()]
    return paced(script, pace_seconds)


__all__ = [
    "abstain",
    "cited_abstention",
    "demo_script",
    "final_report",
    "paced",
    "tool_call",
    "workspace_demo_script",
]
