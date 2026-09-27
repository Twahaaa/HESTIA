"""Context compaction keeps requests under a per-request ceiling without losing citations."""

from __future__ import annotations

import pytest
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)

from hestia.agent.compaction import compact_history, estimate_tokens
from hestia.agent.contracts import RunState
from hestia.agent.fixtures import final_report
from hestia.agent.runner import investigate
from hestia.config import Settings


def _round(call_id: str, handles: list[str], filler: int) -> list:
    return [
        ModelResponse(
            parts=[
                ThinkingPart(content="deliberating " * 50),
                ToolCallPart("get_case_events", {"limit": 5}, tool_call_id=call_id),
            ]
        ),
        ModelRequest(
            parts=[
                ToolReturnPart(
                    "get_case_events",
                    {
                        "available": True,
                        "events": [{"handle": h, "message": "x" * filler} for h in handles],
                    },
                    tool_call_id=call_id,
                )
            ]
        ),
    ]


def _history() -> list:
    messages: list = [ModelRequest(parts=[UserPromptPart("brief")])]
    for index in range(4):
        messages += _round(f"c{index}", [f"ev-{index}a", f"ev-{index}b"], 1_500)
    return messages


def test_small_histories_are_untouched():
    history = _history()
    assert compact_history(history, 1_000_000) is history


def test_oldest_results_condense_to_handles_and_pairing_survives():
    history = _history()
    before = estimate_tokens(history)
    target = int(before * 0.6)  # reachable once the two older results are condensed
    compacted = compact_history(history, target)
    assert estimate_tokens(compacted) <= target
    returns = [
        part
        for message in compacted
        if isinstance(message, ModelRequest)
        for part in message.parts
        if isinstance(part, ToolReturnPart)
    ]
    assert [part.tool_call_id for part in returns] == ["c0", "c1", "c2", "c3"]
    assert returns[0].content["compacted"] is True
    assert returns[0].content["handles"] == ["ev-0a", "ev-0b"]
    # The two most recent requests are never condensed.
    assert "events" in returns[-1].content and "events" in returns[-2].content
    # Older reasoning is dropped; the newest response keeps its parts.
    responses = [message for message in compacted if isinstance(message, ModelResponse)]
    assert not any(isinstance(p, ThinkingPart) for r in responses[:-1] for p in r.parts)
    assert any(isinstance(p, ThinkingPart) for p in responses[-1].parts)
    # The original list is not mutated.
    assert "events" in history[2].parts[0].content


def test_an_unreachable_budget_condenses_everything_it_may_and_stops():
    history = _history() + [ModelResponse(parts=[TextPart("done")])]
    compacted = compact_history(history, 1_000)
    returns = [
        part
        for message in compacted
        if isinstance(message, ModelRequest)
        for part in message.parts
        if isinstance(part, ToolReturnPart)
    ]
    assert [part.content.get("compacted", False) for part in returns] == [True, True, False, False]


def test_settings_reject_a_tiny_context_budget():
    with pytest.raises(ValueError, match="at least 1000"):
        Settings(_env_file=None, agent_context_token_budget=10)  # type: ignore[call-arg]


async def test_a_condensed_handle_remains_citable(prepared, case):
    settings = prepared.model_copy(
        update={"agent_context_token_budget": 1_000, "agent_max_turns": 12}
    )
    first_handles: list[str] = []

    def report_citing_the_oldest(messages, info):
        for message in messages:
            for part in getattr(message, "parts", ()):
                if isinstance(part, ToolReturnPart) and isinstance(part.content, dict):
                    if part.content.get("compacted"):
                        first_handles.extend(part.content["handles"])
                        return final_report(
                            verdict="insufficient_evidence",
                            severity="none",
                            confidence=0.2,
                            summary="Cites an event whose result was condensed.",
                            findings=[
                                {
                                    "statement": "An early event was retrieved.",
                                    "evidence_handles": [part.content["handles"][0]],
                                }
                            ],
                            known_or_novel="uncertain",
                        )(messages, info)
        raise AssertionError("no tool result was condensed")

    def events(messages, info):
        return ModelResponse(parts=[ToolCallPart("get_case_events", {"limit": 20})])

    run = await investigate(
        settings, case, fixture_script=[events, events, events, report_citing_the_oldest]
    )
    assert run.state is RunState.completed, run.incomplete_reason
    assert run.grounding is not None and run.grounding.grounded
    assert first_handles and run.usage.compacted_tool_results >= 1
