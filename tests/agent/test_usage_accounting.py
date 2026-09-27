"""Token and request accounting covers every agent pass, including failed runs."""

from __future__ import annotations

from hestia.agent.contracts import RunState
from hestia.agent.fixtures import abstain, tool_call
from hestia.agent.runner import investigate


def _fabricated(messages, info):
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    return ModelResponse(
        parts=[
            ToolCallPart(
                info.output_tools[0].name,
                {
                    "verdict": "suspicious",
                    "severity": "medium",
                    "confidence": 0.6,
                    "summary": "Cites a handle no tool returned.",
                    "findings": [{"statement": "Invented.", "evidence_handles": ["ev-invented"]}],
                    "known_or_novel": "uncertain",
                    "technique_ids": [],
                    "recommended_actions": [],
                    "limitations": [],
                },
            )
        ]
    )


async def test_repaired_run_counts_both_passes(prepared, case):
    run = await investigate(
        prepared,
        case,
        fixture_script=[tool_call("get_case_session"), _fabricated, abstain("Repaired.")],
    )
    assert run.state is RunState.completed
    assert run.grounding is not None and run.grounding.repair_attempted
    # Two requests in the first pass, one in the repair pass.
    assert run.usage.requests == 3
    assert run.usage.total_tokens == run.usage.input_tokens + run.usage.output_tokens > 0


async def test_refused_grounding_keeps_its_usage(prepared, case):
    run = await investigate(prepared, case, fixture_script=[_fabricated, _fabricated])
    assert run.state is RunState.failed
    assert run.usage.requests == 2
    assert run.usage.input_tokens > 0


async def test_budget_failure_keeps_tokens_already_consumed(prepared, case):
    tight = prepared.model_copy(update={"agent_max_tool_calls": 2})
    run = await investigate(
        tight,
        case,
        fixture_script=[
            tool_call("get_case_session"),
            tool_call("get_case_events", {"limit": 5}),
            tool_call("get_normality_context"),
            abstain("never reached"),
        ],
    )
    assert run.state is RunState.failed
    assert run.report is None
    assert run.usage.requests >= 2
    assert run.usage.input_tokens > 0
