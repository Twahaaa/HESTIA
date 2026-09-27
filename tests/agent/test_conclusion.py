"""Budget-aware conclusion: the agent is told its turn budget and must report in time."""

from __future__ import annotations

from hestia.agent.contracts import RunState, Verdict
from hestia.agent.fixtures import abstain
from hestia.agent.runner import CONCLUDING_NOTE, instructions_digest, investigate


def _instructions(messages) -> str:
    return messages[-1].instructions or ""


def endless_searcher(seen: list[tuple[str, list[str]]]):
    """Calls an evidence tool whenever one is offered; abstains only when forced."""

    def respond(messages, info):
        from pydantic_ai.messages import ModelResponse, ToolCallPart

        tools = [tool.name for tool in info.function_tools]
        seen.append((_instructions(messages), tools))
        if tools:
            return ModelResponse(parts=[ToolCallPart("get_case_events", {"limit": 2})])
        return abstain("Tools were withdrawn; the evidence gathered does not decide it.")(
            messages, info
        )

    return respond


async def test_a_model_that_never_stops_searching_still_reports(prepared, case):
    settings = prepared.model_copy(update={"agent_max_turns": 6, "agent_max_tool_calls": 10})
    seen: list[tuple[str, list[str]]] = []
    responder = endless_searcher(seen)
    run = await investigate(settings, case, fixture_script=[responder] * 6)
    assert run.state is RunState.completed
    assert run.report is not None and run.report.verdict is Verdict.insufficient_evidence
    # 6 turns - 2 reserved - 1 = 3 gathering requests, then a forced conclusion.
    assert [bool(tools) for _, tools in seen] == [True, True, True, False]
    assert [trace.tool for trace in run.traces] == ["get_events"] * 3
    assert "3 model turn(s) remain" in seen[0][0]
    assert "1 model turn(s) remain" in seen[2][0]
    assert CONCLUDING_NOTE in seen[3][0]
    assert "insufficient_evidence" in CONCLUDING_NOTE


async def test_tool_call_ceiling_triggers_conclusion_instead_of_failure(prepared, case):
    settings = prepared.model_copy(update={"agent_max_turns": 12, "agent_max_tool_calls": 2})
    seen: list[tuple[str, list[str]]] = []
    run = await investigate(settings, case, fixture_script=[endless_searcher(seen)] * 12)
    assert run.state is RunState.completed
    assert len(run.traces) == 2
    assert [bool(tools) for _, tools in seen] == [True, True, False]


async def test_citation_repair_runs_without_evidence_tools(prepared, case):
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    offered: list[list[str]] = []

    def fabricate(messages, info):
        offered.append([tool.name for tool in info.function_tools])
        return ModelResponse(
            parts=[
                ToolCallPart(
                    info.output_tools[0].name,
                    {
                        "verdict": "suspicious",
                        "severity": "medium",
                        "confidence": 0.5,
                        "summary": "Cites a handle no tool returned.",
                        "findings": [{"statement": "x", "evidence_handles": ["ev-invented"]}],
                        "known_or_novel": "uncertain",
                        "technique_ids": [],
                        "recommended_actions": [],
                        "limitations": [],
                    },
                )
            ]
        )

    def repair(messages, info):
        offered.append([tool.name for tool in info.function_tools])
        assert CONCLUDING_NOTE in _instructions(messages)
        return abstain("Repaired by abstaining.")(messages, info)

    run = await investigate(prepared, case, fixture_script=[fabricate, repair])
    assert run.state is RunState.completed
    assert run.grounding is not None and run.grounding.repair_attempted
    assert offered[0] and offered[1] == []


def test_instructions_digest_identifies_the_prompt():
    digest = instructions_digest()
    assert len(digest) == 64 and digest == instructions_digest()
