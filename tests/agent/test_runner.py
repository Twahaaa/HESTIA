"""End-to-end runner behaviour, driven by deterministic scripted analysts."""

from __future__ import annotations

import json
import os

import pytest

from hestia.agent.contracts import Coverage, RunState, Severity, Verdict
from hestia.agent.fixtures import abstain, final_report, tool_call
from hestia.agent.runner import investigate
from hestia.store.repository import EvidenceRepository


async def test_agent_uses_real_mcp_tools_and_records_a_trace(prepared, case):
    run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_case_session"),
            tool_call("get_case_events", {"limit": 5}),
            abstain("Retrieved the case and abstained."),
        ],
    )
    assert run.state is RunState.completed
    assert run.fixture is True
    assert [trace.tool for trace in run.traces] == ["get_session", "get_events"]
    assert all(trace.available for trace in run.traces)
    assert run.traces[1].returned >= 1
    assert run.usage.tool_calls == 2
    assert run.usage.requests >= 1


async def test_different_evidence_leads_to_different_tool_choices(prepared, case):
    """The scripted analysts differ, so the recorded traces must differ too."""
    history_run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_case_session"),
            tool_call("get_entity_history", {"entity_type": "host", "entity_id": "host-1"}),
            abstain("Checked prior host activity."),
        ],
    )
    reference_run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_case_session"),
            tool_call("search_reference", {"query": "password guessing", "limit": 2}),
            abstain("Checked reference material."),
        ],
    )
    assert [t.tool for t in history_run.traces] == ["get_session", "get_entity_history"]
    assert [t.tool for t in reference_run.traces] == ["get_session", "search_attack_patterns"]
    assert history_run.traces[1].available is True


async def test_history_is_bounded_by_the_case_boundary(prepared, case):
    run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_case_session"),
            tool_call("get_entity_history", {"entity_type": "host", "entity_id": "host-1"}),
            abstain("Bounded history."),
        ],
    )
    history = run.traces[1]
    assert history.arguments["before"] == case.history_before.isoformat()


async def test_pseudonyms_are_required_for_entity_filters(prepared, case):
    run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_entity_history", {"entity_type": "host", "entity_id": "fixture-host"}),
            abstain("Refused a raw identifier."),
        ],
    )
    # The raw host name is not a pseudonym this run issued, so no MCP call happened.
    assert run.state is RunState.completed
    assert run.traces == ()


async def test_the_agent_can_revise_a_hypothesis(prepared, case):
    run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_case_session"),
            tool_call(
                "record_hypothesis",
                {"claim": "This is a successful brute force.", "support": ["failures seen"]},
            ),
            tool_call("get_case_events", {"limit": 5}),
            tool_call(
                "record_hypothesis",
                {
                    "claim": "The failures are unexplained but not proven hostile.",
                    "contradictions": ["no successful authentication followed in this session"],
                    "retained": True,
                },
            ),
            abstain("Revised the hypothesis after reading the events."),
        ],
    )
    assert run.state is RunState.completed
    assert len(run.hypotheses) == 2
    assert run.hypotheses[0].claim != run.hypotheses[1].claim
    assert run.hypotheses[1].contradictions


async def test_abstention_when_evidence_is_missing(prepared, case):
    """A session that does not exist yields an unavailable tool result, not a verdict."""
    missing = case.model_copy(update={"session_id": "fixture/auth.log:absent"})
    run = await investigate(
        prepared,
        missing,
        fixture_script=[
            tool_call("get_case_session"),
            abstain("The case session could not be retrieved."),
        ],
    )
    assert run.state is RunState.completed
    assert run.report is not None
    assert run.report.verdict is Verdict.insufficient_evidence
    assert run.report.severity is Severity.none
    assert run.traces[0].available is False
    assert "no prepared session" in (run.traces[0].unavailable_reason or "")


async def test_normality_context_is_reported_as_not_ready(prepared, case):
    run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_normality_context"),
            abstain("No model is ready."),
        ],
    )
    assert run.state is RunState.completed
    assert run.traces[0].tool == "get_normality_context"


async def test_cancellation_ends_the_run_without_a_report(prepared, case):
    run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_case_session"),
            tool_call("get_case_events", {"limit": 5}),
            abstain("never reached"),
        ],
        cancel_after_tool_calls=1,
    )
    assert run.state is RunState.cancelled
    assert run.report is None
    assert "cancelled" in (run.incomplete_reason or "")


async def test_tool_call_budget_ends_the_run_as_incomplete(prepared, case):
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
    assert "budget" in (run.incomplete_reason or "").lower()


async def test_token_budget_ends_the_run_as_incomplete(prepared, case):
    tiny = prepared.model_copy(update={"agent_max_total_tokens": 1})
    run = await investigate(
        tiny, case, fixture_script=[tool_call("get_case_session"), abstain("never reached")]
    )
    assert run.state is RunState.failed
    assert run.report is None
    assert "budget" in (run.incomplete_reason or "").lower()


async def test_repeated_identical_tool_calls_stay_bounded(prepared, case):
    """A model that loops on one tool is stopped by the ceiling, not by luck."""
    bounded = prepared.model_copy(update={"agent_max_tool_calls": 3})
    run = await investigate(
        bounded,
        case,
        fixture_script=[tool_call("get_case_session") for _ in range(6)],
    )
    assert run.state is RunState.failed
    assert len(run.traces) <= 3


async def test_malformed_model_output_never_becomes_a_report(prepared, case):
    def broken(messages, info):
        from pydantic_ai.messages import ModelResponse, ToolCallPart

        return ModelResponse(
            parts=[ToolCallPart(info.output_tools[0].name, {"verdict": "definitely-bad"})]
        )

    run = await investigate(
        prepared.model_copy(update={"agent_max_retries": 1}),
        case,
        fixture_script=[broken, broken, broken, broken],
    )
    assert run.state is RunState.failed
    assert run.report is None
    assert run.incomplete_reason


async def test_provider_http_failure_ends_as_incomplete(prepared, case):
    def rate_limited(messages, info):
        from pydantic_ai.exceptions import ModelHTTPError

        raise ModelHTTPError(status_code=429, model_name="fixture-analyst", body="slow down")

    run = await investigate(prepared, case, fixture_script=[rate_limited])
    assert run.state is RunState.failed
    assert run.report is None
    assert "429" in (run.incomplete_reason or "") or "ModelHTTPError" in (
        run.incomplete_reason or ""
    )


async def test_unconfigured_provider_fails_with_an_actionable_reason(prepared, case):
    unconfigured = prepared.model_copy(update={"agent_provider": None})
    run = await investigate(unconfigured, case)
    assert run.state is RunState.failed
    assert run.report is None
    assert "HESTIA_AGENT_PROVIDER" in (run.incomplete_reason or "")


def _serialize(messages) -> str:
    """Serialize the real conversation the model was handed, for leak assertions."""
    from pydantic_ai.messages import ModelMessagesTypeAdapter

    return ModelMessagesTypeAdapter.dump_json(messages).decode()


def _abstain_parts(info, summary: str, findings=()):
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    return ModelResponse(
        parts=[
            ToolCallPart(
                info.output_tools[0].name,
                {
                    "verdict": "insufficient_evidence",
                    "severity": "none",
                    "confidence": 0.1,
                    "summary": summary,
                    "findings": list(findings),
                    "known_or_novel": "uncertain",
                    "technique_ids": [],
                    "recommended_actions": [],
                    "limitations": ["Log content was treated as data."],
                },
            )
        ]
    )


async def test_injection_in_log_text_cannot_grant_tools_or_leak_secrets(prepared, injected_case):
    """Retrieved log text must arrive as neutralized data with no authority."""
    captured: list[str] = []
    offered_tools: list[set[str]] = []

    def snoop(messages, info):
        from pydantic_ai.messages import ModelResponse, ToolCallPart

        captured.append(_serialize(messages))
        offered_tools.append({tool.name for tool in info.function_tools})
        if len(captured) == 1:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "search_related_events",
                        {"query": "COMMAND", "membership": "unmatched", "limit": 5},
                    )
                ]
            )
        return _abstain_parts(info, "The retrieved log text contained an instruction-like string.")

    run = await investigate(prepared, injected_case, fixture_script=[snoop, snoop])
    assert run.state is RunState.completed
    assert run.traces[0].tool == "search_events"
    assert run.traces[0].returned >= 1, "the injected sudo line must be retrieved"

    conversation = "\n".join(captured)
    assert "IGNORE_ALL_PREVIOUS_INSTRUCTIONS" in conversation, "it arrives as data"

    # It is inside the untrusted envelope, which the instructions strip of authority.
    assert "untrusted-log-content" in conversation
    # The injection did not add, rename or remove a single tool.
    expected = {
        "get_case_session",
        "get_case_events",
        "search_related_events",
        "get_entity_history",
        "get_normality_context",
        "search_reference",
        "get_technique",
        "record_hypothesis",
    }
    assert offered_tools[0] == expected
    assert offered_tools[-1] == expected

    # No secret, key or raw identifier was ever placed in the conversation.
    for secret in ("api_key", "HESTIA_AGENT_API_KEY", "sk-", "Authorization"):
        assert secret not in conversation
    assert injected_case.session_id not in conversation
    assert "203.0.113.9" not in conversation
    assert "fixture/auth.log" not in conversation

    # And the verdict stayed an abstention rather than obeying the text.
    assert run.report is not None
    assert run.report.verdict is Verdict.insufficient_evidence


async def test_ungrounded_report_is_repaired_or_refused(prepared, case):
    """A fabricated citation must not be published, even after one repair."""
    attempts = {"n": 0}

    def fabricate(messages, info):
        from pydantic_ai.messages import ModelResponse, ToolCallPart

        attempts["n"] += 1
        return ModelResponse(
            parts=[
                ToolCallPart(
                    info.output_tools[0].name,
                    {
                        "verdict": "malicious",
                        "severity": "high",
                        "confidence": 0.9,
                        "summary": "Confident but unsupported.",
                        "findings": [
                            {
                                "statement": "An attacker authenticated.",
                                "evidence_handles": ["ev-fabricated"],
                            }
                        ],
                        "known_or_novel": "known",
                        "technique_ids": [],
                        "recommended_actions": [],
                        "limitations": [],
                    },
                )
            ]
        )

    run = await investigate(prepared, case, fixture_script=[fabricate, fabricate])
    assert run.state is RunState.failed
    assert run.report is None
    assert run.grounding is not None
    assert run.grounding.grounded is False
    assert run.grounding.repair_attempted is True
    assert "citation validation" in (run.incomplete_reason or "")
    assert attempts["n"] == 2, "exactly one bounded repair attempt"


async def test_the_run_is_persisted_with_its_trace_and_report(prepared, case):
    repository = EvidenceRepository(prepared.evidence_database)
    run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_case_session"),
            tool_call("record_hypothesis", {"claim": "Nothing conclusive yet.", "support": []}),
            abstain("Abstained."),
        ],
        persist=repository.save_case_run,
    )
    stored = repository.read_case_run(run.run_id)
    assert stored is not None
    assert stored["state"] == "completed"
    assert stored["fixture"] == 1
    kinds = sorted({step["kind"] for step in stored["steps"]})
    assert kinds == ["hypothesis", "tool_call"]
    assert json.loads(str(stored["report_json"]))["verdict"] == "insufficient_evidence"
    assert stored["grounded"] == 1
    summary = repository.case_run_summary()
    assert summary["total"] >= 1


async def test_a_failed_run_is_persisted_without_a_report(prepared, case):
    repository = EvidenceRepository(prepared.evidence_database)
    run = await investigate(
        prepared.model_copy(update={"agent_max_tool_calls": 1}),
        case,
        fixture_script=[
            tool_call("get_case_session"),
            tool_call("get_case_events"),
            abstain("never reached"),
        ],
        persist=repository.save_case_run,
    )
    stored = repository.read_case_run(run.run_id)
    assert stored is not None
    assert stored["state"] == "failed"
    assert stored["report_json"] is None
    assert stored["incomplete_reason"]


async def test_investigation_does_not_change_model_state(prepared, case):
    """Running a case must not train, calibrate or otherwise touch normality state."""
    from hestia.normality.catalog import list_models

    before = list_models(prepared.artifact_root)
    normality_dir = prepared.artifact_root / "normality"
    files_before = sorted(p.name for p in normality_dir.glob("*")) if normality_dir.is_dir() else []

    await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_normality_context"),
            tool_call("get_case_events", {"limit": 5}),
            abstain("Abstained."),
        ],
    )

    after = list_models(prepared.artifact_root)
    files_after = sorted(p.name for p in normality_dir.glob("*")) if normality_dir.is_dir() else []
    assert before == after
    assert files_before == files_after
    assert all(model["ready"] is False for model in after)


async def test_report_coverage_wording_is_available(prepared, case):
    run = await investigate(
        prepared,
        case,
        fixture_script=[
            tool_call("get_case_session"),
            final_report(
                verdict="insufficient_evidence",
                severity="none",
                confidence=0.3,
                summary="Reference coverage was limited.",
                findings=[],
                known_or_novel="potentially_novel",
                technique_ids=[],
                recommended_actions=[],
                limitations=["Local reference coverage is partial."],
            ),
        ],
    )
    assert run.report is not None
    assert run.report.known_or_novel is Coverage.potentially_novel


@pytest.mark.skipif(
    not os.environ.get("HESTIA_AGENT_API_KEY"),
    reason="no hosted provider credentials are configured; hosted acceptance is unverified",
)
async def test_live_hosted_smoke(prepared, case):  # pragma: no cover - opt-in only
    """Opt-in hosted smoke. Skipped is reported as not run, never as a pass."""
    from hestia.config import AgentProvider, Settings

    live = Settings(
        data_root=prepared.data_root,
        artifact_root=prepared.artifact_root,
        frontend_dist=prepared.frontend_dist,
        agent_provider=AgentProvider(os.environ["HESTIA_AGENT_PROVIDER"]),
        agent_model=os.environ["HESTIA_AGENT_MODEL"],
        agent_max_tool_calls=6,
        agent_max_turns=8,
    )
    run = await investigate(live, case)
    assert run.fixture is False
    assert run.state in {RunState.completed, RunState.failed}
    if run.state is RunState.completed:
        assert run.grounding is not None and run.grounding.grounded
        assert run.usage.total_tokens > 0
