"""Agent evaluation harness: label boundary, stratified selection, gating, metrics.

Every store here is synthetic. No test contacts a provider: hosted paths are
exercised with refusals and a stand-in investigator that returns stored records.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from hestia.agent.contracts import (
    CaseRun,
    Finding,
    GroundingIssue,
    GroundingResult,
    Report,
    RunState,
    ToolTrace,
    Usage,
)
from hestia.config import AgentProvider, Settings
from hestia.datasets.profiles import DatasetProfile
from hestia.evaluation import agent_eval
from hestia.evaluation.agent_eval import (
    MASKED_DATASET,
    AgentEvalConfig,
    HostedPlan,
    HostedRefused,
    case_input,
    hosted_settings,
    measure,
    plan,
    run_agent_evaluation,
    select_cases,
)
from hestia.ingestion.collector import collect_source
from hestia.ingestion.sessionization import sessionize_events
from hestia.store.repository import EvidenceRepository

LOG = """\
Jan  2 03:04:05 host-a sshd[11]: Failed password for invalid user alice from 198.51.100.7 port 2201 ssh2
Jan  2 03:04:09 host-a sshd[11]: Accepted password for alice from 198.51.100.7 port 2201 ssh2
Jan  3 09:00:00 host-a sshd[13]: Accepted password for bob from 203.0.113.9 port 2203 ssh2
Jan  4 11:22:33 host-a sshd[14]: Accepted password for carol from 192.0.2.4 port 2204 ssh2
"""
#: Deliberately label-like, so a leak into the provider payload is detectable.
PROXY_DATASET = "attack-captures"
SOURCES = (
    ("benign-captures", "benign-captures/auth.log"),
    (PROXY_DATASET, "attack-captures/auth.log"),
)
INDEXED = ("attack-captures", "attack-captures/indexed.log")


def _import(repository: EvidenceRepository, tmp_path: Path, dataset: str, path: str) -> None:
    source = tmp_path / path.replace("/", "_")
    source.write_text(LOG, encoding="utf-8")
    collection = collect_source(
        source,
        DatasetProfile(
            dataset_id=dataset,
            source_path=path,
            default_year=2025,
            timezone="UTC",
            timezone_provenance="synthetic fixture",
            timestamp_uncertainty="none",
            annotation_coverage="none",
        ),
    )
    events = [item.event for item in collection.events]
    sessions, unmatched = sessionize_events(events, gap_seconds=300)
    repository.import_source(
        collection, sessions, ((event, "missing user or source IP") for event in unmatched)
    )


@pytest.fixture
def workspace(tmp_path: Path) -> dict[str, object]:
    settings = Settings(
        data_root=tmp_path / "data",
        artifact_root=tmp_path / "artifacts",
        frontend_dist=tmp_path / "no-ui",
    )
    repository = EvidenceRepository(settings.evidence_database)
    repository.initialize()
    for dataset, path in (*SOURCES, INDEXED):
        _import(repository, tmp_path, dataset, path)
    index = tmp_path / "index.json"
    index.write_text(json.dumps({"documents": [{"source": {"source_uri": INDEXED[1]}}]}))
    config_path = tmp_path / "agent.json"
    config = {
        "schema_version": 1,
        "datasets": [dataset for dataset, _ in SOURCES],
        "per_dataset": 2,
        "seed": 7,
        "reference_index_path": "index.json",
        "labels_path": None,
        "budget": {"max_turns": 8, "max_tool_calls": 10, "max_total_tokens": 50_000},
        "hosted": {
            "provider": "groq",
            "model": "approved-model",
            "max_requests": 100,
            "max_total_tokens": 1_000_000,
            "price_input_per_million_usd": 1.0,
            "price_output_per_million_usd": 2.0,
            "price_source": "synthetic",
        },
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return {"settings": settings, "config_path": config_path, "index": index, "config": config}


def _config(workspace) -> AgentEvalConfig:
    return AgentEvalConfig.model_validate(workspace["config"])


def test_selection_is_deterministic_stratified_and_excludes_indexed_sources(workspace):
    settings: Settings = workspace["settings"]
    first = select_cases(_config(workspace), settings.evidence_database, workspace["index"])
    again = select_cases(_config(workspace), settings.evidence_database, workspace["index"])
    assert first == again
    assert [case.dataset_id for case in first] == [
        "benign-captures",
        PROXY_DATASET,
        "benign-captures",
        PROXY_DATASET,
    ]
    assert not any("indexed.log" in case.session_id for case in first)
    reseeded = _config(workspace).model_copy(update={"seed": 8})
    assert {
        c.session_id for c in select_cases(reseeded, settings.evidence_database, workspace["index"])
    } <= {
        c.session_id
        for c in select_cases(
            _config(workspace).model_copy(update={"per_dataset": 3}),
            settings.evidence_database,
            workspace["index"],
        )
    }


def test_too_few_eligible_sessions_refuses(workspace):
    settings: Settings = workspace["settings"]
    greedy = _config(workspace).model_copy(update={"per_dataset": 4})
    with pytest.raises(ValueError, match="eligible sessions"):
        select_cases(greedy, settings.evidence_database, workspace["index"])


def test_case_brief_masks_the_dataset_and_nothing_label_like_reaches_the_model(workspace):
    from hestia.agent.fixtures import workspace_demo_script
    from hestia.agent.runner import investigate

    settings: Settings = workspace["settings"]
    cases = select_cases(_config(workspace), settings.evidence_database, workspace["index"])
    proxy = next(case for case in cases if case.dataset_id == PROXY_DATASET)
    assert case_input(proxy).dataset_id == MASKED_DATASET
    seen: list[str] = []

    def capture(response):
        def respond(messages, info):
            from pydantic_ai.messages import ModelMessagesTypeAdapter

            seen.append(ModelMessagesTypeAdapter.dump_json(messages).decode())
            return response(messages, info)

        return respond

    import asyncio

    fixture = settings.model_copy(
        update={"agent_provider": AgentProvider.fixture, "agent_model": "fixture-analyst"}
    )
    run = asyncio.run(
        investigate(
            fixture,
            case_input(proxy),
            fixture_script=[capture(item) for item in workspace_demo_script()],
        )
    )
    assert run.state is RunState.completed
    outbound = "\n".join(seen)
    assert MASKED_DATASET in outbound
    assert PROXY_DATASET not in outbound
    assert "ground_truth" not in outbound and '"label' not in outbound


def test_fixture_evaluation_is_mechanics_only_and_immutable(workspace):
    settings: Settings = workspace["settings"]
    result = run_agent_evaluation(
        workspace["config_path"],
        mode="fixture",
        output_root=settings.artifact_root / "evaluation",
        settings_factory=lambda: settings,
    )
    assert result["kind"] == "fixture_mechanics_only"
    assert result["accuracy_claim_allowed"] is False
    assert result["correctness"]["measurable"] is False
    metrics = result["metrics"]
    assert metrics["cases_run"] == 4
    assert metrics["outcomes"]["abstention_rate"] == 1.0
    assert metrics["citations"]["citation_validity_rate"] == 1.0
    assert metrics["usage"]["estimated_cost_usd_at_list_price"] is None
    assert metrics["tools"]["by_tool"]["get_session"] == 4
    results = Path(result["results_path"])
    assert results.is_file() and len(list((results.parent / "runs").iterdir())) == 4
    assert result["frozen"]["provider"] == "fixture"
    assert len(result["frozen"]["agent_instructions_sha256"]) == 64


def _stored_run(case, *, state, verdict=None, grounded=None, repair=False, reason=None, **usage):
    report = None
    if verdict is not None:
        report = Report(
            verdict=verdict,
            severity="none" if verdict in {"insufficient_evidence", "benign"} else "medium",
            confidence=0.5,
            summary="synthetic",
            findings=(
                ()
                if verdict == "insufficient_evidence"
                else (Finding(statement="x", evidence_handles=("ev-1", "ev-2")),)
            ),
            known_or_novel="uncertain",
        )
    grounding = None
    if grounded is not None:
        grounding = GroundingResult(
            grounded=grounded,
            repair_attempted=repair,
            issues=() if grounded else (GroundingIssue(kind="uncited_handle", detail="x"),),
        )
    return CaseRun(
        run_id="r",
        case=case_input(case),
        state=state,
        provider="groq",
        model="approved-model",
        fixture=False,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, tzinfo=UTC),
        traces=(
            ToolTrace(
                step=1,
                tool="get_session",
                arguments={},
                started_at=datetime(2026, 1, 1, tzinfo=UTC),
                duration_ms=10,
                available=True,
            ),
            ToolTrace(
                step=2,
                tool="get_events",
                arguments={},
                started_at=datetime(2026, 1, 1, tzinfo=UTC),
                duration_ms=30,
                available=False,
                unavailable_reason="x",
            ),
        ),
        report=report,
        grounding=grounding,
        usage=Usage(**usage),
        incomplete_reason=reason,
    )


def test_hand_calculated_agent_metrics(workspace):
    settings: Settings = workspace["settings"]
    case = select_cases(_config(workspace), settings.evidence_database, workspace["index"])[0]
    runs = [
        _stored_run(
            case,
            state=RunState.completed,
            verdict="suspicious",
            grounded=True,
            repair=True,
            input_tokens=1_000,
            output_tokens=500,
            total_tokens=1_500,
            wall_seconds=2.0,
        ),
        _stored_run(
            case,
            state=RunState.completed,
            verdict="insufficient_evidence",
            grounded=True,
            input_tokens=3_000,
            output_tokens=0,
            total_tokens=3_000,
            wall_seconds=4.0,
        ),
        _stored_run(
            case,
            state=RunState.failed,
            grounded=False,
            repair=True,
            reason="the report failed citation validation after one repair attempt",
            input_tokens=0,
            output_tokens=1_000,
            total_tokens=1_000,
            wall_seconds=6.0,
        ),
        _stored_run(
            case,
            state=RunState.failed,
            reason="groq keys exhausted after 2 limit response(s)",
            wall_seconds=1.0,
            provider_attempts=2,
            key_rotations=1,
        ),
    ]
    records = [{"run": run.model_dump(mode="json")} for run in runs]
    metrics = measure(records, hosted=_config(workspace).hosted, mode="hosted")
    outcomes = metrics["outcomes"]
    assert outcomes["verdicts"] == {"insufficient_evidence": 1, "suspicious": 1}
    assert outcomes["incomplete"] == {"grounding_refused": 1, "provider_keys_exhausted": 1}
    assert outcomes["abstention_rate"] == 0.25
    assert outcomes["decisive_verdict_rate"] == 0.25
    assert outcomes["completion_rate"] == 0.5
    citations = metrics["citations"]
    assert citations["reports_checked"] == 3
    assert citations["grounded"] == 2
    assert citations["citation_validity_rate"] == pytest.approx(2 / 3)
    assert citations["repair_attempted"] == 2 and citations["repair_succeeded"] == 1
    assert citations["cited_handles_in_published_reports"] == 2
    assert citations["issue_kinds"] == {"uncited_handle": 1}
    tools = metrics["tools"]
    assert tools["calls"] == 8 and tools["unavailable_or_error"] == 4
    assert tools["by_tool"] == {"get_events": 4, "get_session": 4}
    usage = metrics["usage"]
    assert usage["input_tokens"] == 4_000 and usage["output_tokens"] == 1_500
    # 4,000 input at $1/M plus 1,500 output at $2/M.
    assert usage["estimated_cost_usd_at_list_price"] == pytest.approx(0.007)
    assert usage["provider_attempts"] == 2 and usage["key_rotations"] == 1
    assert metrics["latency"] == {"p50_seconds": 3.0, "p95_seconds": 6.0}


def test_empty_measurement_keeps_denominators_null():
    metrics = measure([], hosted=None, mode="fixture")
    assert metrics["outcomes"]["abstention_rate"] is None
    assert metrics["citations"]["citation_validity_rate"] is None
    assert metrics["tools"]["per_run_mean"] is None


def test_labels_are_read_only_after_every_run_finishes(workspace, monkeypatch):
    settings: Settings = workspace["settings"]
    events: list[str] = []
    labels = workspace["config_path"].parent / "labels.jsonl"
    labels.write_text("", encoding="utf-8")
    workspace["config"]["labels_path"] = "labels.jsonl"
    workspace["config_path"].write_text(json.dumps(workspace["config"]), encoding="utf-8")

    real_load = agent_eval.load_labels

    def tracking_load(path, db_path):
        events.append("labels")
        return real_load(path, db_path)

    async def investigator(run_settings, case, **_):
        events.append("run")
        return _stored_run_from_input(case)

    monkeypatch.setattr(agent_eval, "load_labels", tracking_load)
    result = run_agent_evaluation(
        workspace["config_path"],
        mode="fixture",
        output_root=settings.artifact_root / "evaluation",
        settings_factory=lambda: settings,
        investigator=investigator,
    )
    assert events == ["run"] * 4 + ["labels"]
    assert result["correctness"]["measurable"] is False
    assert result["correctness"]["reason"] == "every selected case has unknown truth"


def _stored_run_from_input(case, *, fixture=True, tokens=0):
    return CaseRun(
        run_id="r",
        case=case,
        state=RunState.failed,
        provider="fixture" if fixture else "groq",
        model="fixture-analyst" if fixture else "approved-model",
        fixture=fixture,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, tzinfo=UTC),
        usage=Usage(total_tokens=tokens, input_tokens=tokens, provider_attempts=3),
        incomplete_reason="synthetic stand-in",
    )


def _hosted_settings(workspace, **overrides) -> Settings:
    settings: Settings = workspace["settings"]
    values = {
        "agent_provider": AgentProvider.groq,
        "agent_model": "approved-model",
        "agent_api_keys": ("gsk_synthetic_one", "gsk_synthetic_two"),
        **overrides,
    }
    # model_copy skips validation, so wrap keys the way Settings would.
    values["agent_api_keys"] = tuple(SecretStr(key) for key in values["agent_api_keys"])
    return settings.model_copy(update=values)


def test_hosted_refusals_never_fall_back(workspace):
    hosted = _config(workspace).hosted
    assert hosted is not None

    def invalid() -> Settings:
        return Settings(
            _env_file=None,  # type: ignore[call-arg]
            agent_api_key="gsk_secret_value_1",
            agent_api_keys=("gsk_secret_value_2",),
        )

    with pytest.raises(HostedRefused) as error:
        hosted_settings(invalid, hosted)
    assert "not both" in str(error.value)
    assert "gsk_secret" not in str(error.value)
    with pytest.raises(HostedRefused, match="not the approved provider"):
        hosted_settings(
            lambda: _hosted_settings(workspace, agent_provider=AgentProvider.openrouter), hosted
        )
    with pytest.raises(HostedRefused, match="not the approved model"):
        hosted_settings(lambda: _hosted_settings(workspace, agent_model="other"), hosted)
    with pytest.raises(HostedRefused, match="different provider"):
        hosted_settings(
            lambda: _hosted_settings(workspace, agent_api_keys=("gsk_ok", "sk-or-foreign")), hosted
        )
    with pytest.raises(HostedRefused, match="no groq key"):
        hosted_settings(lambda: _hosted_settings(workspace, agent_api_keys=()), hosted)


def test_hosted_run_requires_the_exact_approval_token(workspace):
    settings: Settings = workspace["settings"]
    calls: list[str] = []

    async def investigator(run_settings, case, **_):
        calls.append(case.case_id)
        return _stored_run_from_input(case, fixture=False)

    kwargs = {
        "mode": "hosted",
        "output_root": settings.artifact_root / "evaluation",
        "settings_factory": lambda: _hosted_settings(workspace),
        "investigator": investigator,
    }
    with pytest.raises(HostedRefused, match="approve"):
        run_agent_evaluation(workspace["config_path"], approval=None, **kwargs)
    cases = select_cases(_config(workspace), settings.evidence_database, workspace["index"])
    two = plan(_config(workspace), cases, mode="hosted", limit_cases=2)
    full = plan(_config(workspace), cases, mode="hosted")
    assert two["approval_token"] != full["approval_token"]
    # Two cases x (8 turns + 4 rate-limited responses).
    assert two["max_requests"] == 24 and two["max_total_tokens"] == 200_000
    with pytest.raises(HostedRefused):
        run_agent_evaluation(workspace["config_path"], approval=two["approval_token"], **kwargs)
    assert calls == []
    result = run_agent_evaluation(
        workspace["config_path"], approval=two["approval_token"], limit_cases=2, **kwargs
    )
    assert len(calls) == 2
    assert result["kind"] == "hosted_agent"
    assert result["frozen"]["model"] == "approved-model"


def test_hosted_ceiling_stops_before_a_case_that_might_cross_it(workspace):
    settings: Settings = workspace["settings"]
    config = _config(workspace)
    cases = select_cases(config, settings.evidence_database, workspace["index"])

    async def investigator(run_settings, case, **_):
        return _stored_run_from_input(case, fixture=False, tokens=60_000)

    records, ledger = agent_eval.execute(
        config,
        cases,
        _hosted_settings(workspace),
        mode="hosted",
        output_dir=settings.artifact_root / "ceiling",
        ceilings=(100, 220_000),
        investigator=investigator,
    )
    # 0 + 100k reserve fits; 60k + 100k fits; 120k + 100k fits; 180k + 100k does not.
    assert len(records) == 3
    assert ledger["stop_reason"] == "evaluation token ceiling"
    assert ledger["stopped_before_case"] == cases[3].case_id


def test_mode_mismatch_is_an_error(workspace):
    settings: Settings = workspace["settings"]

    async def investigator(run_settings, case, **_):
        return _stored_run_from_input(case, fixture=True)

    with pytest.raises(RuntimeError, match="provider kind"):
        agent_eval.execute(
            _config(workspace),
            select_cases(_config(workspace), settings.evidence_database, workspace["index"]),
            _hosted_settings(workspace),
            mode="hosted",
            output_dir=settings.artifact_root / "mismatch",
            ceilings=(100, 10_000_000),
            investigator=investigator,
        )


def test_public_agent_config_is_valid_and_label_free():
    path = Path(__file__).parents[2] / "evaluation" / "configs" / "agent-smoke.json"
    config = agent_eval.load_config(path)
    assert config.labels_path is None
    assert isinstance(config.hosted, HostedPlan)
    assert config.hosted.provider == "groq"


def test_case_budget_enables_bounded_rate_limit_pacing(workspace):
    budgeted = agent_eval._budgeted(_hosted_settings(workspace), _config(workspace).budget)
    assert budgeted.agent_rate_limit_pacing is True
    assert budgeted.agent_rate_limited_attempts == 4
    assert budgeted.agent_rate_limit_max_wait_seconds == 65
    assert _config(workspace).budget.http_attempts == 12
    tuned = _config(workspace).budget.model_copy(
        update={"max_retries": 4, "context_token_budget": 5_000}
    )
    budgeted = agent_eval._budgeted(_hosted_settings(workspace), tuned)
    assert budgeted.agent_max_retries == 4
    assert budgeted.agent_context_token_budget == 5_000
    assert agent_eval._failure_kind("rate_limit budget exhausted: 5 ...") == "rate_limit_allowance"
    assert (
        agent_eval._failure_kind("groq keys exhausted for now: the next key ...")
        == "provider_keys_exhausted"
    )


def test_hosted_cases_wait_for_rate_limit_headroom_or_stop(workspace):
    from hestia.agent.providers import rate_limit_pacer

    settings: Settings = workspace["settings"]
    config = _config(workspace)
    cases = select_cases(config, settings.evidence_database, workspace["index"])
    hosted = agent_eval._budgeted(_hosted_settings(workspace), config.budget)
    pacer = rate_limit_pacer(hosted)
    assert pacer is not None
    for position in (0, 1):
        pacer.retire(position)
    slept: list[float] = []

    async def investigator(run_settings, case, **_):
        return _stored_run_from_input(case, fixture=False)

    records, ledger = agent_eval.execute(
        config,
        cases,
        _hosted_settings(workspace),
        mode="hosted",
        output_dir=settings.artifact_root / "blocked",
        ceilings=(100, 10_000_000),
        investigator=investigator,
        sleep=slept.append,
    )
    assert records == [] and slept == []
    assert ledger["stopped_before_case"] == cases[0].case_id
    assert "headroom" in ledger["stop_reason"]


def test_hosted_records_carry_key_free_rate_limit_snapshots(workspace):
    settings: Settings = workspace["settings"]
    config = _config(workspace)
    cases = select_cases(config, settings.evidence_database, workspace["index"])

    async def investigator(run_settings, case, **_):
        return _stored_run_from_input(case, fixture=False)

    records, ledger = agent_eval.execute(
        config,
        cases[:1],
        _hosted_settings(workspace),
        mode="hosted",
        output_dir=settings.artifact_root / "snap",
        ceilings=(100, 10_000_000),
        investigator=investigator,
        sleep=lambda seconds: None,
    )
    snapshot = records[0]["rate_limits_after"]
    assert [item["key_position"] for item in snapshot] == [0, 1]
    assert "gsk_synthetic" not in json.dumps(records)
    assert ledger["wait_between_cases_seconds"] == 0.0
