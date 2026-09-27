"""Bounded, reproducible evaluation of the investigation agent itself.

This measures what the agent did on a pre-registered case set: outcomes,
abstentions, citation validity, tool use, latency and token/cost accounting.
Case correctness is scored only when reviewed labels exist, and only after every
run has finished; selection, agent inputs and tools never read labels.

Two modes, never mixed and never substituted for one another:

- ``fixture`` runs the deterministic scripted analyst. It exercises the harness
  and is reported as mechanics only; it is never hosted-model accuracy.
- ``hosted`` runs the configured provider/model once per case, only with an
  approval token derived from the exact plan (cases, model, request and token
  ceilings). A missing or invalid configuration refuses; it never falls back to
  the fixture or to another provider.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import time
import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from hestia.agent.contracts import CaseInput, CaseRun, RunState, Verdict
from hestia.agent.runner import instructions_digest
from hestia.config import AgentProvider, Settings
from hestia.evaluation.contracts import Truth
from hestia.evaluation.datasets import load_labels, session_truths, sha256
from hestia.evaluation.metrics import confusion, latency, wilson
from hestia.evaluation.source_labels import (
    AIT_NORMAL_SOURCE,
    normalize_technique,
    parent_technique,
    technique_from_path,
)

#: Stands in for the dataset name in the agent's case brief. A dataset name can
#: be a label proxy (CAM-LDS logs were captured during attack steps).
MASKED_DATASET = "masked-for-evaluation"
FIXTURE_MODEL = "fixture-analyst"
#: Credential prefixes that identify the *other* provider. A key carrying one
#: cannot belong to the selected provider, so the run refuses.
_FOREIGN_KEY_PREFIXES = {"groq": ("sk-or-",), "openrouter": ("gsk_",)}

Mode = Literal["fixture", "hosted"]


class HostedPlan(BaseModel):
    """The only hosted provider/model this evaluation may contact, with ceilings."""

    model_config = ConfigDict(frozen=True)
    provider: Literal["groq", "openrouter"]
    model: str = Field(min_length=1)
    #: Evaluation-wide ceiling on provider HTTP attempts, including retries/rotation.
    max_requests: int = Field(ge=1)
    #: Evaluation-wide token ceiling; a case is not started unless its full
    #: per-case reserve still fits.
    max_total_tokens: int = Field(ge=1)
    price_input_per_million_usd: float | None = Field(default=None, ge=0)
    price_output_per_million_usd: float | None = Field(default=None, ge=0)
    price_source: str | None = None


class CaseBudget(BaseModel):
    model_config = ConfigDict(frozen=True)
    max_turns: int = Field(default=8, ge=1)
    max_tool_calls: int = Field(default=16, ge=1)
    #: Per agent pass. The framework checks it after each response, so one pass
    #: can overshoot by at most one request; a case has a first pass and at most
    #: one citation-repair pass.
    max_total_tokens: int = Field(default=50_000, ge=1)
    max_wall_seconds: float = Field(default=180.0, gt=0)
    #: HTTP 429 responses a case may absorb on top of its turns (rate-limit pacing).
    max_rate_limited: int = Field(default=4, ge=0)
    #: Longest single wait for a key to regain headroom before the case stops.
    max_rate_limit_wait_seconds: float = Field(default=65.0, ge=0, le=120)
    #: Output/tool retries the model may use (malformed tool calls count).
    max_retries: int = Field(default=2, ge=1, le=8)
    #: Estimated per-request history ceiling; older tool results are condensed.
    context_token_budget: int | None = Field(default=None, ge=1_000)
    #: Before each hosted case, wait at most this long for a key to have headroom.
    max_wait_between_cases_seconds: float = Field(default=90.0, ge=0, le=300)

    @property
    def token_reserve(self) -> int:
        return 2 * self.max_total_tokens

    @property
    def http_attempts(self) -> int:
        """Hard per-case ceiling on provider HTTP attempts, 429s included."""
        return self.max_turns + self.max_rate_limited


class AgentEvalConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    schema_version: int = 1
    #: Label-free stratified selection: per dataset, sessions ordered by
    #: sha256("<seed>:<session_id>"), first ``per_dataset`` taken.
    datasets: tuple[str, ...] = Field(min_length=1)
    per_dataset: int = Field(ge=1, le=20)
    seed: int
    reference_index_path: str
    labels_path: str | None = None
    #: Session -> ATT&CK technique set sidecar; read only by ``score``.
    techniques_path: str | None = None
    budget: CaseBudget = CaseBudget()
    hosted: HostedPlan | None = None

    @model_validator(mode="after")
    def check_version(self) -> AgentEvalConfig:
        if self.schema_version != 1:
            raise ValueError("unsupported agent evaluation config version")
        if len(set(self.datasets)) != len(self.datasets):
            raise ValueError("datasets must be distinct")
        if self.techniques_path is not None and self.labels_path is None:
            raise ValueError("techniques_path needs labels_path")
        return self


class EvaluationCase(BaseModel):
    model_config = ConfigDict(frozen=True)
    case_id: str
    session_id: str
    dataset_id: str
    session_start: datetime
    session_end: datetime
    event_count: int


class HostedRefused(RuntimeError):
    """A hosted evaluation cannot start; nothing was sent to any provider."""


# -- configuration -------------------------------------------------------------


def load_config(path: Path) -> AgentEvalConfig:
    return AgentEvalConfig.model_validate_json(path.read_text(encoding="utf-8"))


def _indexed_sources(index_path: Path) -> frozenset[str]:
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    return frozenset(
        str(document["source"]["source_uri"]) for document in payload.get("documents", ())
    )


def select_cases(
    config: AgentEvalConfig, db_path: Path, index_path: Path
) -> tuple[EvaluationCase, ...]:
    """Choose cases from store structure only. Never opens a label file.

    Sessions whose source file is searchable in the reference index are excluded,
    so a case cannot retrieve its own log as "reference material". The order is
    interleaved by dataset, so the first N cases cover datasets evenly.
    """
    from hestia.runs.cases import case_id_for

    indexed = _indexed_sources(index_path)
    strata: list[list[EvaluationCase]] = []
    with sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True) as db:
        for dataset in config.datasets:
            rows = db.execute(
                """SELECT s.session_id, s.session_json, src.path,
                          (SELECT COUNT(*) FROM session_events se
                           WHERE se.session_id = s.session_id)
                   FROM sessions s JOIN sources src ON src.id = s.source_id
                   WHERE src.dataset_id = ?""",
                (dataset,),
            ).fetchall()
            eligible = [row for row in rows if row[2] not in indexed]
            eligible.sort(
                key=lambda row: hashlib.sha256(f"{config.seed}:{row[0]}".encode()).hexdigest()
            )
            if len(eligible) < config.per_dataset:
                raise ValueError(
                    f"dataset {dataset!r} has {len(eligible)} eligible sessions; "
                    f"{config.per_dataset} requested"
                )
            stratum: list[EvaluationCase] = []
            strata.append(stratum)
            for session_id, session_json, _, count in eligible[: config.per_dataset]:
                session = json.loads(session_json)
                stratum.append(
                    EvaluationCase(
                        case_id=case_id_for(session_id),
                        session_id=session_id,
                        dataset_id=dataset,
                        session_start=datetime.fromisoformat(session["start_time"]),
                        session_end=datetime.fromisoformat(session["end_time"]),
                        event_count=int(count),
                    )
                )
    # Round-robin across datasets, so any prefix (``--limit-cases``) stays stratified.
    return tuple(case for rank in zip(*strata, strict=True) for case in rank)


def case_input(case: EvaluationCase) -> CaseInput:
    """What the agent receives: opaque case ID, masked dataset, time bounds."""
    return CaseInput(
        case_id=case.case_id,
        session_id=case.session_id,
        opened_at=datetime.now(UTC),
        session_start=case.session_start,
        session_end=case.session_end,
        dataset_id=MASKED_DATASET,
        history_before=case.session_start,
    )


def manifest_hash(cases: Sequence[EvaluationCase]) -> str:
    canonical = json.dumps(
        [case.model_dump(mode="json") for case in cases], sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


# -- planning and approval -------------------------------------------------------


def plan(
    config: AgentEvalConfig,
    cases: Sequence[EvaluationCase],
    *,
    mode: Mode,
    limit_cases: int | None = None,
) -> dict[str, Any]:
    """Describe exactly what a run would do. Contacts nothing."""
    chosen = tuple(cases[:limit_cases] if limit_cases is not None else cases)
    budget = config.budget
    summary: dict[str, Any] = {
        "mode": mode,
        "cases": [
            {"case_id": case.case_id, "dataset_id": case.dataset_id, "events": case.event_count}
            for case in chosen
        ],
        "case_manifest_sha256": manifest_hash(chosen),
        "per_case_budget": budget.model_dump(mode="json"),
    }
    if mode == "fixture":
        summary["provider"] = "fixture"
        summary["model"] = FIXTURE_MODEL
        summary["outbound"] = "none; the scripted analyst runs locally"
        return summary
    hosted = config.hosted
    if hosted is None:
        raise HostedRefused("the config has no hosted plan")
    requests = min(hosted.max_requests, len(chosen) * budget.http_attempts)
    tokens = min(hosted.max_total_tokens, len(chosen) * budget.token_reserve)
    worst_cost = None
    if (
        hosted.price_input_per_million_usd is not None
        and hosted.price_output_per_million_usd is not None
    ):
        # Upper bound: every token priced at the higher of the two list prices.
        rate = max(hosted.price_input_per_million_usd, hosted.price_output_per_million_usd)
        worst_cost = round(tokens * rate / 1_000_000, 4)
    summary.update(
        {
            "provider": hosted.provider,
            "model": hosted.model,
            "max_requests": requests,
            "max_total_tokens": tokens,
            "token_ceiling_note": (
                "checked after each response: a pass may overshoot by one request, and a "
                "case starts only if its full reserve still fits"
            ),
            "rate_limits": (
                "each key is paced within its provider-reported token/request limits; a 429 "
                "cools that key for retry-after; waits are capped per case and counted"
            ),
            "price_source": hosted.price_source,
            "worst_case_cost_usd_at_list_price": worst_cost,
            "outbound": (
                "system instructions; case brief (opaque case id, masked dataset, session "
                "window, history boundary); tool schemas; redacted tool results "
                "(pseudonymized host/user/IP, event types, timestamps, redacted and "
                "truncated log message text, counts, model readiness, public ATT&CK/CAM "
                "reference snippets). No labels, source paths, digests or keys."
            ),
        }
    )
    summary["approval_token"] = approval_token(summary)
    return summary


def approval_token(summary: dict[str, Any]) -> str:
    """Binds an approval to the exact model, cases and ceilings shown to the user."""
    bound = {
        name: summary[name]
        for name in (
            "provider",
            "model",
            "case_manifest_sha256",
            "max_requests",
            "max_total_tokens",
            "per_case_budget",
        )
    }
    canonical = json.dumps(bound, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def hosted_settings(settings_factory: Callable[[], Settings], hosted: HostedPlan) -> Settings:
    """Load the local configuration and refuse anything but the approved provider."""
    try:
        settings = settings_factory()
    except Exception as exc:  # noqa: BLE001 - message may echo env input; never show it
        detail = str(exc).splitlines()[1].strip() if "\n" in str(exc) else "invalid settings"
        detail = detail.split("[type=")[0].strip()
        raise HostedRefused(f"local agent configuration is invalid: {detail}") from None
    if settings.agent_provider is None or settings.agent_provider.value != hosted.provider:
        raise HostedRefused(
            f"configured provider {getattr(settings.agent_provider, 'value', None)!r} "
            f"is not the approved provider {hosted.provider!r}"
        )
    if settings.agent_model != hosted.model:
        raise HostedRefused("configured model is not the approved model")
    keys = settings.agent_keys
    if not keys:
        raise HostedRefused(f"no {hosted.provider} key is configured")
    if any(key.startswith(_FOREIGN_KEY_PREFIXES[hosted.provider]) for key in keys):
        raise HostedRefused(
            f"a configured key belongs to a different provider than {hosted.provider}; "
            "keys are never combined across providers"
        )
    return settings


def _budgeted(settings: Settings, budget: CaseBudget) -> Settings:
    return settings.model_copy(
        update={
            "agent_max_turns": budget.max_turns,
            "agent_max_tool_calls": budget.max_tool_calls,
            "agent_max_total_tokens": budget.max_total_tokens,
            "agent_max_wall_seconds": budget.max_wall_seconds,
            "agent_fixture_pace_seconds": 0.0,
            "agent_rate_limit_pacing": True,
            "agent_max_retries": budget.max_retries,
            "agent_context_token_budget": budget.context_token_budget,
            "agent_rate_limited_attempts": budget.max_rate_limited,
            "agent_rate_limit_max_wait_seconds": budget.max_rate_limit_wait_seconds,
        }
    )


# -- execution -------------------------------------------------------------------


Investigator = Callable[..., Any]


def execute(
    config: AgentEvalConfig,
    cases: Sequence[EvaluationCase],
    settings: Settings,
    *,
    mode: Mode,
    output_dir: Path,
    ceilings: tuple[int, int] | None = None,
    investigator: Investigator | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run each case once, sequentially, and write each record as it finishes.

    Labels are not available here. Hosted runs stop before a case whose request
    or token reserve would cross the approved evaluation ceiling, and wait a
    bounded time for rate-limit headroom before starting each case.
    """
    from hestia.agent.fixtures import workspace_demo_script
    from hestia.agent.providers import rate_limit_pacer
    from hestia.agent.runner import investigate

    run_case = investigator or investigate
    settings = _budgeted(settings, config.budget)
    if mode == "fixture":
        settings = settings.model_copy(
            update={"agent_provider": AgentProvider.fixture, "agent_model": FIXTURE_MODEL}
        )
    records: list[dict[str, Any]] = []
    ledger: dict[str, Any] = {
        "requests": 0,
        "tokens": 0,
        "stopped_before_case": None,
        "stop_reason": None,
        "wait_between_cases_seconds": 0.0,
    }
    pacer = rate_limit_pacer(settings) if mode == "hosted" else None
    (output_dir / "runs").mkdir(parents=True, exist_ok=False)
    for position, case in enumerate(cases, 1):
        if mode == "hosted":
            if ceilings is None:
                raise HostedRefused("a hosted evaluation requires approved ceilings")
            max_requests, max_tokens = ceilings
            if ledger["requests"] + config.budget.http_attempts > max_requests:
                ledger["stopped_before_case"] = case.case_id
                ledger["stop_reason"] = "evaluation request ceiling"
                break
            if ledger["tokens"] + config.budget.token_reserve > max_tokens:
                ledger["stopped_before_case"] = case.case_id
                ledger["stop_reason"] = "evaluation token ceiling"
                break
            if pacer is not None:
                _, wait = pacer.choose(0)
                if wait > config.budget.max_wait_between_cases_seconds:
                    ledger["stopped_before_case"] = case.case_id
                    ledger["stop_reason"] = f"no key has rate-limit headroom within {wait:.1f}s"
                    break
                if wait > 0:
                    sleep(wait)
                    ledger["wait_between_cases_seconds"] = round(
                        ledger["wait_between_cases_seconds"] + wait, 3
                    )
        script = workspace_demo_script() if mode == "fixture" else None
        run: CaseRun = asyncio.run(
            run_case(settings, case_input(case), fixture_script=script, stdio=False)
        )
        if run.fixture != (mode == "fixture"):
            raise RuntimeError("a run's provider kind does not match the evaluation mode")
        ledger["requests"] += run.usage.provider_attempts or run.usage.requests
        ledger["tokens"] += run.usage.total_tokens
        record = {
            "position": position,
            "case_id": case.case_id,
            "dataset_id": case.dataset_id,
            "run": run.model_dump(mode="json"),
            # Key-free provider rate-limit state after this case, by key position.
            "rate_limits_after": pacer.snapshot() if pacer is not None else None,
        }
        (output_dir / "runs" / f"{position:03d}.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        records.append(record)
    return records, ledger


# -- measurement -------------------------------------------------------------------


def _spread(values: Sequence[float]) -> dict[str, float | None]:
    measured = latency(values)
    return {"p50": measured["p50_seconds"], "p95": measured["p95_seconds"]}


def _failure_kind(reason: str | None) -> str:
    text = (reason or "").lower()
    if "citation validation" in text:
        return "grounding_refused"
    if "rate_limit budget" in text:
        return "rate_limit_allowance"
    if "keys exhausted" in text:
        return "provider_keys_exhausted"
    if "provider request failed" in text:
        return "provider_error"
    if "budget exhausted" in text:
        return "budget"
    if "cancel" in text:
        return "cancelled"
    return "other"


def measure(
    records: Sequence[dict[str, Any]], *, hosted: HostedPlan | None, mode: Mode
) -> dict[str, Any]:
    """Descriptive agent metrics. Undefined denominators stay null."""
    runs = [CaseRun.model_validate(record["run"]) for record in records]
    total = len(runs)
    verdicts = Counter(
        run.report.verdict.value for run in runs if run.state is RunState.completed and run.report
    )
    abstained = verdicts.get(Verdict.insufficient_evidence.value, 0)
    completed = sum(verdicts.values())
    incomplete = Counter(
        _failure_kind(run.incomplete_reason) for run in runs if run.state is not RunState.completed
    )
    grounding_checked = [run for run in runs if run.grounding is not None]
    grounded = sum(run.grounding.grounded for run in grounding_checked if run.grounding)
    issues = Counter(
        issue.kind for run in grounding_checked if run.grounding for issue in run.grounding.issues
    )
    repaired = [
        run for run in grounding_checked if run.grounding and run.grounding.repair_attempted
    ]
    cited = sum(
        len(finding.evidence_handles)
        for run in runs
        if run.report is not None
        for finding in run.report.findings
    )
    traces = [trace for run in runs for trace in run.traces]
    per_run_calls = [len(run.traces) for run in runs]
    tokens_in = sum(run.usage.input_tokens for run in runs)
    tokens_out = sum(run.usage.output_tokens for run in runs)
    cost = None
    if (
        mode == "hosted"
        and hosted is not None
        and hosted.price_input_per_million_usd is not None
        and hosted.price_output_per_million_usd is not None
    ):
        cost = round(
            tokens_in * hosted.price_input_per_million_usd / 1_000_000
            + tokens_out * hosted.price_output_per_million_usd / 1_000_000,
            6,
        )
    return {
        "cases_run": total,
        "outcomes": {
            "completed": completed,
            "verdicts": dict(sorted(verdicts.items())),
            "incomplete": dict(sorted(incomplete.items())),
            "abstention_rate": abstained / total if total else None,
            "decisive_verdict_rate": (completed - abstained) / total if total else None,
            "completion_rate": completed / total if total else None,
        },
        "citations": {
            "reports_checked": len(grounding_checked),
            "grounded": grounded,
            "citation_validity_rate": (
                grounded / len(grounding_checked) if grounding_checked else None
            ),
            "cited_handles_in_published_reports": cited,
            "repair_attempted": len(repaired),
            "repair_succeeded": sum(
                run.grounding.grounded for run in repaired if run.grounding is not None
            ),
            "issue_kinds": dict(sorted(issues.items())),
            "note": "citation existence/consistency only; semantic grounding is unmeasured",
        },
        "tools": {
            "calls": len(traces),
            "by_tool": dict(sorted(Counter(trace.tool for trace in traces).items())),
            "unavailable_or_error": sum(
                (not trace.available) or trace.error is not None for trace in traces
            ),
            "per_run_mean": sum(per_run_calls) / total if total else None,
            "per_run_max": max(per_run_calls) if per_run_calls else None,
            "hypotheses_recorded": sum(len(run.hypotheses) for run in runs),
            "tool_latency_ms": _spread([trace.duration_ms for trace in traces]),
        },
        "latency": latency([run.usage.wall_seconds for run in runs]),
        "usage": {
            "requests": sum(run.usage.requests for run in runs),
            "provider_attempts": sum(run.usage.provider_attempts for run in runs),
            "key_rotations": sum(run.usage.key_rotations for run in runs),
            "compacted_tool_results": sum(run.usage.compacted_tool_results for run in runs),
            "rate_limited_responses": sum(run.usage.rate_limited for run in runs),
            "rate_limit_wait_seconds": round(
                sum(run.usage.rate_limit_wait_seconds for run in runs), 3
            ),
            "input_tokens": tokens_in,
            "output_tokens": tokens_out,
            "total_tokens": tokens_in + tokens_out,
            "per_run_total_tokens": _spread([run.usage.total_tokens for run in runs]),
            "estimated_cost_usd_at_list_price": cost,
            "cost_note": (
                "list-price estimate from recorded tokens, not a billed amount"
                if cost is not None
                else "not priced (fixture run or no price in config)"
            ),
            "token_note": (
                "framework estimates for a scripted local model, not provider counts"
                if mode == "fixture"
                else "provider-reported usage as returned to the framework"
            ),
        },
    }


def _indexed_techniques(index_path: Path | None) -> frozenset[str]:
    """Techniques that have CAM-LDS technique-folder documents in the reference index."""
    if index_path is None:
        return frozenset()
    found = (technique_from_path(source) for source in _indexed_sources(index_path))
    return frozenset(technique for technique in found if technique is not None)


def _technique_match(proposed: set[str], truth: set[str]) -> str:
    if not proposed:
        return "none_proposed"
    if proposed & truth:
        return "exact"
    if {parent_technique(t) for t in proposed} & {parent_technique(t) for t in truth}:
        return "parent"
    return "mismatch"


def _rate(successes: int, total: int) -> dict[str, Any]:
    return {
        "count": successes,
        "of": total,
        "rate": successes / total if total else None,
        "ci95": wilson(successes, total),
    }


def score(
    records: Sequence[dict[str, Any]],
    labels_path: Path | None,
    db_path: Path,
    *,
    techniques_path: Path | None = None,
    index_path: Path | None = None,
) -> dict[str, Any]:
    """Join labels to finished runs. The only place labels are read.

    The technique metric covers attack cases whose ATT&CK technique set is known:
    ``exact`` when a proposed ID is in the set, ``parent`` when only the base
    technique agrees (T1110 vs T1110.001), ``none_proposed`` / ``mismatch``
    otherwise, and ``no_report`` when the run published nothing. Rates use every
    such case as the denominator, so a missing report counts against the agent.
    """
    if labels_path is None:
        return {
            "measurable": False,
            "reason": "no reviewed label set is configured for these cases",
            "labels_sha256": None,
            "confusion": confusion(()),
        }
    labels, digest = load_labels(labels_path, db_path)
    annotation_sources = {
        json.loads(line)["annotation_source"]
        for line in labels_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    truths = session_truths(db_path, labels)
    session_techniques: dict[str, set[str]] = {}
    techniques_digest = None
    if techniques_path is not None:
        payload = json.loads(techniques_path.read_text(encoding="utf-8"))
        session_techniques = {
            session: set(row["techniques"]) for session, row in payload["sessions"].items()
        }
        techniques_digest = sha256(techniques_path)
    indexed = _indexed_techniques(index_path)

    rows: list[tuple[Truth, str | None]] = []
    cases: list[dict[str, Any]] = []
    matches: Counter[str] = Counter()
    for record in records:
        run = CaseRun.model_validate(record["run"])
        prediction = run.report.verdict.value if run.report is not None else None
        truth = truths.get(run.case.session_id, Truth.unknown)
        rows.append((truth, prediction))
        row: dict[str, Any] = {
            "case_id": run.case.case_id,
            "dataset_id": record.get("dataset_id"),
            "truth": truth.value,
            "prediction": prediction,
        }
        known = session_techniques.get(run.case.session_id)
        if truth is Truth.attack and known:
            proposed = {
                technique
                for value in (run.report.technique_ids if run.report is not None else ())
                if (technique := normalize_technique(value)) is not None
            }
            match = _technique_match(proposed, known) if run.report is not None else "no_report"
            matches[match] += 1
            row["technique"] = {
                "truth": sorted(known),
                "truth_set_size": len(known),
                "proposed": sorted(proposed),
                "match": match,
                "cam_sibling_in_reference_index": bool(known & indexed),
            }
        cases.append(row)
    matrix = confusion(rows)
    eligible = sum(matches.values())
    technique = {
        "measurable": eligible > 0,
        "techniques_sha256": techniques_digest,
        "eligible_attack_cases": eligible,
        "counts": {
            name: matches.get(name, 0)
            for name in ("exact", "parent", "mismatch", "none_proposed", "no_report")
        },
        "exact": _rate(matches["exact"], eligible),
        "exact_or_parent": _rate(matches["exact"] + matches["parent"], eligible),
        "cases_with_cam_sibling_in_reference_index": sum(
            bool(row.get("technique", {}).get("cam_sibling_in_reference_index")) for row in cases
        ),
    }

    limitations = [
        "Labels are rule-derived from upstream dataset conventions, not reviewed per "
        f"event by Hestia ({len(annotation_sources)} annotation rule(s) in the sidecar).",
        f"n={matrix['labelled']} labelled case(s); Wilson 95% intervals are wide and "
        "rates describe this pilot sample only.",
    ]
    by_truth: dict[str, set[str]] = {}
    for row in cases:
        if row["truth"] != Truth.unknown.value:
            by_truth.setdefault(row["truth"], set()).add(str(row["dataset_id"]))
    attack_sets = by_truth.get(Truth.attack.value, set())
    normal_sets = by_truth.get(Truth.normal.value, set())
    if attack_sets and normal_sets and not attack_sets & normal_sets:
        limitations.append(
            f"Dataset confound: every attack case is from {sorted(attack_sets)} and every "
            f"normal case from {sorted(normal_sets)}, so a detector of dataset style "
            "would score the same."
        )
    if technique["cases_with_cam_sibling_in_reference_index"]:
        limitations.append(
            "Technique matches are inflated: the reference index holds CAM-LDS documents "
            "filed under the same techniques, which the agent can retrieve."
        )
    if any(row.get("technique", {}).get("truth_set_size", 0) > 1 for row in cases):
        limitations.append(
            "Some truth technique sets hold several IDs (one log file filed under several "
            "techniques); any overlap counts as a match, which is lenient."
        )
    if AIT_NORMAL_SOURCE in annotation_sources:
        limitations.append(
            "AIT 'unlisted = normal' is the upstream convention adopted for evaluation "
            "labels only; it departs from H1's 'unlabelled = unknown' policy, and the "
            "normality training gate still has 0 eligible sessions."
        )
    return {
        "measurable": matrix["labelled"] > 0,
        "reason": None if matrix["labelled"] else "every selected case has unknown truth",
        "labels_sha256": digest,
        "confusion": matrix,
        "technique": technique,
        "cases": cases,
        "limitations": limitations if matrix["labelled"] else [],
    }


# -- orchestration -----------------------------------------------------------------


def run_agent_evaluation(
    config_path: Path,
    *,
    mode: Mode,
    output_root: Path,
    settings_factory: Callable[[], Settings],
    approval: str | None = None,
    limit_cases: int | None = None,
    investigator: Investigator | None = None,
) -> dict[str, Any]:
    """Select, (for hosted) verify approval, run, measure, then score. Immutable output."""
    config_path = config_path.resolve()
    config = load_config(config_path)

    def resolve(value: str | None) -> Path | None:
        return (config_path.parent / value).resolve() if value is not None else None

    index_path = resolve(config.reference_index_path)
    assert index_path is not None
    if mode == "hosted":
        if config.hosted is None:
            raise HostedRefused("the config has no hosted plan")
        settings = hosted_settings(settings_factory, config.hosted)
    else:
        settings = settings_factory()
    db_path = settings.evidence_database
    if not db_path.is_file():
        raise FileNotFoundError(db_path)
    cases = select_cases(config, db_path, index_path)
    chosen = tuple(cases[:limit_cases] if limit_cases is not None else cases)
    summary = plan(config, cases, mode=mode, limit_cases=limit_cases)
    if mode == "hosted" and approval != summary["approval_token"]:
        raise HostedRefused(
            "hosted evaluation needs --approve with the token from --plan for this exact "
            "model, case set and ceiling"
        )

    frozen = {
        "config_sha256": sha256(config_path),
        "evidence_sha256": sha256(db_path),
        "reference_index_sha256": sha256(index_path),
        "case_manifest_sha256": summary["case_manifest_sha256"],
        "agent_instructions_sha256": instructions_digest(),
        "mode": mode,
        "provider": summary["provider"],
        "model": summary["model"],
    }
    pending = output_root / f"agent-pending-{uuid.uuid4().hex[:12]}"
    try:
        ceilings = (
            (summary["max_requests"], summary["max_total_tokens"]) if mode == "hosted" else None
        )
        records, ledger = execute(
            config,
            chosen,
            settings,
            mode=mode,
            output_dir=pending,
            ceilings=ceilings,
            investigator=investigator,
        )
        metrics = measure(records, hosted=config.hosted, mode=mode)
        # Labels are opened only now, after every run has finished.
        correctness = score(
            records,
            resolve(config.labels_path),
            db_path,
            techniques_path=resolve(config.techniques_path),
            index_path=index_path,
        )
        result: dict[str, Any] = {
            "schema_version": 1,
            "kind": "fixture_mechanics_only" if mode == "fixture" else "hosted_agent",
            "accuracy_claim_allowed": mode == "hosted" and bool(correctness["measurable"]),
            "frozen": frozen,
            "plan": summary,
            "cases": [
                {"case_id": case.case_id, "dataset_id": case.dataset_id, "events": case.event_count}
                for case in chosen
            ],
            "ledger": ledger,
            "metrics": metrics,
            "correctness": correctness,
            "limitations": [
                "Cases are a small label-free stratified sample; outcome rates describe "
                "this sample only.",
                "Citation validity is existence/consistency, not semantic truth.",
                "Fixture runs test harness mechanics and are never model accuracy.",
                "Hosted providers are nondeterministic; one run per case, no repeats.",
                *correctness.get("limitations", ()),
            ],
        }
        canonical = json.dumps(result, sort_keys=True, separators=(",", ":"), default=str)
        run_id = "agent-" + hashlib.sha256(canonical.encode()).hexdigest()[:20]
        (pending / "results.json").write_text(
            json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
        )
        destination = output_root / run_id
        pending.rename(destination)
    except BaseException:
        # Keep partial evidence of what ran; mark it rather than deleting it.
        if pending.exists():
            pending.rename(pending.with_name(pending.name.replace("pending", "aborted")))
        raise
    return {"run_id": run_id, "results_path": str(destination / "results.json"), **result}


__all__ = [
    "MASKED_DATASET",
    "AgentEvalConfig",
    "CaseBudget",
    "EvaluationCase",
    "HostedPlan",
    "HostedRefused",
    "approval_token",
    "case_input",
    "execute",
    "hosted_settings",
    "load_config",
    "manifest_hash",
    "measure",
    "plan",
    "run_agent_evaluation",
    "score",
    "select_cases",
]
