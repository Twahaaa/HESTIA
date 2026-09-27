import time

import pytest

from hestia.agent.budgets import Budget, BudgetExceeded, BudgetLedger
from hestia.config import AgentProvider, Settings


def test_budget_comes_from_settings(settings):
    budget = Budget.from_settings(settings)
    assert budget.max_tool_calls == 10
    assert budget.max_turns == 12
    assert budget.as_dict()["max_wall_seconds"] == 30.0


def test_tool_call_ceiling_is_enforced_independently_of_the_framework(settings):
    ledger = BudgetLedger(budget=Budget.from_settings(settings))
    for _ in range(10):
        ledger.record_tool_call()
    with pytest.raises(BudgetExceeded) as exc:
        ledger.record_tool_call()
    assert exc.value.budget == "tool_calls"


def test_wall_clock_budget_stops_the_run(settings):
    budget = Budget.from_settings(settings).__class__(
        max_turns=5,
        max_tool_calls=5,
        max_total_tokens=100,
        max_wall_seconds=0.01,
        max_retries=1,
        request_timeout_seconds=1.0,
    )
    ledger = BudgetLedger(budget=budget)
    time.sleep(0.02)
    with pytest.raises(BudgetExceeded) as exc:
        ledger.check()
    assert exc.value.budget == "wall_clock"


def test_cancellation_is_a_budget_outcome(settings):
    ledger = BudgetLedger(budget=Budget.from_settings(settings))
    ledger.cancel("operator stopped the case")
    with pytest.raises(BudgetExceeded) as exc:
        ledger.check()
    assert exc.value.budget == "cancellation"
    assert "operator stopped" in exc.value.detail


def test_usage_limits_mirror_the_configured_budget(settings):
    limits = Budget.from_settings(settings).usage_limits()
    assert limits.request_limit == 12
    assert limits.tool_calls_limit == 10
    assert limits.total_tokens_limit == settings.agent_max_total_tokens


def test_settings_reject_parallel_cases_and_nonpositive_budgets():
    with pytest.raises(ValueError, match="concurrency"):
        Settings(agent_concurrency=2)
    with pytest.raises(ValueError, match="at least 1"):
        Settings(agent_max_tool_calls=0)
    with pytest.raises(ValueError, match="positive"):
        Settings(agent_max_wall_seconds=0)


def test_provider_status_is_explicit_without_configuration(tmp_path):
    from hestia.agent.providers import provider_status

    status = provider_status(Settings(artifact_root=tmp_path))
    assert status.configured is False
    assert "HESTIA_AGENT_PROVIDER" in (status.reason or "")

    partial = provider_status(Settings(agent_provider=AgentProvider.groq, artifact_root=tmp_path))
    assert partial.configured is False
    assert "never guessed" in (partial.reason or "")

    keyless = provider_status(
        Settings(
            agent_provider=AgentProvider.groq,
            agent_model="llama-3.3-70b-versatile",
            artifact_root=tmp_path,
        )
    )
    assert keyless.configured is False
    assert "HESTIA_AGENT_API_KEY" in (keyless.reason or "")


def test_no_silent_provider_fallback(tmp_path):
    from hestia.agent.providers import ProviderUnavailable, build_model

    with pytest.raises(ProviderUnavailable):
        build_model(Settings(artifact_root=tmp_path))
    with pytest.raises(ProviderUnavailable, match="scripted"):
        build_model(
            Settings(
                agent_provider=AgentProvider.fixture,
                agent_model="fixture",
                artifact_root=tmp_path,
            )
        )
