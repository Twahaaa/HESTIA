"""Provider-key rotation is offline-tested; no test contacts a hosted API."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import SecretStr
from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.models.function import FunctionModel

from hestia.agent.budgets import BudgetExceeded
from hestia.agent.contracts import RunState
from hestia.agent.fixtures import demo_script
from hestia.agent.providers import GroqAdapter, OpenRouterAdapter, build_model, provider_status
from hestia.agent.rotation import ProviderKeysExhausted, RotatingModel, rotatable_limit
from hestia.agent.runner import investigate
from hestia.config import AgentProvider, Settings


class FakeModel(Model):
    def __init__(self, result: Callable[[], ModelResponse]) -> None:
        super().__init__()
        self.result = result
        self.calls = 0

    @property
    def model_name(self) -> str:
        return "fake-model"

    @property
    def system(self) -> str:
        return "groq"

    async def request(self, messages, model_settings, model_request_parameters):
        self.calls += 1
        return self.result()


def failure(status: int, body=None) -> Callable[[], ModelResponse]:
    def raise_error():
        raise ModelHTTPError(status_code=status, model_name="fake-model", body=body)

    return raise_error


def successful() -> ModelResponse:
    return ModelResponse(parts=[TextPart(content="success")])


@pytest.mark.parametrize("provider", [AgentProvider.groq, AgentProvider.openrouter])
def test_settings_accept_an_ordered_list_without_exposing_keys(tmp_path, provider):
    env = tmp_path / ".env"
    env.write_text(
        'HESTIA_AGENT_API_KEYS=\'["secret-one","secret-two"]\'\n'
        f"HESTIA_AGENT_PROVIDER={provider.value}\n"
        "HESTIA_AGENT_MODEL=provider/model\n",
        encoding="utf-8",
    )
    settings = Settings(_env_file=env)
    assert settings.agent_keys == ("secret-one", "secret-two")
    assert provider_status(settings).configured is True
    assert "secret-one" not in repr(settings)
    assert "secret-two" not in str(provider_status(settings).as_dict())
    with pytest.raises(ValueError, match="either"):
        Settings(agent_api_key=SecretStr("one"), agent_api_keys=(SecretStr("two"),))
    with pytest.raises(ValueError, match="unique"):
        Settings(agent_api_keys=(SecretStr("same"), SecretStr("same")))
    with pytest.raises(ValueError, match="nonempty"):
        Settings(agent_api_keys=(SecretStr("  "),))


@pytest.mark.asyncio
async def test_adapters_disable_hidden_sdk_retries_without_contacting_provider():
    groq = GroqAdapter("llama-3.3-70b-versatile", 5).create_model("placeholder")
    router = OpenRouterAdapter("openai/gpt-5.2", 5).create_model("placeholder")
    assert groq.provider.client.max_retries == 0
    assert router.provider.client.max_retries == 0
    assert groq.model_name == "llama-3.3-70b-versatile"
    assert router.model_name == "openai/gpt-5.2"
    await groq.provider.client.close()
    await router.provider.client.close()


@pytest.mark.asyncio
async def test_rotates_on_429_and_keeps_new_key_for_later_requests():
    first = FakeModel(failure(429, {"error": "slow down"}))
    second = FakeModel(successful)
    model = RotatingModel(
        (first, second), provider="groq", max_attempts=4, before_attempt=lambda: None
    )
    parameters = ModelRequestParameters()
    assert (await model.request([], None, parameters)).parts[0].content == "success"
    await model.request([], None, parameters)
    assert (first.calls, second.calls) == (1, 2)
    assert (model.attempts, model.key_rotations) == (3, 1)


@pytest.mark.asyncio
async def test_request_attempts_remain_bounded_after_rotation():
    models = (FakeModel(failure(429)), FakeModel(successful))
    model = RotatingModel(models, provider="groq", max_attempts=2, before_attempt=lambda: None)
    await model.request([], None, ModelRequestParameters())
    with pytest.raises(BudgetExceeded, match="requests budget exhausted"):
        await model.request([], None, ModelRequestParameters())
    assert (models[0].calls, models[1].calls) == (1, 1)


@pytest.mark.asyncio
async def test_all_limited_keys_end_without_leaking_error_body():
    model = RotatingModel(
        (
            FakeModel(failure(429, {"error": "secret-one"})),
            FakeModel(failure(429, {"error": "secret-two"})),
        ),
        provider="groq",
        max_attempts=3,
        before_attempt=lambda: None,
    )
    with pytest.raises(ProviderKeysExhausted, match="keys exhausted") as exc:
        await model.request([], None, ModelRequestParameters())
    assert "secret" not in str(exc.value)
    assert model.attempts == 2


def test_openrouter_402_rotates_only_for_explicit_per_key_credit_limit():
    per_key = ModelHTTPError(
        status_code=402,
        model_name="fake-model",
        body={"error": {"metadata": {"limit_source": "openrouter_key_limit"}}},
    )
    account = ModelHTTPError(
        status_code=402,
        model_name="fake-model",
        body={"error": {"metadata": {"limit_source": "openrouter_credits"}}},
    )
    assert rotatable_limit("openrouter", per_key)
    assert not rotatable_limit("groq", per_key)
    assert not rotatable_limit("openrouter", account)
    for status in (400, 401, 403, 404, 500, 503):
        assert not rotatable_limit("groq", ModelHTTPError(status, "fake-model"))


@pytest.mark.asyncio
async def test_openrouter_per_key_credit_limit_rotates_but_account_limit_does_not():
    per_key = {"error": {"metadata": {"limit_source": "openrouter_key_limit"}}}
    account = {"error": {"metadata": {"limit_source": "openrouter_credits"}}}
    first = FakeModel(failure(402, per_key))
    second = FakeModel(successful)
    model = RotatingModel(
        (first, second), provider="openrouter", max_attempts=3, before_attempt=lambda: None
    )
    await model.request([], None, ModelRequestParameters())
    assert model.key_rotations == 1
    blocked = FakeModel(failure(402, account))
    other = FakeModel(successful)
    no_rotation = RotatingModel(
        (blocked, other), provider="openrouter", max_attempts=3, before_attempt=lambda: None
    )
    with pytest.raises(ModelHTTPError) as exc:
        await no_rotation.request([], None, ModelRequestParameters())
    assert exc.value.status_code == 402
    assert other.calls == 0


@pytest.mark.asyncio
async def test_nonlimit_http_errors_do_not_try_next_key():
    first = FakeModel(failure(401, {"error": "bad credential"}))
    second = FakeModel(successful)
    model = RotatingModel(
        (first, second), provider="groq", max_attempts=4, before_attempt=lambda: None
    )
    with pytest.raises(ModelHTTPError) as exc:
        await model.request([], None, ModelRequestParameters())
    assert exc.value.status_code == 401
    assert (first.calls, second.calls, model.key_rotations) == (1, 0, 0)


@pytest.mark.asyncio
async def test_cancellation_or_wall_budget_stops_before_switching_keys():
    first = FakeModel(failure(429))
    second = FakeModel(successful)
    checks = 0

    def stop_before_second_attempt():
        nonlocal checks
        checks += 1
        if checks == 2:
            raise BudgetExceeded("cancellation", "operator stopped the case")

    model = RotatingModel(
        (first, second), provider="groq", max_attempts=4, before_attempt=stop_before_second_attempt
    )
    with pytest.raises(BudgetExceeded, match="cancellation budget exhausted"):
        await model.request([], None, ModelRequestParameters())
    assert first.calls == 1
    assert second.calls == 0
    assert model.attempts == 1


@pytest.mark.asyncio
async def test_run_rotates_without_adding_a_second_agent_or_exposing_keys(
    prepared, case, monkeypatch
):
    from hestia.agent.providers import _scripted

    script = _scripted(demo_script())

    def adapter_model(self, key: str):
        if key == "key-one":

            def limited(messages, info):
                raise ModelHTTPError(429, self.model_name, body={"error": key})

            return FunctionModel(limited, model_name=self.model_name)
        return FunctionModel(script, model_name=self.model_name)

    monkeypatch.setattr(GroqAdapter, "create_model", adapter_model)
    settings = prepared.model_copy(
        update={
            "agent_provider": AgentProvider.groq,
            "agent_model": "fixture-analyst",
            "agent_api_keys": (SecretStr("key-one"), SecretStr("key-two")),
        }
    )
    model = build_model(settings)
    assert isinstance(model, RotatingModel)
    run = await investigate(settings, case)
    assert run.state is RunState.completed
    assert run.usage.key_rotations == 1
    assert run.usage.provider_attempts >= 2
    assert "key-one" not in run.model_dump_json()
    assert "key-two" not in run.model_dump_json()


@pytest.mark.asyncio
async def test_run_never_persists_provider_body_or_any_configured_key(prepared, case, monkeypatch):
    def adapter_model(self, key: str):
        def rejected(messages, info):
            raise ModelHTTPError(401, self.model_name, body={"secret": key})

        return FunctionModel(rejected, model_name=self.model_name)

    monkeypatch.setattr(GroqAdapter, "create_model", adapter_model)
    settings = prepared.model_copy(
        update={
            "agent_provider": AgentProvider.groq,
            "agent_model": "fixture-analyst",
            "agent_api_keys": (SecretStr("key-one"), SecretStr("key-two")),
        }
    )
    run = await investigate(settings, case)
    assert run.state is RunState.failed
    assert run.usage.provider_attempts == 1
    assert run.usage.key_rotations == 0
    assert "HTTP 401" in (run.incomplete_reason or "")
    assert "key-one" not in run.model_dump_json()
    assert "key-two" not in run.model_dump_json()


@pytest.mark.asyncio
async def test_run_exhausts_keys_as_incomplete_without_a_report(prepared, case, monkeypatch):
    def adapter_model(self, key: str):
        def limited(messages, info):
            raise ModelHTTPError(429, self.model_name, body={"error": key})

        return FunctionModel(limited, model_name=self.model_name)

    monkeypatch.setattr(GroqAdapter, "create_model", adapter_model)
    settings = prepared.model_copy(
        update={
            "agent_provider": AgentProvider.groq,
            "agent_model": "fixture-analyst",
            "agent_api_keys": (SecretStr("key-one"), SecretStr("key-two")),
        }
    )
    run = await investigate(settings, case)
    assert run.state is RunState.failed
    assert run.report is None
    assert run.usage.provider_attempts == 2
    assert run.usage.key_rotations == 1
    assert "keys exhausted" in (run.incomplete_reason or "")
    assert "key-one" not in run.model_dump_json()
    assert "key-two" not in run.model_dump_json()
