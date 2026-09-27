"""Client-side rate-limit pacing. Offline: fake clock, fake sleep, fake models."""

from __future__ import annotations

import httpx
import pytest
from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.usage import RequestUsage

from hestia.agent.budgets import BudgetExceeded
from hestia.agent.providers import GroqAdapter, _observing_client
from hestia.agent.ratelimit import (
    DEFAULT_COOLDOWN_SECONDS,
    KeyPacer,
    RateLimitPolicy,
    fingerprint,
    parse_duration,
    shared_pacer,
)
from hestia.agent.rotation import ProviderKeysExhausted, RotatingModel


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


KEYS = ("key-alpha", "key-beta")


def pacer(clock: Clock, **policy) -> KeyPacer:
    return KeyPacer(tuple(fingerprint(key) for key in KEYS), RateLimitPolicy(**policy), clock=clock)


class Scripted(Model):
    """Replays outcomes; a 429 first reports its headers, as the HTTP hook would."""

    def __init__(self, key: str, outcomes: list, observer: KeyPacer | None) -> None:
        super().__init__()
        self.key, self.outcomes, self.observer, self.calls = key, list(outcomes), observer, 0

    @property
    def model_name(self) -> str:
        return "fake-model"

    @property
    def system(self) -> str:
        return "groq"

    async def request(self, messages, model_settings, model_request_parameters):
        self.calls += 1
        outcome = self.outcomes.pop(0) if self.outcomes else ("ok", 1_000)
        kind, value = outcome
        if kind == "429":
            if self.observer is not None:
                headers = {} if value is None else {"retry-after": str(value)}
                self.observer.observe(self.key, 429, headers)
            raise ModelHTTPError(429, "fake-model", body={"error": self.key})
        return ModelResponse(
            parts=[TextPart(content="ok")],
            usage=RequestUsage(input_tokens=value, output_tokens=0),
        )


def rotating(models, clock, key_pacer, *, max_attempts=4, max_rate_limited=4, check=None):
    return RotatingModel(
        models,
        provider="groq",
        max_attempts=max_attempts,
        before_attempt=check or (lambda: None),
        pacer=key_pacer,
        max_rate_limited=max_rate_limited,
        sleep=clock.sleep,
    )


def test_parse_provider_durations():
    assert parse_duration("12") == 12
    assert parse_duration("7.66s") == pytest.approx(7.66)
    assert parse_duration("2m59.56s") == pytest.approx(179.56)
    assert parse_duration("1h2m3s") == 3723
    assert parse_duration("250ms") == pytest.approx(0.25)
    assert parse_duration("soon") is None
    assert parse_duration(None) is None


async def test_429_cools_the_key_and_does_not_spend_a_model_turn():
    clock = Clock()
    key_pacer = pacer(clock)
    first = Scripted(KEYS[0], [("429", 5)], key_pacer)
    second = Scripted(KEYS[1], [], key_pacer)
    model = rotating((first, second), clock, key_pacer, max_attempts=1, max_rate_limited=1)
    await model.request([], None, ModelRequestParameters())
    assert (first.calls, second.calls) == (1, 1)
    assert (model.attempts, model.rate_limited, model.key_rotations) == (2, 1, 1)
    assert model.rate_limit_wait_seconds == 0


async def test_single_key_waits_for_retry_after_then_reuses_the_key():
    clock = Clock()
    key_pacer = KeyPacer((fingerprint(KEYS[0]),), RateLimitPolicy(), clock=clock)
    only = Scripted(KEYS[0], [("429", 3)], key_pacer)
    model = rotating((only,), clock, key_pacer)
    await model.request([], None, ModelRequestParameters())
    assert only.calls == 2
    assert model.rate_limit_wait_seconds == pytest.approx(3.0)
    assert model.key_rotations == 0


async def test_wait_beyond_the_limit_ends_cleanly_without_another_request():
    clock = Clock()
    key_pacer = pacer(clock, max_wait_seconds=10)
    first = Scripted(KEYS[0], [("429", 30)], key_pacer)
    second = Scripted(KEYS[1], [("429", None)], key_pacer)
    model = rotating((first, second), clock, key_pacer)
    with pytest.raises(ProviderKeysExhausted, match="beyond the 10.0s wait") as error:
        await model.request([], None, ModelRequestParameters())
    assert (first.calls, second.calls) == (1, 1)
    assert "key-alpha" not in str(error.value) and "key-beta" not in str(error.value)
    assert DEFAULT_COOLDOWN_SECONDS > 10


async def test_rate_limited_allowance_is_bounded():
    clock = Clock()
    key_pacer = pacer(clock)
    first = Scripted(KEYS[0], [("429", 0)] * 10, key_pacer)
    second = Scripted(KEYS[1], [("429", 0)] * 10, key_pacer)
    model = rotating((first, second), clock, key_pacer, max_attempts=2, max_rate_limited=2)
    with pytest.raises(BudgetExceeded, match="rate_limit budget exhausted"):
        await model.request([], None, ModelRequestParameters())
    assert model.attempts == 4 and first.calls + second.calls == 4


async def test_token_window_switches_keys_before_the_provider_refuses():
    clock = Clock()
    key_pacer = pacer(clock, tokens_per_minute=5_000, max_wait_seconds=90)
    first = Scripted(KEYS[0], [("ok", 4_000), ("ok", 4_000)], key_pacer)
    second = Scripted(KEYS[1], [("ok", 4_000)], key_pacer)
    model = rotating((first, second), clock, key_pacer)
    await model.request([], None, ModelRequestParameters())
    await model.request([], None, ModelRequestParameters())
    # Key alpha has 4,000 of 5,000 used; a ~5,000-token request moves to beta.
    assert (first.calls, second.calls) == (1, 1)
    assert model.rate_limited == 0 and model.key_rotations == 1
    # Both keys now full and clear at the same moment: wait, keeping the current key.
    await model.request([], None, ModelRequestParameters())
    assert (first.calls, second.calls) == (1, 2)
    assert model.rate_limit_wait_seconds == pytest.approx(60.0)


def test_provider_headers_drive_headroom_and_daily_exhaustion():
    clock = Clock()
    key_pacer = pacer(clock)
    key_pacer.observe(
        KEYS[0],
        200,
        {
            "x-ratelimit-limit-tokens": "8000",
            "x-ratelimit-remaining-tokens": "500",
            "x-ratelimit-reset-tokens": "7.5s",
        },
    )
    assert key_pacer.choose(0, hint=2_000) == (1, 0.0)
    key_pacer.observe(
        KEYS[1],
        200,
        {"x-ratelimit-remaining-requests": "0", "x-ratelimit-reset-requests": "3h0m0s"},
    )
    # 7,500 tokens refill over 7.5 s (1,000/s): 1,500 more are needed.
    position, wait = key_pacer.choose(0, hint=2_000)
    assert position == 0 and wait == pytest.approx(1.5)
    key_pacer.observe("an-unknown-key", 429, {"retry-after": "5"})
    assert key_pacer.choose(0, hint=100) == (0, 0.0)


async def test_cancellation_is_checked_while_waiting():
    clock = Clock()
    key_pacer = KeyPacer((fingerprint(KEYS[0]),), RateLimitPolicy(), clock=clock)
    only = Scripted(KEYS[0], [("429", 5)], key_pacer)
    calls = {"n": 0}

    def check() -> None:
        calls["n"] += 1
        if clock.now >= 1_002:
            raise BudgetExceeded("cancellation", "operator stopped the case")

    model = rotating((only,), clock, key_pacer, check=check)
    with pytest.raises(BudgetExceeded, match="cancellation"):
        await model.request([], None, ModelRequestParameters())
    assert only.calls == 1


def test_shared_pacer_is_per_provider_model_and_key_set_without_storing_keys():
    policy = RateLimitPolicy()
    one = shared_pacer("groq", "m", KEYS, policy)
    assert shared_pacer("groq", "m", KEYS, policy) is one
    assert shared_pacer("groq", "other", KEYS, policy) is not one
    assert shared_pacer("groq", "m", KEYS[:1], policy) is not one
    assert not any(key in repr(vars(one)) for key in KEYS)


async def test_http_hook_reports_status_and_headers():
    seen: list[tuple[str, int, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"retry-after": "2"})

    client = _observing_client(
        lambda **kwargs: httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs),
        "key-alpha",
        lambda key, status, headers: seen.append((key, status, headers.get("retry-after"))),
    )
    await client.get("https://example.invalid/")
    await client.aclose()
    assert seen == [("key-alpha", 429, "2")]
    assert _observing_client(httpx.AsyncClient, "key-alpha", None) is None


async def test_groq_adapter_installs_the_hook_only_when_pacing():
    paced = GroqAdapter("m", 5, observe=lambda *args: None).create_model("placeholder")
    plain = GroqAdapter("m", 5).create_model("placeholder")
    assert paced.provider.client._client.event_hooks["response"]
    assert not plain.provider.client._client.event_hooks["response"]
    assert paced.provider.client.max_retries == 0
    await paced.provider.client.close()
    await plain.provider.client.close()


def test_reported_budget_replaces_the_local_window_and_refills():
    clock = Clock()
    key_pacer = pacer(clock, tokens_per_minute=8_000)
    # Locally the key looks full for a minute, but the provider says otherwise.
    key_pacer.record_success(0, 7_000)
    assert key_pacer.choose(0, hint=4_000)[0] == 1
    key_pacer.observe(
        KEYS[0],
        200,
        {
            "x-ratelimit-limit-tokens": "8000",
            "x-ratelimit-remaining-tokens": "2000",
            "x-ratelimit-reset-tokens": "45s",
        },
    )
    key_pacer.record_limited(1)  # beta cools for 60 s (no retry-after)
    # 6,000 tokens refill over 45 s (133.3/s): 2,000 more take 15 s.
    position, wait = key_pacer.choose(0, hint=4_000)
    assert position == 0 and wait == pytest.approx(15.0)
    clock.now += 15
    assert key_pacer.choose(0, hint=4_000) == (0, 0.0)


def test_snapshot_is_key_free_and_numeric():
    clock = Clock()
    key_pacer = pacer(clock)
    key_pacer.observe(
        KEYS[1],
        200,
        {
            "x-ratelimit-limit-tokens": "8000",
            "x-ratelimit-remaining-tokens": "6000",
            "x-ratelimit-reset-tokens": "15s",
            "x-ratelimit-remaining-requests": "990",
            "x-ratelimit-reset-requests": "1m26.4s",
        },
    )
    key_pacer.record_limited(0)
    snapshot = key_pacer.snapshot()
    assert snapshot[0]["cooling_seconds"] == DEFAULT_COOLDOWN_SECONDS
    assert snapshot[1]["provider_tokens_per_minute"] == 8_000
    assert snapshot[1]["tokens_remaining"] == 6_000
    assert snapshot[1]["seconds_to_token_reset"] == 15.0
    assert snapshot[1]["requests_remaining_today"] == 990
    assert not any(key in repr(snapshot) for key in KEYS)
