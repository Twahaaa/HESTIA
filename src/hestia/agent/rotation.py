"""One-provider, bounded key rotation at the model request boundary.

Only provider-specific, per-key limit failures can switch credentials; other
HTTP errors and our own run budgets never trigger rotation. Keys and provider
response bodies are absent from public diagnostics.

Without a pacer, a key that hits a limit is not tried again in that run. With a
`KeyPacer`, keys are chosen by headroom before each request, a 429 cools the key
down for the provider's ``retry-after`` (it may be used again later), waits are
bounded, and rate-limited responses have their own attempt budget so they do not
consume the model's turns.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from typing import Any

from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.models.wrapper import WrapperModel
from pydantic_ai.settings import ModelSettings

from hestia.agent.budgets import BudgetExceeded
from hestia.agent.ratelimit import KeyPacer


class ProviderKeysExhausted(RuntimeError):
    """Every configured key for this provider hit a rotatable limit."""


def rotatable_limit(provider: str, error: ModelHTTPError) -> bool:
    if error.status_code == 429:
        return True
    # OpenRouter distinguishes a per-key credit cap from account-wide credits
    # and in-flight spending. Only the former can be solved with another key.
    if provider != "openrouter" or error.status_code != 402:
        return False
    body = error.body
    if not isinstance(body, dict) or not isinstance(body.get("error"), dict):
        return False
    metadata = body["error"].get("metadata")
    return isinstance(metadata, dict) and metadata.get("limit_source") == "openrouter_key_limit"


class RotatingModel(WrapperModel):
    """Same provider/model on each key; one cumulative attempt budget per run."""

    def __init__(
        self,
        models: Sequence[Model],
        *,
        provider: str,
        max_attempts: int,
        before_attempt: Callable[[], None],
        pacer: KeyPacer | None = None,
        max_rate_limited: int = 0,
        remaining_seconds: Callable[[], float] | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if not models or max_attempts < 1:
            raise ValueError("at least one model and one provider attempt are required")
        if any(model.model_id != models[0].model_id for model in models[1:]):
            raise ValueError("key rotation cannot switch model or provider")
        super().__init__(models[0])
        self._models = tuple(models)
        self._provider = provider
        self._max_attempts = max_attempts
        self._before_attempt = before_attempt
        self._pacer = pacer
        self._max_rate_limited = max_rate_limited if pacer is not None else 0
        self._remaining_seconds = remaining_seconds or (lambda: math.inf)
        self._sleep = sleep
        self._index = 0
        self._last_tokens: int | None = None
        #: Every HTTP attempt, including rate-limited ones.
        self.attempts = 0
        self.key_rotations = 0
        self.rate_limited = 0
        self.rate_limit_wait_seconds = 0.0

    def _check_ceilings(self) -> None:
        turns = self.attempts - self.rate_limited
        if turns >= self._max_attempts:
            raise BudgetExceeded("requests", f"{turns} provider attempts reached the limit")
        if self.attempts >= self._max_attempts + self._max_rate_limited:
            raise BudgetExceeded(
                "rate_limit",
                f"{self.rate_limited} rate-limited responses used the allowance of "
                f"{self._max_rate_limited}",
            )

    async def _paced(self) -> None:
        """Pick the key with headroom, waiting a bounded time if none has any."""
        assert self._pacer is not None
        hint = None if self._last_tokens is None else int(self._last_tokens * 1.25)
        position, wait = self._pacer.choose(self._index, hint)
        allowed = min(self._pacer.policy.max_wait_seconds, self._remaining_seconds())
        if wait > allowed:
            raise ProviderKeysExhausted(
                f"{self._provider} keys exhausted for now: the next key has headroom in "
                f"{wait:.1f}s, beyond the {allowed:.1f}s wait allowed; no other provider "
                "was tried"
            )
        while wait > 0:
            step = min(wait, 1.0)
            await self._sleep(step)
            self.rate_limit_wait_seconds += step
            wait -= step
            self._before_attempt()
        if position != self._index:
            self._index = position
            self.key_rotations += 1

    async def _attempt(self) -> Model:
        self._before_attempt()
        self._check_ceilings()
        if self._pacer is not None:
            await self._paced()
        self.attempts += 1
        return self._models[self._index]

    def _succeeded(self, response: ModelResponse | None) -> None:
        if self._pacer is None:
            return
        usage = getattr(response, "usage", None)
        tokens = int(getattr(usage, "input_tokens", 0) or 0) + int(
            getattr(usage, "output_tokens", 0) or 0
        )
        if response is None or tokens <= 0:
            tokens = self._pacer.estimate(self._index)
        self._last_tokens = tokens
        self._pacer.record_success(self._index, tokens)

    def __repr__(self) -> str:
        return (
            f"RotatingModel(provider={self._provider!r}, model={self.model_name!r}, "
            f"attempts={self.attempts}, key_rotations={self.key_rotations})"
        )

    async def aclose(self) -> None:
        """Close all SDK clients created for this single case run."""
        for model in self._models:
            provider = model.provider
            if provider is not None:
                await provider.client.close()

    def _advance(self, error: ModelHTTPError) -> None:
        if not rotatable_limit(self._provider, error):
            raise error
        if self._pacer is not None:
            # The next attempt picks a key by headroom; this one cools down.
            if error.status_code == 429:
                self.rate_limited += 1
                self._pacer.record_limited(self._index)
            else:
                self._pacer.retire(self._index)
            return
        if self._index + 1 >= len(self._models):
            raise ProviderKeysExhausted(
                f"{self._provider} keys exhausted after {self.attempts} limit response(s) "
                f"(HTTP {error.status_code}); no other provider was tried"
            ) from None
        self._index += 1
        self.key_rotations += 1

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        while True:
            model = await self._attempt()
            try:
                response = await model.request(messages, model_settings, model_request_parameters)
            except ModelHTTPError as error:
                self._advance(error)
                continue
            self._succeeded(response)
            return response

    @asynccontextmanager
    async def request_stream(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
        run_context: Any = None,
    ):
        """Rotate only if opening the stream fails, never after partial output."""
        while True:
            model = await self._attempt()
            opened = False
            try:
                async with model.request_stream(
                    messages, model_settings, model_request_parameters, run_context
                ) as response:
                    opened = True
                    yield response
                    self._succeeded(None)
                    return
            except ModelHTTPError as error:
                if opened:
                    raise
                self._advance(error)
