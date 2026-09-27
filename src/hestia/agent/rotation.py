"""One-provider, bounded key rotation at the model request boundary.

Only provider-specific, per-key limit failures can switch credentials. A key
is tried at most once after it hits a limit in a run; other HTTP errors and
our own run budgets never trigger rotation. Keys and provider response bodies
are absent from public diagnostics.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import asynccontextmanager
from typing import Any

from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.models.wrapper import WrapperModel
from pydantic_ai.settings import ModelSettings

from hestia.agent.budgets import BudgetExceeded


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
        self._index = 0
        self.attempts = 0
        self.key_rotations = 0

    def _attempt(self) -> Model:
        self._before_attempt()
        if self.attempts >= self._max_attempts:
            raise BudgetExceeded("requests", f"{self.attempts} provider attempts reached the limit")
        self.attempts += 1
        return self._models[self._index]

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
            model = self._attempt()
            try:
                return await model.request(messages, model_settings, model_request_parameters)
            except ModelHTTPError as error:
                self._advance(error)

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
            model = self._attempt()
            opened = False
            try:
                async with model.request_stream(
                    messages, model_settings, model_request_parameters, run_context
                ) as response:
                    opened = True
                    yield response
                    return
            except ModelHTTPError as error:
                if opened:
                    raise
                self._advance(error)
