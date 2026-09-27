"""Provider resolution with no guessing and no silent fallback.

A missing or incomplete configuration is an explicit unavailable status, not a
default model and not a different provider. The fixture provider is local,
deterministic and labelled as a fixture wherever a run is stored or reported, so
a test run can never be mistaken for a hosted result.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from hestia.agent.budgets import BudgetLedger
from hestia.agent.rotation import RotatingModel
from hestia.config import AgentProvider, Settings


class ProviderUnavailable(RuntimeError):
    """The configured provider cannot be used, with an actionable reason."""


@dataclass(frozen=True)
class ProviderStatus:
    """What `GET /api/agent/status` and the CLI report without contacting anyone."""

    configured: bool
    provider: str | None
    model: str | None
    fixture: bool
    reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "provider": self.provider,
            "model": self.model,
            "fixture": self.fixture,
            "reason": self.reason,
        }


def provider_status(settings: Settings) -> ProviderStatus:
    """Describe provider readiness from configuration alone. Never calls out."""
    provider = settings.agent_provider
    if provider is None:
        return ProviderStatus(
            configured=False,
            provider=None,
            model=None,
            fixture=False,
            reason=(
                "no agent provider is configured; set HESTIA_AGENT_PROVIDER, "
                "HESTIA_AGENT_MODEL and HESTIA_AGENT_API_KEY or HESTIA_AGENT_API_KEYS, or run with "
                "--fixture-provider for a deterministic local investigation"
            ),
        )
    if provider is AgentProvider.fixture:
        return ProviderStatus(
            configured=True,
            provider=provider.value,
            model=settings.agent_model or "fixture",
            fixture=True,
            reason=None,
        )
    if not settings.agent_model:
        return ProviderStatus(
            configured=False,
            provider=provider.value,
            model=None,
            fixture=False,
            reason=(
                f"HESTIA_AGENT_MODEL is not set for provider {provider.value}; "
                "the model identifier is never guessed"
            ),
        )
    if not settings.agent_keys:
        return ProviderStatus(
            configured=False,
            provider=provider.value,
            model=settings.agent_model,
            fixture=False,
            reason=(
                f"HESTIA_AGENT_API_KEY or HESTIA_AGENT_API_KEYS is not set "
                f"for provider {provider.value}"
            ),
        )
    return ProviderStatus(
        configured=True,
        provider=provider.value,
        model=settings.agent_model,
        fixture=False,
        reason=None,
    )


@dataclass(frozen=True)
class GroqAdapter:
    model_name: str
    timeout_seconds: float

    def create_model(self, api_key: str):
        from groq import AsyncGroq
        from pydantic_ai.models.groq import GroqModel
        from pydantic_ai.providers.groq import GroqProvider

        # SDK defaults silently retry 429s. Disable that so *each* HTTP
        # attempt is accounted for by the outer run-wide request budget.
        client = AsyncGroq(api_key=api_key, timeout=self.timeout_seconds, max_retries=0)
        return GroqModel(self.model_name, provider=GroqProvider(groq_client=client))


@dataclass(frozen=True)
class OpenRouterAdapter:
    model_name: str
    timeout_seconds: float

    def create_model(self, api_key: str):
        from openai import AsyncOpenAI
        from pydantic_ai.models.openrouter import OpenRouterModel
        from pydantic_ai.providers.openrouter import OpenRouterProvider

        client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            timeout=self.timeout_seconds,
            max_retries=0,
        )
        return OpenRouterModel(self.model_name, provider=OpenRouterProvider(openai_client=client))


def build_model(
    settings: Settings,
    *,
    fixture_script: Sequence[Callable[..., Any]] | None = None,
    ledger: BudgetLedger | None = None,
):
    """Return a Pydantic AI model for the configured provider.

    Raises:
        ProviderUnavailable: when configuration is missing or a fixture run was
            requested without a script. The caller surfaces the reason; it never
            substitutes another provider.
    """
    status = provider_status(settings)
    if not status.configured:
        raise ProviderUnavailable(status.reason or "the agent provider is not configured")

    if status.fixture:
        if not fixture_script:
            raise ProviderUnavailable(
                "the fixture provider requires an explicit scripted response sequence"
            )
        from pydantic_ai.models.function import FunctionModel

        return FunctionModel(_scripted(fixture_script))

    provider = settings.agent_provider
    if provider is AgentProvider.groq:
        adapter = GroqAdapter(settings.agent_model, settings.agent_request_timeout_seconds)
    elif provider is AgentProvider.openrouter:
        adapter = OpenRouterAdapter(settings.agent_model, settings.agent_request_timeout_seconds)
    else:
        raise ProviderUnavailable(f"provider {provider!r} is not supported by this build")
    return RotatingModel(
        tuple(adapter.create_model(key) for key in settings.agent_keys),
        provider=provider.value,
        max_attempts=settings.agent_max_turns,
        before_attempt=ledger.check if ledger is not None else lambda: None,
    )


def _scripted(script: Sequence[Callable[..., Any]]) -> Callable[..., Any]:
    """Drive `FunctionModel` from an explicit list of response builders.

    Running past the end of a script is a test authoring error, so it raises
    rather than repeating the last response and hiding a broken expectation.
    """
    index = {"turn": 0}

    def respond(messages: Any, info: Any) -> Any:
        turn = index["turn"]
        if turn >= len(script):
            raise AssertionError(
                f"fixture script exhausted after {len(script)} responses; "
                "the agent asked for another turn"
            )
        index["turn"] = turn + 1
        return script[turn](messages, info)

    return respond


__all__ = [
    "GroqAdapter",
    "OpenRouterAdapter",
    "ProviderStatus",
    "ProviderUnavailable",
    "build_model",
    "provider_status",
]
