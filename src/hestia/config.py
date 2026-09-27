from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentProvider(StrEnum):
    """Providers this build knows how to talk to.

    ``fixture`` is a local deterministic model used by tests and demos. It never
    reaches the network and is always labelled as a fixture in stored runs.
    """

    groq = "groq"
    openrouter = "openrouter"
    fixture = "fixture"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HESTIA_", env_file=".env", extra="ignore")
    data_root: Path = Path("data")
    artifact_root: Path = Path("artifacts")
    frontend_dist: Path = Path("frontend/dist")
    mcp_max_page_size: int = 100
    mcp_default_page_size: int = 25
    mcp_max_result_bytes: int = 262_144
    mcp_max_snippet_chars: int = 2_000
    mcp_max_query_chars: int = 200
    mcp_tool_timeout_seconds: float = 30.0
    mcp_max_evidence_refs: int = 50

    # --- H3 hosted investigation agent -------------------------------------
    # Absent configuration is an explicit unavailable status, never a guess and
    # never a silent fallback to some other provider or model.
    agent_provider: AgentProvider | None = None
    agent_model: str = ""
    agent_api_key: SecretStr | None = None
    #: Alternative to agent_api_key: an ordered list of keys for the SAME
    #: provider and model. Never a cross-provider fallback.
    agent_api_keys: tuple[SecretStr, ...] = ()
    agent_max_turns: int = 8
    agent_max_tool_calls: int = 16
    agent_max_total_tokens: int = 120_000
    agent_max_wall_seconds: float = 180.0
    agent_max_retries: int = 2
    agent_request_timeout_seconds: float = 60.0
    agent_concurrency: int = 1
    #: Salt for local, reversible pseudonyms. Generated per deployment and kept
    #: local; it is never sent to a provider and never written to an export.
    agent_redaction_salt: SecretStr | None = None

    # --- H4 case workspace ---------------------------------------------------
    #: Delay before each scripted fixture turn, so a demo run can be watched in
    #: the workspace. Applies to fixture runs only; hosted runs are never paced.
    agent_fixture_pace_seconds: float = 0.0
    #: Recorded as the actor on a review disposition when the analyst gives none.
    #: There is no authentication in this build, so this is a label, not an identity.
    analyst_name: str = "local-analyst"

    @model_validator(mode="after")
    def validate_agent_keys(self) -> Settings:
        if self.agent_api_key is not None and self.agent_api_keys:
            raise ValueError("set either agent_api_key or agent_api_keys, not both")
        keys = self.agent_keys
        if len(keys) > 8 or len(set(keys)) != len(keys) or any(not key.strip() for key in keys):
            raise ValueError("agent keys must be nonempty, unique and limited to 8")
        return self

    @property
    def agent_keys(self) -> tuple[str, ...]:
        if self.agent_api_keys:
            return tuple(key.get_secret_value() for key in self.agent_api_keys)
        if self.agent_api_key is not None:
            return (self.agent_api_key.get_secret_value(),)
        return ()

    @field_validator("agent_fixture_pace_seconds")
    @classmethod
    def bound_fixture_pace(cls, value: float) -> float:
        if not 0 <= value <= 5:
            raise ValueError("agent_fixture_pace_seconds must be between 0 and 5")
        return value

    @field_validator("agent_concurrency")
    @classmethod
    def reject_parallel_cases(cls, value: int) -> int:
        """One active case per runtime. H3 deliberately has no queue service."""
        if value != 1:
            raise ValueError("agent_concurrency must be 1; H3 runs one case at a time")
        return value

    @field_validator(
        "agent_max_turns",
        "agent_max_tool_calls",
        "agent_max_total_tokens",
        "agent_max_retries",
    )
    @classmethod
    def reject_nonpositive_budget(cls, value: int) -> int:
        if value < 1:
            raise ValueError("agent budgets must be at least 1")
        return value

    @field_validator("agent_max_wall_seconds", "agent_request_timeout_seconds")
    @classmethod
    def reject_nonpositive_seconds(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("agent time budgets must be positive")
        return value

    @property
    def evidence_database(self) -> Path:
        return self.artifact_root / "evidence.sqlite3"

    @property
    def knowledge_index(self) -> Path:
        return self.artifact_root / "knowledge" / "reference-index.json"

    @property
    def attack_reference_root(self) -> Path:
        return self.data_root / "reference" / "attack"

    @property
    def demo_marker(self) -> Path:
        """Present only in a workspace created by `hestia demo-seed`."""
        return self.artifact_root / "demo-workspace.json"

    @property
    def redaction_map_root(self) -> Path:
        """Local-only pseudonym maps. Excluded from the source export."""
        return self.artifact_root / "cases"
