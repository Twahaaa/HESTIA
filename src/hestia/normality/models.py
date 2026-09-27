"""Data-only behavioral feature contracts, independent of persistence."""

from pydantic import BaseModel, ConfigDict, Field


class ModelCompatibilityError(ValueError):
    """A saved model does not match the active implementation."""


class MaterializedFeatureContext(BaseModel):
    """Explicit historical counts supplied to pure Session feature extraction."""

    model_config = ConfigDict(frozen=True)

    deployment_timezone: str = "UTC"
    auth_frequency_window_count: int = Field(default=0, ge=0)
    user_first_seen: bool = True
    src_ip_first_seen: bool = True
    host_first_seen: bool = True
    user_observation_count: int = Field(default=0, ge=0)
    src_ip_observation_count: int = Field(default=0, ge=0)
    host_observation_count: int = Field(default=0, ge=0)
    distinct_hosts_for_user: int = Field(default=0, ge=0)
    distinct_users_for_src_ip: int = Field(default=0, ge=0)
    distinct_users_for_host: int = Field(default=0, ge=0)
    distinct_src_ips_for_host: int = Field(default=0, ge=0)


class SessionFeatures(BaseModel):
    """Immutable, versioned deterministic features for one closed Session."""

    model_config = ConfigDict(frozen=True)

    feature_schema_version: str
    session_id: str
    deployment_timezone: str
    login_hour_utc: int = Field(ge=0, le=23)
    login_hour_local: int = Field(ge=0, le=23)
    hour_sin: float
    hour_cos: float
    auth_frequency_window_count: int = Field(ge=0)
    event_count: int = Field(ge=1)
    failure_count: int = Field(ge=0)
    failure_proportion: float = Field(ge=0.0, le=1.0)
    success_proportion: float = Field(ge=0.0, le=1.0)
    distinct_hosts_in_session: int = Field(ge=1)
    event_type_proportions: tuple[tuple[str, float], ...]
    event_types: tuple[str, ...]
    materialized_context: MaterializedFeatureContext
