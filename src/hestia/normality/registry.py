"""Fixed behavioral model registry and trusted local BLOB persistence."""

from __future__ import annotations

import hashlib
import json
import math
import pickle
import platform
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

import river
from pydantic import BaseModel, ConfigDict, StrictBytes
from river import anomaly, compose, drift, preprocessing

from hestia.normality.features import FEATURE_SCHEMA_VERSION
from hestia.normality.models import ModelCompatibilityError
from hestia.normality.transitions import TransitionModel

_GLOBAL_ENTITY_KEY = "__global__"


@dataclass(frozen=True)
class ModelSpec:
    """Immutable compatibility contract for one named behavioral primitive."""

    model_id: str
    entity_kind: str
    primitive: str
    feature_names: tuple[str, ...]
    feature_schema_version: str
    hyperparameters: Mapping[str, int | float | str]
    warmup_observations: int
    parent_model_id: str | None = None


class VerifiedModelBlob(BaseModel):
    """Manager-produced bytes accompanied by pre-deserialization trust metadata."""

    model_config = ConfigDict(frozen=True)

    sha256: str
    python_version: str
    river_version: str
    class_path: str
    registry_id: str
    feature_schema_version: str
    hyperparameters_json: str
    blob: StrictBytes


class CircularHourCounts:
    """Deterministic circular-hour categorical counts with Laplace smoothing."""

    def __init__(self, *, alpha: float = 1.0) -> None:
        self.alpha = alpha
        self.counts: Counter[int] = Counter()
        self.total = 0

    def score_one(self, hour: int) -> float:
        """Return unrounded negative log probability for a UTC/local hour bin."""
        if not 0 <= hour <= 23:
            raise ValueError("Login hour must be in [0, 23]")
        return -math.log((self.counts[hour] + self.alpha) / (self.total + 24 * self.alpha))

    def learn_one(self, hour: int) -> None:
        """Increment one hour bin."""
        if not 0 <= hour <= 23:
            raise ValueError("Login hour must be in [0, 23]")
        self.counts[hour] += 1
        self.total += 1


@dataclass
class _BehavioralModel:
    """Private mutable estimator plus drift and learning provenance."""

    estimator: Any
    drift_detector: drift.ADWIN
    observation_count: int = 0
    drift_detection_count: int = 0
    drift_since: int | None = None
    drift_observations: list[int] = field(default_factory=list)


def _spec(
    model_id: str,
    entity_kind: str,
    primitive: str,
    feature_names: tuple[str, ...],
    hyperparameters: Mapping[str, int | float | str],
    *,
    warmup: int = 2,
    parent_model_id: str | None = None,
) -> ModelSpec:
    return ModelSpec(
        model_id=model_id,
        entity_kind=entity_kind,
        primitive=primitive,
        feature_names=feature_names,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        hyperparameters=MappingProxyType(dict(hyperparameters)),
        warmup_observations=warmup,
        parent_model_id=parent_model_id,
    )


_PARENTS = {
    "login_hour_rarity": _spec(
        "login_hour_rarity", "user", "CircularHourCounts", ("login_hour_local",), {"alpha": 1.0}
    ),
    "auth_frequency": _spec(
        "auth_frequency",
        "user",
        "StandardAbsoluteDeviation",
        ("auth_frequency_window_count",),
        {},
    ),
    "src_ip_behavior": _spec(
        "src_ip_behavior",
        "src_ip",
        "MinMaxScaler|HalfSpaceTrees",
        (
            "failure_proportion",
            "success_proportion",
            "distinct_hosts_in_session",
            "distinct_users_for_src_ip",
            "hour_sin",
            "hour_cos",
        ),
        {"n_trees": 10, "height": 8, "window_size": 250, "seed": 42},
        warmup=250,
    ),
    "host_access": _spec(
        "host_access",
        "host",
        "MinMaxScaler|HalfSpaceTrees",
        (
            "failure_proportion",
            "success_proportion",
            "event_count",
            "distinct_users_for_host",
            "distinct_src_ips_for_host",
            "hour_sin",
            "hour_cos",
        ),
        {"n_trees": 10, "height": 8, "window_size": 250, "seed": 42},
        warmup=250,
    ),
    "transition_surprise": _spec(
        "transition_surprise",
        "user",
        "TransitionModel",
        ("event_types",),
        {"alpha": 1.0},
    ),
}
_DRIFT = {
    f"{model_id}_drift": _spec(
        f"{model_id}_drift",
        spec.entity_kind,
        "ADWIN",
        ("parent_score",),
        {"delta": 0.002, "clock": 32, "max_buckets": 5, "min_window_length": 5, "grace_period": 10},
        parent_model_id=model_id,
    )
    for model_id, spec in _PARENTS.items()
}
MODEL_REGISTRY: Mapping[str, ModelSpec] = MappingProxyType({**_PARENTS, **_DRIFT})


def _create_model(spec: ModelSpec) -> _BehavioralModel:
    """Construct one private seeded model exactly from its registry specification."""
    if MODEL_REGISTRY.get(spec.model_id) != spec or spec.parent_model_id is not None:
        raise ModelCompatibilityError(f"Unknown or non-parent model ID: {spec.model_id!r}")
    if spec.primitive == "CircularHourCounts":
        estimator: Any = CircularHourCounts(alpha=float(spec.hyperparameters["alpha"]))
    elif spec.primitive == "StandardAbsoluteDeviation":
        estimator = anomaly.StandardAbsoluteDeviation()
    elif spec.primitive == "MinMaxScaler|HalfSpaceTrees":
        estimator = compose.Pipeline(
            preprocessing.MinMaxScaler(),
            anomaly.HalfSpaceTrees(**dict(spec.hyperparameters)),
        )
    elif spec.primitive == "TransitionModel":
        estimator = TransitionModel(alpha=float(spec.hyperparameters["alpha"]))
    else:
        raise ModelCompatibilityError(f"Unsupported registry primitive: {spec.primitive!r}")
    return _BehavioralModel(estimator=estimator, drift_detector=drift.ADWIN(**_adwin_parameters()))


def _score_model(model: _BehavioralModel, spec: ModelSpec, value: object) -> float:
    """Return a pre-update parent score without mutating model state."""
    if spec.primitive == "CircularHourCounts":
        return float(model.estimator.score_one(value))
    if spec.primitive == "StandardAbsoluteDeviation":
        score = float(model.estimator.score_one(None, float(value)))
        return score if math.isfinite(score) else 0.0
    if spec.primitive == "MinMaxScaler|HalfSpaceTrees":
        return float(model.estimator.score_one(_bounded_vector(spec, value)))
    if spec.primitive == "TransitionModel":
        transition_score = model.estimator.score(tuple(value))
        return transition_score.mean_negative_log_probability or 0.0
    raise ModelCompatibilityError(f"Unsupported registry primitive: {spec.primitive!r}")


def _learn_model(model: _BehavioralModel, spec: ModelSpec, value: object) -> float:
    """Score, update drift metadata, then learn while retaining parent history."""
    score = _score_model(model, spec, value)
    model.drift_detector.update(score)
    if model.drift_detector.drift_detected:
        model.drift_detection_count += 1
        model.drift_since = model.observation_count + 1
        model.drift_observations.append(model.observation_count + 1)
    if spec.primitive == "CircularHourCounts":
        model.estimator.learn_one(value)
    elif spec.primitive == "StandardAbsoluteDeviation":
        model.estimator.learn_one(None, float(value))
    elif spec.primitive == "MinMaxScaler|HalfSpaceTrees":
        model.estimator.learn_one(_bounded_vector(spec, value))
    elif spec.primitive == "TransitionModel":
        model.estimator.learn(tuple(value))
    else:
        raise ModelCompatibilityError(f"Unsupported registry primitive: {spec.primitive!r}")
    model.observation_count += 1
    return score


def serialize_model(model: _BehavioralModel, spec: ModelSpec) -> VerifiedModelBlob:
    """Serialize manager-owned state with complete deterministic compatibility metadata."""
    _require_registered_spec(spec)
    payload = pickle.dumps(model, protocol=pickle.HIGHEST_PROTOCOL)
    return VerifiedModelBlob(
        sha256=hashlib.sha256(payload).hexdigest(),
        python_version=platform.python_version(),
        river_version=river.__version__,
        class_path=_expected_class_path(spec),
        registry_id=spec.model_id,
        feature_schema_version=spec.feature_schema_version,
        hyperparameters_json=_hyperparameters_json(spec),
        blob=payload,
    )


def load_verified_model(blob: VerifiedModelBlob, spec: ModelSpec) -> _BehavioralModel:
    """Verify trusted local bytes and all metadata before invoking the unpickler."""
    if not isinstance(blob, VerifiedModelBlob):
        raise TypeError("load_verified_model accepts only a VerifiedModelBlob, never a path")
    _require_registered_spec(spec)
    expected = {
        "sha256": hashlib.sha256(blob.blob).hexdigest(),
        "python_version": platform.python_version(),
        "river_version": river.__version__,
        "class_path": _expected_class_path(spec),
        "registry_id": spec.model_id,
        "feature_schema_version": spec.feature_schema_version,
        "hyperparameters_json": _hyperparameters_json(spec),
    }
    for field_name, expected_value in expected.items():
        if getattr(blob, field_name) != expected_value:
            raise ModelCompatibilityError(
                f"Model {spec.model_id!r} has incompatible {field_name}: "
                f"expected {expected_value!r}"
            )
    loaded = pickle.loads(blob.blob)
    if not isinstance(loaded, _BehavioralModel) or _class_path(loaded.estimator) != blob.class_path:
        raise ModelCompatibilityError(
            f"Model {spec.model_id!r} deserialized to an incompatible class"
        )
    return loaded


def _bounded_vector(spec: ModelSpec, value: object) -> dict[str, float]:
    if not isinstance(value, Mapping) or set(value) != set(spec.feature_names):
        raise ValueError(f"{spec.model_id} requires fixed features {spec.feature_names!r}")
    vector = {name: float(value[name]) for name in spec.feature_names}
    if any(not math.isfinite(item) for item in vector.values()):
        raise ValueError("Behavioral model features must be finite")
    return vector


def _adwin_parameters() -> dict[str, int | float]:
    return dict(MODEL_REGISTRY["auth_frequency_drift"].hyperparameters)


def _require_registered_spec(spec: ModelSpec) -> None:
    if MODEL_REGISTRY.get(spec.model_id) != spec or spec.parent_model_id is not None:
        raise ModelCompatibilityError(f"Unknown model registry ID: {spec.model_id!r}")


def _hyperparameters_json(spec: ModelSpec) -> str:
    return json.dumps(dict(spec.hyperparameters), sort_keys=True, separators=(",", ":"))


def _class_path(value: object) -> str:
    return f"{type(value).__module__}.{type(value).__qualname__}"


def _expected_class_path(spec: ModelSpec) -> str:
    expected = {
        "CircularHourCounts": f"{__name__}.CircularHourCounts",
        "StandardAbsoluteDeviation": "river.anomaly.sad.StandardAbsoluteDeviation",
        "MinMaxScaler|HalfSpaceTrees": "river.compose.pipeline.Pipeline",
        "TransitionModel": "hestia.normality.transitions.TransitionModel",
    }
    return expected[spec.primitive]


__all__ = ["MODEL_REGISTRY", "ModelSpec", "load_verified_model", "serialize_model"]
