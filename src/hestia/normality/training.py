"""Deterministic, normal-only chronological training orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from hestia.normality.artifacts import TrustedLocalModelArtifact, build_artifact
from hestia.normality.features import FEATURE_SCHEMA_VERSION
from hestia.normality.inputs import model_input
from hestia.normality.models import SessionFeatures
from hestia.normality.registry import MODEL_REGISTRY, _create_model, _learn_model


@dataclass(frozen=True)
class NormalTrainingEligibility:
    """Explicit curation evidence required before a session can train a model."""

    eligible: bool
    normal: bool
    split: Literal["training", "validation", "test"]
    evidence_ref: str
    reason: str


@dataclass(frozen=True)
class TrainingObservation:
    """One visibly curated closed-session feature record."""

    started_at: datetime
    session_id: str
    user: str | None
    src_ip: str | None
    host: str | None
    features: SessionFeatures
    content_sha256: str
    eligibility: NormalTrainingEligibility


@dataclass(frozen=True)
class PrequentialTrainingScore:
    """Score emitted before the same observation is learned."""

    session_id: str
    model_id: str
    entity_id: str
    observation_count_before: int
    raw_score: float


@dataclass(frozen=True)
class TrainingResult:
    artifacts: tuple[TrustedLocalModelArtifact, ...]
    prequential_scores: tuple[PrequentialTrainingScore, ...]


def train_normal_models(
    observations: list[TrainingObservation] | tuple[TrainingObservation, ...],
    *,
    seed: int = 42,
    model_ids: tuple[str, ...] | None = None,
) -> TrainingResult:
    """Train per-entity models chronologically, always scoring before learning."""
    selected_ids = model_ids or tuple(
        model_id for model_id, spec in MODEL_REGISTRY.items() if spec.parent_model_id is None
    )
    for model_id in selected_ids:
        spec = MODEL_REGISTRY.get(model_id)
        if spec is None or spec.parent_model_id is not None:
            raise ValueError(f"Unknown parent model ID: {model_id!r}")
        registry_seed = spec.hyperparameters.get("seed")
        if registry_seed is not None and registry_seed != seed:
            raise ValueError(
                f"Seed {seed} does not match {model_id!r} registry seed {registry_seed}"
            )

    ordered = tuple(sorted(observations, key=lambda item: (item.started_at, item.session_id)))
    _validate_observations(ordered)
    models: dict[tuple[str, str], object] = {}
    hashes: dict[tuple[str, str], list[str]] = {}
    scores: list[PrequentialTrainingScore] = []

    for observation in ordered:
        for model_id in selected_ids:
            spec = MODEL_REGISTRY[model_id]
            entity_id = _entity_id(observation, spec.entity_kind)
            if entity_id is None:
                continue
            key = (model_id, entity_id)
            model = models.setdefault(key, _create_model(spec))
            value = model_input(model_id, observation.features)
            count_before = model.observation_count
            raw_score = _learn_model(model, spec, value)
            scores.append(
                PrequentialTrainingScore(
                    session_id=observation.session_id,
                    model_id=model_id,
                    entity_id=entity_id,
                    observation_count_before=count_before,
                    raw_score=raw_score,
                )
            )
            hashes.setdefault(key, []).append(observation.content_sha256)

    artifacts = tuple(
        build_artifact(
            models[key],
            model_id=key[0],
            entity_id=key[1],
            seed=seed,
            training_hashes=tuple(hashes[key]),
        )
        for key in sorted(models)
    )
    return TrainingResult(artifacts=artifacts, prequential_scores=tuple(scores))


def _validate_observations(observations: tuple[TrainingObservation, ...]) -> None:
    seen_sessions: set[str] = set()
    seen_hashes: set[str] = set()
    for observation in observations:
        eligibility = observation.eligibility
        if not eligibility.eligible or not eligibility.normal or eligibility.split != "training":
            raise ValueError(
                "Every training observation requires explicit normal training eligibility"
            )
        if not eligibility.evidence_ref or not eligibility.reason:
            raise ValueError("Training eligibility requires evidence_ref and reason")
        if observation.started_at.tzinfo is None:
            raise ValueError("Training timestamps must be timezone-aware")
        if observation.features.session_id != observation.session_id:
            raise ValueError("Training feature/session identity mismatch")
        if observation.features.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError("Training feature schema does not match the active schema")
        if len(observation.content_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in observation.content_sha256
        ):
            raise ValueError("Training content hashes must be lowercase SHA-256 values")
        if observation.session_id in seen_sessions or observation.content_sha256 in seen_hashes:
            raise ValueError("Duplicate sessions or content hashes cannot train twice")
        seen_sessions.add(observation.session_id)
        seen_hashes.add(observation.content_sha256)


def _entity_id(observation: TrainingObservation, entity_kind: str) -> str | None:
    return {
        "user": observation.user,
        "src_ip": observation.src_ip,
        "host": observation.host,
    }[entity_kind]


__all__ = [
    "NormalTrainingEligibility",
    "PrequentialTrainingScore",
    "TrainingObservation",
    "TrainingResult",
    "train_normal_models",
]
