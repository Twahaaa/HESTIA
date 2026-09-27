"""Immutable evaluation scoring with explicit readiness abstention."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from hestia.normality.artifacts import TrustedLocalModelArtifact, load_artifact
from hestia.normality.inputs import model_input
from hestia.normality.models import SessionFeatures
from hestia.normality.registry import MODEL_REGISTRY, _score_model


@dataclass(frozen=True)
class ModelScore:
    model_id: str
    entity_kind: str
    entity_id: str | None
    ready: bool
    raw_score: float | None
    reason: str | None
    explanation: str | None
    evidence_refs: tuple[str, ...]
    observation_count: int
    warmup_observations: int


@dataclass(frozen=True)
class CandidateSession:
    """Prioritization evidence only; this contract deliberately carries no verdict."""

    session_id: str
    scores: tuple[ModelScore, ...]
    evidence_refs: tuple[str, ...]


CandidatePersistence = Callable[[CandidateSession], None]


def score_session(
    features: SessionFeatures,
    *,
    user: str | None,
    src_ip: str | None,
    host: str | None,
    artifacts: Mapping[tuple[str, str], TrustedLocalModelArtifact],
    evidence_refs: tuple[str, ...],
    model_ids: tuple[str, ...] | None = None,
    persist_candidate: CandidatePersistence | None = None,
) -> CandidateSession:
    """Score without learning; unavailable or warming models return a null score."""
    selected_ids = model_ids or tuple(
        model_id for model_id, spec in MODEL_REGISTRY.items() if spec.parent_model_id is None
    )
    entities = {"user": user, "src_ip": src_ip, "host": host}
    scores: list[ModelScore] = []
    stable_refs = tuple(sorted(set(evidence_refs)))

    for model_id in selected_ids:
        spec = MODEL_REGISTRY.get(model_id)
        if spec is None or spec.parent_model_id is not None:
            raise ValueError(f"Unknown parent model ID: {model_id!r}")
        entity_id = entities[spec.entity_kind]
        artifact = artifacts.get((model_id, entity_id)) if entity_id is not None else None
        if entity_id is None:
            scores.append(
                _unready(
                    model_id,
                    spec.entity_kind,
                    None,
                    spec.warmup_observations,
                    "entity identity is unavailable",
                    stable_refs,
                )
            )
            continue
        if artifact is None:
            scores.append(
                _unready(
                    model_id,
                    spec.entity_kind,
                    entity_id,
                    spec.warmup_observations,
                    "no trained artifact",
                    stable_refs,
                )
            )
            continue
        if artifact.metadata.model_id != model_id or artifact.metadata.entity_id != entity_id:
            raise ValueError("Artifact lookup key does not match artifact metadata")
        model = load_artifact(artifact)
        count = model.observation_count
        if count < spec.warmup_observations:
            scores.append(
                ModelScore(
                    model_id=model_id,
                    entity_kind=spec.entity_kind,
                    entity_id=entity_id,
                    ready=False,
                    raw_score=None,
                    reason=f"warmup incomplete: {count}/{spec.warmup_observations}",
                    explanation=None,
                    evidence_refs=stable_refs,
                    observation_count=count,
                    warmup_observations=spec.warmup_observations,
                )
            )
            continue
        raw_score = _score_model(model, spec, model_input(model_id, features))
        scores.append(
            ModelScore(
                model_id=model_id,
                entity_kind=spec.entity_kind,
                entity_id=entity_id,
                ready=True,
                raw_score=raw_score,
                reason=None,
                explanation=(
                    f"{model_id} scored {spec.entity_kind} {entity_id!r} from "
                    f"{', '.join(spec.feature_names)} after {count} normal observations"
                ),
                evidence_refs=stable_refs,
                observation_count=count,
                warmup_observations=spec.warmup_observations,
            )
        )

    candidate = CandidateSession(
        session_id=features.session_id,
        scores=tuple(scores),
        evidence_refs=stable_refs,
    )
    if persist_candidate is not None:
        persist_candidate(candidate)
    return candidate


def _unready(
    model_id: str,
    entity_kind: str,
    entity_id: str | None,
    warmup: int,
    reason: str,
    evidence_refs: tuple[str, ...],
) -> ModelScore:
    return ModelScore(
        model_id=model_id,
        entity_kind=entity_kind,
        entity_id=entity_id,
        ready=False,
        raw_score=None,
        reason=reason,
        explanation=None,
        evidence_refs=evidence_refs,
        observation_count=0,
        warmup_observations=warmup,
    )


__all__ = ["CandidatePersistence", "CandidateSession", "ModelScore", "score_session"]
