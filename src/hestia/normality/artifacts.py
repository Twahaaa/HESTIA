"""Trusted-local model artifacts bound to reproducible training metadata."""

from __future__ import annotations

import hashlib
import json
import platform
from base64 import b64decode, b64encode
from pathlib import Path
from typing import Self

import river
from pydantic import BaseModel, ConfigDict, Field, model_validator

from hestia.normality.features import FEATURE_SCHEMA_VERSION
from hestia.normality.models import ModelCompatibilityError
from hestia.normality.registry import (
    MODEL_REGISTRY,
    VerifiedModelBlob,
    _BehavioralModel,
    load_verified_model,
    serialize_model,
)


class TrainingArtifactMetadata(BaseModel):
    """Reproducibility and provenance metadata for one entity model."""

    model_config = ConfigDict(frozen=True)

    model_id: str
    entity_kind: str
    entity_id: str
    seed: int
    python_version: str
    river_version: str
    feature_schema_version: str
    training_hashes: tuple[str, ...]
    observation_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_hashes(self) -> Self:
        if not self.entity_id:
            raise ValueError("entity_id must not be empty")
        if len(set(self.training_hashes)) != len(self.training_hashes):
            raise ValueError("training_hashes must be unique")
        if any(
            len(item) != 64 or any(char not in "0123456789abcdef" for char in item)
            for item in self.training_hashes
        ):
            raise ValueError("training_hashes must be lowercase SHA-256 values")
        if self.observation_count != len(self.training_hashes):
            raise ValueError("observation_count must equal the number of training hashes")
        return self


class TrustedLocalModelArtifact(BaseModel):
    """Verified model bytes plus metadata protected by a deterministic digest."""

    model_config = ConfigDict(frozen=True)

    metadata: TrainingArtifactMetadata
    metadata_sha256: str
    model_blob: VerifiedModelBlob


def build_artifact(
    model: _BehavioralModel,
    *,
    model_id: str,
    entity_id: str,
    seed: int,
    training_hashes: tuple[str, ...],
) -> TrustedLocalModelArtifact:
    """Serialize manager-owned model state through the existing verified mechanism."""
    spec = MODEL_REGISTRY.get(model_id)
    if spec is None or spec.parent_model_id is not None:
        raise ModelCompatibilityError(f"Unknown parent model ID: {model_id!r}")
    metadata = TrainingArtifactMetadata(
        model_id=model_id,
        entity_kind=spec.entity_kind,
        entity_id=entity_id,
        seed=seed,
        python_version=platform.python_version(),
        river_version=river.__version__,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        training_hashes=training_hashes,
        observation_count=model.observation_count,
    )
    return TrustedLocalModelArtifact(
        metadata=metadata,
        metadata_sha256=_metadata_digest(metadata),
        model_blob=serialize_model(model, spec),
    )


def load_artifact(
    artifact: TrustedLocalModelArtifact,
    *,
    expected_metadata: TrainingArtifactMetadata | None = None,
) -> _BehavioralModel:
    """Reject envelope/runtime mismatches before loading trusted local bytes."""
    if not isinstance(artifact, TrustedLocalModelArtifact):
        raise TypeError("load_artifact accepts only a TrustedLocalModelArtifact")
    metadata = artifact.metadata
    if artifact.metadata_sha256 != _metadata_digest(metadata):
        raise ModelCompatibilityError("Training artifact metadata digest mismatch")
    if expected_metadata is not None and metadata != expected_metadata:
        raise ModelCompatibilityError("Training artifact metadata does not match expectation")
    spec = MODEL_REGISTRY.get(metadata.model_id)
    if spec is None or spec.parent_model_id is not None:
        raise ModelCompatibilityError(f"Unknown parent model ID: {metadata.model_id!r}")
    expected = {
        "entity_kind": spec.entity_kind,
        "python_version": platform.python_version(),
        "river_version": river.__version__,
        "feature_schema_version": spec.feature_schema_version,
    }
    for field_name, value in expected.items():
        if getattr(metadata, field_name) != value:
            raise ModelCompatibilityError(
                f"Training artifact has incompatible {field_name}: expected {value!r}"
            )
    registry_seed = spec.hyperparameters.get("seed")
    if registry_seed is not None and metadata.seed != registry_seed:
        raise ModelCompatibilityError("Training artifact seed does not match the registry")
    model = load_verified_model(artifact.model_blob, spec)
    if model.observation_count != metadata.observation_count:
        raise ModelCompatibilityError("Training artifact observation count mismatch")
    return model


def write_artifact(artifact: TrustedLocalModelArtifact, path: Path) -> None:
    """Atomically persist a trusted-local artifact in an explicit JSON envelope."""
    payload = artifact.model_dump(mode="python")
    payload["model_blob"]["blob"] = b64encode(artifact.model_blob.blob).decode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def read_artifact(path: Path) -> TrustedLocalModelArtifact:
    """Read and fully verify an artifact produced by :func:`write_artifact`."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    try:
        payload["model_blob"]["blob"] = b64decode(payload["model_blob"]["blob"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ModelCompatibilityError("Invalid model artifact envelope") from exc
    artifact = TrustedLocalModelArtifact.model_validate(payload)
    load_artifact(artifact)
    return artifact


def _metadata_digest(metadata: TrainingArtifactMetadata) -> str:
    payload = json.dumps(
        metadata.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "TrainingArtifactMetadata",
    "TrustedLocalModelArtifact",
    "build_artifact",
    "load_artifact",
    "read_artifact",
    "write_artifact",
]
