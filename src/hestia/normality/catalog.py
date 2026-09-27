import json
from pathlib import Path

from hestia.normality.artifacts import load_artifact, read_artifact
from hestia.normality.registry import MODEL_REGISTRY


def list_models(artifact_root: Path | None = None) -> list[dict]:
    """Report readiness only from verified local artifact metadata."""
    artifacts_by_model: dict[str, list[dict]] = {}
    invalid_by_model: dict[str, int] = {}
    if artifact_root is not None:
        for path in sorted((artifact_root / "normality").glob("*--*.json")):
            try:
                artifact = read_artifact(path)
                model = load_artifact(artifact)
            except (OSError, ValueError, TypeError):
                model_id = path.name.split("--", 1)[0]
                invalid_by_model[model_id] = invalid_by_model.get(model_id, 0) + 1
                continue
            metadata = artifact.metadata
            spec = MODEL_REGISTRY[metadata.model_id]
            ready = metadata.observation_count >= spec.warmup_observations
            artifacts_by_model.setdefault(metadata.model_id, []).append(
                {
                    "entity_id": metadata.entity_id,
                    "observation_count": model.observation_count,
                    "ready": ready,
                    "reason": None
                    if ready
                    else (
                        f"warmup incomplete: {metadata.observation_count}/"
                        f"{spec.warmup_observations}"
                    ),
                    "training_hash_count": len(metadata.training_hashes),
                }
            )

    preparation_reason = _preparation_reason(artifact_root)
    result = []
    for spec in MODEL_REGISTRY.values():
        entities = sorted(
            artifacts_by_model.get(spec.model_id, []), key=lambda item: item["entity_id"]
        )
        if spec.parent_model_id is not None:
            reason = "parent model readiness is reported separately"
        elif invalid_by_model.get(spec.model_id):
            reason = "one or more artifacts failed verification"
        elif not entities:
            reason = preparation_reason or "no verified training artifact"
        elif not all(item["ready"] for item in entities):
            reason = "one or more entity models have incomplete warmup"
        else:
            reason = None
        ready = bool(entities) and reason is None
        result.append(
            {
                "model_id": spec.model_id,
                "primitive": spec.primitive,
                "entity_kind": spec.entity_kind,
                "warmup_observations": spec.warmup_observations,
                "parent_model_id": spec.parent_model_id,
                "status": "ready" if ready else "not_ready",
                "ready": ready,
                "readiness_reason": reason,
                "entities": entities,
            }
        )
    return result


def _preparation_reason(artifact_root: Path | None) -> str | None:
    if artifact_root is None:
        return None
    path = artifact_root / "preparation" / "readiness.json"
    if not path.is_file():
        return None
    try:
        reason = json.loads(path.read_text(encoding="utf-8")).get("reason")
    except (OSError, ValueError, TypeError):
        return None
    return reason if isinstance(reason, str) and reason else None
