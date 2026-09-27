"""Visibly synthetic mechanics tests for training, artifacts, and scoring."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hestia.normality.artifacts import load_artifact, read_artifact, write_artifact
from hestia.normality.catalog import list_models
from hestia.normality.models import (
    MaterializedFeatureContext,
    ModelCompatibilityError,
    SessionFeatures,
)
from hestia.normality.scoring import score_session
from hestia.normality.training import (
    NormalTrainingEligibility,
    TrainingObservation,
    train_normal_models,
)


def _synthetic_observation(index: int, *, eligible: bool = True) -> TrainingObservation:
    session_id = f"synthetic-session-{index:03d}"
    features = SessionFeatures(
        feature_schema_version="1",
        session_id=session_id,
        deployment_timezone="UTC",
        login_hour_utc=index % 24,
        login_hour_local=index % 24,
        hour_sin=0.0,
        hour_cos=1.0,
        auth_frequency_window_count=index,
        event_count=1,
        failure_count=0,
        failure_proportion=0.0,
        success_proportion=1.0,
        distinct_hosts_in_session=1,
        event_type_proportions=(("ssh_auth_success", 1.0),),
        event_types=("ssh_auth_success",),
        materialized_context=MaterializedFeatureContext(
            auth_frequency_window_count=index,
            distinct_users_for_src_ip=1,
            distinct_users_for_host=1,
            distinct_src_ips_for_host=1,
        ),
    )
    return TrainingObservation(
        started_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=index),
        session_id=session_id,
        user="synthetic-alice",
        src_ip="192.0.2.10",
        host="synthetic-host",
        features=features,
        content_sha256=hashlib.sha256(session_id.encode()).hexdigest(),
        eligibility=NormalTrainingEligibility(
            eligible=eligible,
            normal=True,
            split="training",
            evidence_ref=f"synthetic-eligibility:{session_id}",
            reason="synthetic mechanics fixture, not academic evaluation data",
        ),
    )


def test_training_is_explicitly_normal_chronological_and_score_before_learn() -> None:
    later = _synthetic_observation(2)
    earlier = _synthetic_observation(1)
    result = train_normal_models((later, earlier), model_ids=("auth_frequency",))

    assert [score.session_id for score in result.prequential_scores] == [
        earlier.session_id,
        later.session_id,
    ]
    assert [score.observation_count_before for score in result.prequential_scores] == [0, 1]
    assert result.artifacts[0].metadata.observation_count == 2
    assert result.artifacts[0].metadata.training_hashes == (
        earlier.content_sha256,
        later.content_sha256,
    )

    with pytest.raises(ValueError, match="explicit normal training eligibility"):
        train_normal_models((_synthetic_observation(3, eligible=False),))


def test_artifacts_are_reproducible_and_reject_metadata_mismatch() -> None:
    observations = tuple(_synthetic_observation(index) for index in range(3))
    first = train_normal_models(observations, model_ids=("auth_frequency",)).artifacts[0]
    second = train_normal_models(observations, model_ids=("auth_frequency",)).artifacts[0]

    assert first.metadata == second.metadata
    assert first.metadata_sha256 == second.metadata_sha256
    assert first.model_blob.sha256 == second.model_blob.sha256

    mismatched = first.model_copy(
        update={"metadata": first.metadata.model_copy(update={"entity_id": "synthetic-bob"})}
    )
    with pytest.raises(ModelCompatibilityError, match="metadata digest mismatch"):
        load_artifact(mismatched)


def test_artifact_file_round_trip_drives_entity_readiness(tmp_path: Path) -> None:
    observations = tuple(_synthetic_observation(index) for index in range(2))
    artifact = train_normal_models(observations, model_ids=("auth_frequency",)).artifacts[0]
    path = tmp_path / "normality" / "auth_frequency--fixture.json"
    write_artifact(artifact, path)

    assert read_artifact(path) == artifact
    model = next(item for item in list_models(tmp_path) if item["model_id"] == "auth_frequency")
    assert model["ready"] is True
    assert model["entities"] == [
        {
            "entity_id": "synthetic-alice",
            "observation_count": 2,
            "ready": True,
            "reason": None,
            "training_hash_count": 2,
        }
    ]


def test_scoring_is_immutable_and_cold_or_warming_models_return_null() -> None:
    observations = tuple(_synthetic_observation(index) for index in range(2))
    artifact = train_normal_models(observations, model_ids=("auth_frequency",)).artifacts[0]
    artifacts = {(artifact.metadata.model_id, artifact.metadata.entity_id): artifact}
    before = artifact.model_blob.sha256
    persisted = []

    candidate = score_session(
        _synthetic_observation(9).features,
        user="synthetic-alice",
        src_ip="192.0.2.10",
        host="synthetic-host",
        artifacts=artifacts,
        evidence_refs=("synthetic:event:9",),
        model_ids=("auth_frequency", "src_ip_behavior"),
        persist_candidate=persisted.append,
    )

    ready, cold = candidate.scores
    assert ready.ready is True
    assert ready.raw_score is not None
    assert ready.explanation is not None
    assert ready.evidence_refs == ("synthetic:event:9",)
    assert cold.ready is False
    assert cold.raw_score is None
    assert cold.reason == "no trained artifact"
    assert artifact.model_blob.sha256 == before
    assert persisted == [candidate]


def test_hst_warmup_remains_250_and_never_surfaces_warmup_zero_as_a_score() -> None:
    observations = tuple(_synthetic_observation(index) for index in range(249))
    artifact = train_normal_models(observations, model_ids=("src_ip_behavior",)).artifacts[0]
    candidate = score_session(
        _synthetic_observation(300).features,
        user="synthetic-alice",
        src_ip="192.0.2.10",
        host="synthetic-host",
        artifacts={("src_ip_behavior", "192.0.2.10"): artifact},
        evidence_refs=("synthetic:event:300",),
        model_ids=("src_ip_behavior",),
    )

    score = candidate.scores[0]
    assert score.warmup_observations == 250
    assert score.observation_count == 249
    assert score.raw_score is None
    assert score.reason == "warmup incomplete: 249/250"
