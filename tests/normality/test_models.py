"""Behavior tests for the fixed River registry and trusted model blobs."""

from __future__ import annotations

import math
import pickle

import pytest
from pydantic import ValidationError
from river import anomaly, compose, drift, preprocessing

from hestia.normality.features import FEATURE_SCHEMA_VERSION
from hestia.normality.models import ModelCompatibilityError
from hestia.normality.registry import (
    MODEL_REGISTRY,
    ModelSpec,
    _create_model,
    _learn_model,
    _score_model,
    load_verified_model,
    serialize_model,
)


def test_fixed_registry_names_primitives_entities_and_hyperparameters() -> None:
    parents = {
        "login_hour_rarity",
        "auth_frequency",
        "src_ip_behavior",
        "host_access",
        "transition_surprise",
    }
    assert parents.issubset(MODEL_REGISTRY)
    assert {f"{model_id}_drift" for model_id in parents}.issubset(MODEL_REGISTRY)

    assert MODEL_REGISTRY["login_hour_rarity"].primitive == "CircularHourCounts"
    assert MODEL_REGISTRY["auth_frequency"].primitive == "StandardAbsoluteDeviation"
    assert MODEL_REGISTRY["src_ip_behavior"].primitive == "MinMaxScaler|HalfSpaceTrees"
    assert MODEL_REGISTRY["host_access"].primitive == "MinMaxScaler|HalfSpaceTrees"
    assert MODEL_REGISTRY["transition_surprise"].primitive == "TransitionModel"
    assert all(MODEL_REGISTRY[f"{model_id}_drift"].primitive == "ADWIN" for model_id in parents)
    assert MODEL_REGISTRY["login_hour_rarity"].entity_kind == "user"
    assert MODEL_REGISTRY["src_ip_behavior"].entity_kind == "src_ip"
    assert MODEL_REGISTRY["host_access"].entity_kind == "host"
    assert MODEL_REGISTRY["src_ip_behavior"].hyperparameters["seed"] == 42
    assert MODEL_REGISTRY["src_ip_behavior"].feature_schema_version == FEATURE_SCHEMA_VERSION

    assert isinstance(
        _create_model(MODEL_REGISTRY["auth_frequency"]).estimator,
        anomaly.StandardAbsoluteDeviation,
    )
    src_model = _create_model(MODEL_REGISTRY["src_ip_behavior"])
    assert isinstance(src_model.estimator, compose.Pipeline)
    assert isinstance(src_model.estimator[0], preprocessing.MinMaxScaler)
    assert isinstance(src_model.estimator[1], anomaly.HalfSpaceTrees)
    assert isinstance(src_model.drift_detector, drift.ADWIN)


def test_score_then_learn_and_drift_preserve_parent_history() -> None:
    spec = MODEL_REGISTRY["auth_frequency"]
    model = _create_model(spec)
    before = _score_model(model, spec, 10.0)
    _learn_model(model, spec, 10.0)
    after_one = model.observation_count
    _learn_model(model, spec, 100.0)

    assert before >= 0.0
    assert after_one == 1
    assert model.observation_count == 2
    assert model.drift_detection_count >= 0
    assert model.estimator is not None


def test_verified_blob_rejects_every_mismatch_before_unpickle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = MODEL_REGISTRY["auth_frequency"]
    blob = serialize_model(_create_model(spec), spec)
    calls = 0

    def forbidden_loads(_payload: bytes) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("pickle.loads must not run before metadata verification")

    monkeypatch.setattr(pickle, "loads", forbidden_loads)
    mutations = (
        {"sha256": "0" * 64},
        {"python_version": "0.0.0"},
        {"river_version": "0.0.0"},
        {"class_path": "builtins.object"},
        {"registry_id": "unknown"},
        {"feature_schema_version": "999"},
        {"hyperparameters_json": '{"unexpected":true}'},
    )
    for mutation in mutations:
        with pytest.raises(ModelCompatibilityError):
            load_verified_model(blob.model_copy(update=mutation), spec)
    assert calls == 0


def test_verified_blob_round_trip_and_api_has_no_path_surface() -> None:
    spec = MODEL_REGISTRY["transition_surprise"]
    model = _create_model(spec)
    _learn_model(model, spec, ("ssh_auth_success", "sudo_command"))
    blob = serialize_model(model, spec)
    loaded = load_verified_model(blob, spec)

    expected = _score_model(model, spec, ("ssh_auth_success", "sudo_command"))
    actual = _score_model(loaded, spec, ("ssh_auth_success", "sudo_command"))
    assert actual == expected
    assert math.isfinite(actual)
    with pytest.raises((TypeError, ValidationError)):
        load_verified_model("/tmp/untrusted.pkl", spec)  # type: ignore[arg-type]


def test_unknown_registry_ids_fail_closed() -> None:
    with pytest.raises(TypeError):
        MODEL_REGISTRY["new"] = ModelSpec(  # type: ignore[index]
            model_id="new",
            entity_kind="user",
            primitive="unknown",
            feature_names=(),
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            hyperparameters={},
            warmup_observations=1,
        )
