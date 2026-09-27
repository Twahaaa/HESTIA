"""Frozen evaluation inputs and an explicit case ground-truth policy."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Truth(StrEnum):
    attack = "attack"
    normal = "normal"
    unknown = "unknown"


class EventLabel(BaseModel):
    """One reviewed event annotation; absent rows mean unknown, never normal."""

    model_config = ConfigDict(frozen=True)
    event_id: str = Field(min_length=1)
    dataset_id: str = Field(min_length=1)
    source_path: str = Field(min_length=1)
    line_no: int = Field(ge=1)
    truth: Truth
    annotation_source: str = Field(min_length=1)


class EvaluationConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    schema_version: int = 1
    split_manifests: tuple[str, ...] = ()
    labels_path: str | None = None
    reference_index_path: str | None = None
    model_artifact_path: str | None = None
    calibration_path: str | None = None
    prompt_hash: str | None = None
    provider: str | None = None
    model: str | None = None
    model_revision: str | None = None
    seed: int | None = None

    @model_validator(mode="after")
    def check_version(self) -> EvaluationConfig:
        if self.schema_version != 1:
            raise ValueError("unsupported evaluation config version")
        return self


def case_truth(event_truths: tuple[Truth, ...]) -> Truth:
    """Any confirmed attack makes a mixed session attack.

    A session is normal only when *every* constituent event has an explicit
    normal annotation. Unknowns cannot be treated as benign. Unmatched events
    are evaluated separately and never silently assigned to a session.
    """
    if Truth.attack in event_truths:
        return Truth.attack
    if event_truths and all(value is Truth.normal for value in event_truths):
        return Truth.normal
    return Truth.unknown
