"""Ablation contracts, with parity checks before comparing results."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Arm(StrEnum):
    normality_only = "normality_only"
    fixed_context = "fixed_context"
    evidence_tools = "evidence_tools"
    full_context = "full_context"


class ArmRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    arm: Arm
    dataset_hash: str
    model: str | None
    model_revision: str | None
    budget_hash: str
    case_ids: tuple[str, ...]
    run_order: int
    seed: int | None = None


def validate_matrix(records: tuple[ArmRecord, ...]) -> None:
    if {record.arm for record in records} != set(Arm):
        raise ValueError("all four distinct ablation arms are required")
    if len(records) != len(Arm):
        raise ValueError("exactly one record per arm is required")
    if len({record.run_order for record in records}) != len(records):
        raise ValueError("run order must be recorded uniquely")
    for field in ("dataset_hash", "budget_hash", "case_ids"):
        if len({getattr(record, field) for record in records}) != 1:
            raise ValueError(f"ablation arms must share {field}")
    hosted = [record for record in records if record.arm is not Arm.normality_only]
    if len({(record.model, record.model_revision) for record in hosted}) != 1:
        raise ValueError("LLM arms must use the same model and revision")
