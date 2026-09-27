"""Frozen, source-qualified timestamp and annotation profiles."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from hestia.datasets.catalog import DATASETS, read_manifest


class DatasetProfile(BaseModel):
    """Immutable provenance required to interpret one source file."""

    model_config = ConfigDict(frozen=True)

    dataset_id: str
    source_path: str
    default_year: int = Field(ge=1970, le=9999)
    timezone: str
    timezone_provenance: str
    timestamp_uncertainty: str
    annotation_coverage: Literal["complete", "partial", "none", "unknown"]
    dst_fold: Literal[0, 1] | None = None


def derive_ait_year(metadata_path: Path) -> int:
    """Derive AIT's initial year from its checked-in dataset metadata."""
    text = metadata_path.read_text(encoding="utf-8")
    match = re.search(r"^start:\s*['\"]?(\d{4})-", text, flags=re.MULTILINE)
    if match is None:
        raise ValueError(f"AIT metadata has no ISO start year: {metadata_path}")
    return int(match.group(1))


def dataset_profiles(data_root: Path, dataset_id: str) -> tuple[DatasetProfile, ...]:
    """Build profiles only for log files declared by a verified manifest."""
    if dataset_id not in DATASETS:
        raise ValueError("Unknown dataset identifier")
    manifest = read_manifest(data_root, dataset_id)
    if manifest is None:
        raise FileNotFoundError(f"Dataset is not imported: {dataset_id}")

    if dataset_id == "ait-auth":
        metadata = next((item for item in manifest.files if item.role == "metadata"), None)
        if metadata is None:
            raise ValueError("AIT manifest has no metadata file")
        year = derive_ait_year(data_root / "raw" / metadata.path)
        provenance = "UTC configured for reproducibility; upstream metadata omits timezone"
        uncertainty = "AIT metadata supplies date range but no timezone"
        coverage = "partial"
    elif dataset_id == "cam-auth":
        year = 2025
        provenance = "UTC explicitly configured for reproducibility; selected logs omit timezone"
        uncertainty = (
            "Yearless records use the configured 2025 profile year; upstream metadata is absent"
        )
        coverage = "unknown"
    else:
        year = 2016
        provenance = "UTC configured explicitly; Loghub sample does not encode timezone"
        uncertainty = "OpenSSH sample omits year and timezone; 2016 is dataset-profile metadata"
        coverage = "none"

    return tuple(
        DatasetProfile(
            dataset_id=dataset_id,
            source_path=item.path,
            default_year=year,
            timezone="UTC",
            timezone_provenance=provenance,
            timestamp_uncertainty=uncertainty,
            annotation_coverage=coverage,
        )
        for item in sorted(manifest.files, key=lambda entry: entry.path)
        if item.role == "log"
    )


__all__ = ["DatasetProfile", "dataset_profiles", "derive_ait_year"]
