"""Local manifest catalog; never resolves caller-supplied filesystem paths."""

import hashlib
from pathlib import Path

from pydantic import BaseModel, Field

DATASETS = ("ait-auth", "cam-auth", "openssh")


class DataFile(BaseModel):
    path: str
    size: int = Field(ge=0)
    sha256: str
    role: str


class DatasetManifest(BaseModel):
    schema_version: int = 1
    dataset_id: str
    upstream: str
    version: str
    files: list[DataFile]
    annotation_policy: str = "Evaluation only; unlabelled events are unknown."


def digest(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def read_manifest(root: Path, dataset_id: str) -> DatasetManifest | None:
    if dataset_id not in DATASETS:
        raise ValueError("Unknown dataset identifier")
    path = root / "manifests" / f"{dataset_id}.json"
    return DatasetManifest.model_validate_json(path.read_text()) if path.exists() else None


def summary(root: Path, dataset_id: str) -> dict:
    manifest = read_manifest(root, dataset_id)
    if manifest is None:
        return {"dataset_id": dataset_id, "status": "not_imported", "file_count": 0}
    valid = 0
    for entry in manifest.files:
        path = (root / "raw" / entry.path).resolve()
        if not path.is_relative_to((root / "raw").resolve()):
            raise ValueError("Manifest path escapes raw data root")
        if path.is_file() and path.stat().st_size == entry.size and digest(path) == entry.sha256:
            valid += 1
    return {
        "dataset_id": dataset_id,
        "status": "available" if valid == len(manifest.files) else "incomplete",
        "file_count": len(manifest.files),
        "verified_files": valid,
        "bytes": sum(f.size for f in manifest.files),
        "annotation_files": sum(f.role == "annotation" for f in manifest.files),
        "annotation_policy": manifest.annotation_policy,
    }


def list_datasets(root: Path) -> list[dict]:
    return [summary(root, dataset_id) for dataset_id in DATASETS]
