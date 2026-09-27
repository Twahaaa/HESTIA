"""Deterministic, leakage-resistant evidence split manifests."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SplitItem(BaseModel):
    """One source-qualified unit proposed for normal-data curation."""

    model_config = ConfigDict(frozen=True)

    item_id: str
    source_path: str
    timestamp: datetime
    host: str
    content_hash: str
    campaign_id: str | None = None
    eligible: bool
    eligibility_reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def reject_naive_time(self) -> SplitItem:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("Split timestamps must be timezone-aware")
        return self


class SplitEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    item_id: str
    split: Literal["reference", "validation", "evaluation", "excluded"]
    content_hash: str
    host: str
    campaign_id: str | None
    reason: str


class SplitManifest(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: int = 1
    strategy: str = "chronological groups joined by host, campaign, or content hash"
    coverage_claims: tuple[str, ...]
    source_hashes: dict[str, str]
    entries: tuple[SplitEntry, ...]
    manifest_hash: str


def cam_campaign_id(source_path: str) -> str | None:
    """Derive the repeated CAM scenario directory across its three catalog views."""
    parts = Path(source_path).parts
    for category in ("sequences", "steps", "techniques"):
        if category not in parts:
            continue
        index = parts.index(category)
        offset = 2 if category == "techniques" else 1
        if index + offset < len(parts):
            return parts[index + offset]
    return None


def _campaign(item: SplitItem) -> str | None:
    return item.campaign_id or cam_campaign_id(item.source_path)


def _group_items(items: list[SplitItem]) -> list[list[SplitItem]]:
    parent = list(range(len(items)))

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = root(left), root(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    seen: dict[tuple[str, str], int] = {}
    for index, item in enumerate(items):
        keys = [("host", item.host), ("content", item.content_hash)]
        if (campaign_id := _campaign(item)) is not None:
            keys.append(("campaign", campaign_id))
        for key in keys:
            if key in seen:
                union(index, seen[key])
            else:
                seen[key] = index

    groups: dict[int, list[SplitItem]] = {}
    for index, item in enumerate(items):
        groups.setdefault(root(index), []).append(item)
    return sorted(
        groups.values(),
        key=lambda group: (
            min(item.timestamp for item in group),
            min(item.item_id for item in group),
        ),
    )


def build_split_manifest(
    items: list[SplitItem],
    *,
    reference_fraction: float = 0.6,
    validation_fraction: float = 0.2,
) -> SplitManifest:
    """Assign eligible groups chronologically without host/campaign/duplicate leakage."""
    if not 0 < reference_fraction < 1 or not 0 < validation_fraction < 1:
        raise ValueError("Split fractions must be between zero and one")
    if reference_fraction + validation_fraction >= 1:
        raise ValueError("Reference and validation fractions must leave an evaluation split")
    if len({item.item_id for item in items}) != len(items):
        raise ValueError("Split item ids must be unique")

    eligible = [item for item in items if item.eligible]
    groups = _group_items(eligible)
    total = sum(len(group) for group in groups)
    assigned = 0
    split_by_id: dict[str, Literal["reference", "validation", "evaluation"]] = {}
    for group in groups:
        fraction = assigned / total if total else 1.0
        split: Literal["reference", "validation", "evaluation"]
        if fraction < reference_fraction:
            split = "reference"
        elif fraction < reference_fraction + validation_fraction:
            split = "validation"
        else:
            split = "evaluation"
        for item in group:
            split_by_id[item.item_id] = split
        assigned += len(group)

    entries = tuple(
        SplitEntry(
            item_id=item.item_id,
            split=split_by_id[item.item_id] if item.eligible else "excluded",
            content_hash=item.content_hash,
            host=item.host,
            campaign_id=_campaign(item),
            reason=item.eligibility_reason,
        )
        for item in sorted(items, key=lambda value: value.item_id)
    )
    source_hashes = dict(sorted((item.source_path, item.content_hash) for item in items))
    coverage_claims = (
        "Only records with explicit eligibility evidence enter normal-data splits.",
        "Unlabelled records are unknown unless separately supported by eligibility evidence.",
        "Hosts, campaign groups, and duplicate content do not cross split boundaries.",
    )
    canonical = json.dumps(
        {
            "schema_version": 1,
            "strategy": "chronological groups joined by host, campaign, or content hash",
            "coverage_claims": coverage_claims,
            "source_hashes": source_hashes,
            "entries": [entry.model_dump(mode="json") for entry in entries],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return SplitManifest(
        coverage_claims=coverage_claims,
        source_hashes=source_hashes,
        entries=entries,
        manifest_hash=hashlib.sha256(canonical.encode()).hexdigest(),
    )


def write_split_manifest(manifest: SplitManifest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


__all__ = [
    "SplitEntry",
    "SplitItem",
    "SplitManifest",
    "build_split_manifest",
    "cam_campaign_id",
    "write_split_manifest",
]
