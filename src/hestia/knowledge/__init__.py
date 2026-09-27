"""Attributed reference material for investigation, built reproducibly offline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from hestia.datasets.splits import SplitManifest
from hestia.knowledge.attack import (
    ATTACK_SOURCE_URL,
    ATTACK_VERSION,
    SNAPSHOT_FILENAME,
    AttackSnapshot,
    build_attack_documents,
    build_snapshot,
    fetch_bundle,
    read_snapshot,
    write_snapshot,
)
from hestia.knowledge.cam import build_cam_documents
from hestia.knowledge.contracts import (
    KNOWLEDGE_SCHEMA_VERSION,
    ReferenceDocument,
    ReferenceIndex,
    index_digest,
    read_index,
    write_index,
)
from hestia.knowledge.retrieval import LexicalIndex

HELD_OUT_SPLITS = ("validation", "evaluation")
EXCLUSION_RULE = (
    "A source file is excluded from the reference corpus when any prepared item from "
    f"that file is assigned to a {' or '.join(HELD_OUT_SPLITS)} split, so reference "
    "retrieval cannot quote evidence a later evaluation scores."
)


def held_out_source_paths(manifest_paths: tuple[Path, ...]) -> tuple[str, ...]:
    """Collect the source paths any held-out split claims, across split manifests."""
    held_out: set[str] = set()
    for path in manifest_paths:
        manifest = SplitManifest.model_validate_json(path.read_text(encoding="utf-8"))
        held_out_ids = {
            entry.item_id for entry in manifest.entries if entry.split in HELD_OUT_SPLITS
        }
        for source_path in manifest.source_hashes:
            if any(item_id.startswith(f"{source_path}:") for item_id in held_out_ids):
                held_out.add(source_path)
    return tuple(sorted(held_out))


def build_reference_index(
    data_root: Path,
    *,
    split_manifests: tuple[Path, ...] = (),
    attack_snapshot: AttackSnapshot | None = None,
) -> ReferenceIndex:
    """Assemble the versioned reference index from local, attributed material only."""
    held_out = held_out_source_paths(split_manifests)
    cam_documents, skipped = build_cam_documents(data_root, excluded_source_paths=held_out)
    documents: list[ReferenceDocument] = list(cam_documents)
    collections: list[str] = []
    notes: list[str] = []
    if cam_documents:
        collections.append("cam-auth")
    else:
        notes.append(
            "No CAM-LDS reference documents were built: the technique corpus is not "
            "present in this deployment's data root."
        )
    if attack_snapshot is not None:
        attack_documents = build_attack_documents(attack_snapshot)
        documents.extend(attack_documents)
        if attack_documents:
            collections.append("mitre-attack")
        notes.append(
            f"MITRE ATT&CK Enterprise v{attack_snapshot.attack_version} subset holds "
            f"{len(attack_documents)} auth-relevant techniques out of the full catalog."
        )
    else:
        notes.append(
            "No MITRE ATT&CK snapshot is pinned in this deployment; technique lookups "
            "will report the reference as unavailable rather than inventing one."
        )
    notes.append(
        "Reference matches are attributed source material. They do not establish that "
        "a session is a known technique, and their absence does not establish novelty."
    )
    if not held_out:
        notes.append(
            "No prepared item is assigned to a held-out split, so the reference/test "
            "overlap exclusion currently removes nothing. It is enforced regardless."
        )
    ordered = tuple(sorted(documents, key=lambda item: item.document_id))
    return ReferenceIndex(
        built_at=datetime.now(UTC),
        documents=ordered,
        collections=tuple(dict.fromkeys(collections)),  # type: ignore[arg-type]
        excluded_source_paths=tuple(sorted(set(held_out) | set(skipped))),
        exclusion_rule=EXCLUSION_RULE,
        coverage_notes=tuple(notes),
        index_hash=index_digest(
            ordered, tuple(sorted(set(held_out) | set(skipped))), EXCLUSION_RULE
        ),
    )


__all__ = [
    "ATTACK_SOURCE_URL",
    "ATTACK_VERSION",
    "EXCLUSION_RULE",
    "HELD_OUT_SPLITS",
    "KNOWLEDGE_SCHEMA_VERSION",
    "SNAPSHOT_FILENAME",
    "AttackSnapshot",
    "LexicalIndex",
    "ReferenceDocument",
    "ReferenceIndex",
    "build_reference_index",
    "build_snapshot",
    "fetch_bundle",
    "held_out_source_paths",
    "read_index",
    "read_snapshot",
    "write_index",
    "write_snapshot",
]
