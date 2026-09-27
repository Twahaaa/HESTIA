"""Evaluation-only labels derived from the upstream datasets' own conventions.

These labels exist so the investigation agent's outcomes can be scored. They are
written to a private sidecar under ``artifacts/evaluation/labels/`` and read by
``agent_eval.score`` only after every run has finished. They are never imported
into the evidence store, never offered to MCP tools or the agent, and never used
for case selection or normality training.

Rules (each row's ``annotation_source`` names the rule it came from):

- AIT-LDS V2.1: an event whose line is listed in the matching file under
  ``labels/`` is attack; every other event is normal, per the dataset's stated
  convention that unlisted events "can be considered to be labeled as 'normal'".
  This departs from H1's "unlabelled = unknown" policy for evaluation labels
  only; the normality training gate is unchanged.
- CAM-LDS ``manifestations_filtered``: logs that are direct consequences of
  attacks, so every event is attack. The ATT&CK technique set of a session comes
  from ``/techniques/<T####-###>/`` folders holding the same content hash.
- Anything else (for example OpenSSH) gets no row and stays unknown.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

from hestia.datasets.aitlds import load_aitlds_labels
from hestia.evaluation.contracts import EventLabel, Truth

AIT_DATASET = "ait-auth"
CAM_DATASET = "cam-auth"
AIT_ATTACK_SOURCE = (
    "AIT-LDS V2.1 (zenodo.org/records/19483937, CC BY-NC-SA 4.0): line listed in "
    "labels/<host>/logs/<file>"
)
AIT_NORMAL_SOURCE = (
    "AIT-LDS V2.1 (zenodo.org/records/19483937, CC BY-NC-SA 4.0): unlisted event, "
    "upstream convention 'can be considered to be labeled as normal'"
)
CAM_ATTACK_SOURCE = (
    "CAM-LDS manifestations_filtered (zenodo.org/records/18390561, CC BY 4.0): "
    "direct consequences of attacks"
)
LABELS_FILE = "source-labels.jsonl"
TECHNIQUES_FILE = "session-techniques.json"
MANIFEST_FILE = "manifest.json"

_TECHNIQUE_FOLDER = re.compile(r"/techniques/(T\d{4})-(\d{3})/")
_TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")


def technique_from_path(path: str) -> str | None:
    """``.../techniques/T1110-001/...`` -> ``T1110.001``; ``-000`` -> the base ID."""
    match = _TECHNIQUE_FOLDER.search(path)
    if match is None:
        return None
    base, sub = match.groups()
    return base if sub == "000" else f"{base}.{sub}"


def normalize_technique(value: str) -> str | None:
    """Extract an ATT&CK ID from free model text such as ``t1110.001 (Brute Force)``."""
    match = _TECHNIQUE_ID.search(value.strip().upper())
    return match.group(0) if match else None


def parent_technique(technique: str) -> str:
    return technique.split(".", 1)[0]


def ait_label_file(raw_root: Path, source_path: str) -> Path:
    """``ait-auth/full/gather/<host>/logs/<file>`` -> ``.../labels/<host>/logs/<file>``."""
    parts = source_path.split("/")
    if parts.count("gather") != 1:
        raise ValueError(f"AIT source path has no single gather/ segment: {source_path}")
    return raw_root / "/".join("labels" if part == "gather" else part for part in parts)


def _connect(db_path: Path) -> sqlite3.Connection:
    if not db_path.is_file():
        raise FileNotFoundError(db_path)
    return sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)


def build_source_labels(
    db_path: Path, raw_root: Path
) -> tuple[list[EventLabel], dict[str, dict[str, Any]], dict[str, Any]]:
    """Derive event labels and session technique sets. Reads the store read-only."""
    labels: list[EventLabel] = []
    counts: dict[str, int] = defaultdict(int)
    label_files: dict[str, str] = {}
    with _connect(db_path) as db:
        sources = db.execute(
            "SELECT id, dataset_id, path, hash FROM sources ORDER BY path"
        ).fetchall()
        if any(dataset == AIT_DATASET for _, dataset, _, _ in sources):
            labels_root = raw_root / AIT_DATASET / "full" / "labels"
            if not labels_root.is_dir():
                # Without the upstream labels directory, "unlisted" cannot mean normal.
                raise FileNotFoundError(f"AIT-LDS labels directory missing: {labels_root}")
        for source_id, dataset, path, _ in sources:
            if dataset not in {AIT_DATASET, CAM_DATASET}:
                continue
            attack_lines: set[int] = set()
            if dataset == AIT_DATASET:
                label_file = ait_label_file(raw_root, path)
                if label_file.is_file():
                    listed = load_aitlds_labels(label_file, expected_source=path)
                    attack_lines = {line for (_, line), record in listed.items() if record.attack}
                    label_files[path] = hashlib.sha256(label_file.read_bytes()).hexdigest()
            for event_id, line_no in db.execute(
                "SELECT event_id, line_no FROM events WHERE source_id = ? ORDER BY line_no",
                (source_id,),
            ):
                if dataset == CAM_DATASET:
                    truth, annotation = Truth.attack, CAM_ATTACK_SOURCE
                elif line_no in attack_lines:
                    truth, annotation = Truth.attack, AIT_ATTACK_SOURCE
                else:
                    truth, annotation = Truth.normal, AIT_NORMAL_SOURCE
                counts[f"{dataset}:{truth.value}"] += 1
                labels.append(
                    EventLabel(
                        event_id=event_id,
                        dataset_id=dataset,
                        source_path=path,
                        line_no=line_no,
                        truth=truth,
                        annotation_source=annotation,
                    )
                )

        by_hash: dict[str, set[str]] = defaultdict(set)
        for _, dataset, path, digest in sources:
            technique = technique_from_path(path) if dataset == CAM_DATASET else None
            if technique is not None:
                by_hash[digest].add(technique)
        techniques: dict[str, dict[str, Any]] = {}
        for session_id, path, digest in db.execute(
            """SELECT s.session_id, src.path, src.hash FROM sessions s
               JOIN sources src ON src.id = s.source_id
               WHERE src.dataset_id = ? ORDER BY s.session_id""",
            (CAM_DATASET,),
        ):
            found = by_hash.get(digest)
            if found:
                techniques[session_id] = {
                    "techniques": sorted(found),
                    "via": "path" if technique_from_path(path) else "content_hash",
                }
    summary = {
        "events_by_dataset_truth": dict(sorted(counts.items())),
        "ait_label_files_sha256": dict(sorted(label_files.items())),
        "cam_sessions_with_techniques": len(techniques),
        "distinct_techniques": len({t for row in techniques.values() for t in row["techniques"]}),
    }
    return labels, techniques, summary


def write_source_labels(db_path: Path, raw_root: Path, output_dir: Path) -> dict[str, Any]:
    """Write the label sidecar, the session technique sidecar and a manifest."""
    labels, techniques, summary = build_source_labels(db_path, raw_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    labels_path = output_dir / LABELS_FILE
    techniques_path = output_dir / TECHNIQUES_FILE
    staged_labels = labels_path.with_suffix(".jsonl.tmp")
    staged_labels.write_text(
        "".join(label.model_dump_json() + "\n" for label in labels), encoding="utf-8"
    )
    staged_techniques = techniques_path.with_suffix(".json.tmp")
    staged_techniques.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "rule": (
                    "CAM-LDS techniques/<T####-###>/ folder name, inherited by any CAM "
                    "source with an identical content hash"
                ),
                "sessions": techniques,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    staged_labels.replace(labels_path)
    staged_techniques.replace(techniques_path)
    manifest = {
        "schema_version": 1,
        "evidence_sha256": hashlib.sha256(db_path.read_bytes()).hexdigest(),
        "labels_path": str(labels_path),
        "labels_sha256": hashlib.sha256(labels_path.read_bytes()).hexdigest(),
        "labelled_events": len(labels),
        "techniques_path": str(techniques_path),
        "techniques_sha256": hashlib.sha256(techniques_path.read_bytes()).hexdigest(),
        "rules": [AIT_ATTACK_SOURCE, AIT_NORMAL_SOURCE, CAM_ATTACK_SOURCE],
        "scope": "evaluation scoring only; never agent input, selection or training",
        **summary,
    }
    (output_dir / MANIFEST_FILE).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


__all__ = [
    "AIT_ATTACK_SOURCE",
    "AIT_NORMAL_SOURCE",
    "CAM_ATTACK_SOURCE",
    "ait_label_file",
    "build_source_labels",
    "normalize_technique",
    "parent_technique",
    "technique_from_path",
    "write_source_labels",
]
