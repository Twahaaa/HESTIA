"""Join private evaluation annotations to frozen evidence identifiers."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from hestia.datasets.splits import SplitManifest
from hestia.evaluation.contracts import EventLabel, Truth, case_truth


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_splits(paths: tuple[Path, ...]) -> tuple[dict[str, str], dict[str, str]]:
    """Verify canonical manifest hashes and refuse conflicting session assignments."""
    assignments: dict[str, str] = {}
    digests: dict[str, str] = {}
    for path in paths:
        manifest = SplitManifest.model_validate_json(path.read_text(encoding="utf-8"))
        canonical = manifest.model_dump(mode="json", exclude={"manifest_hash"})
        expected = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if manifest.manifest_hash != expected:
            raise ValueError(f"split manifest hash mismatch: {path}")
        digests[str(path)] = sha256(path)
        for entry in manifest.entries:
            if entry.item_id in assignments:
                raise ValueError(f"duplicate split session: {entry.item_id}")
            assignments[entry.item_id] = entry.split
    return assignments, digests


def verify_store_splits(paths: tuple[Path, ...], db_path: Path) -> None:
    """Ensure each frozen split entry still identifies the same stored source bytes."""
    with sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True) as db:
        for path in paths:
            manifest = SplitManifest.model_validate_json(path.read_text(encoding="utf-8"))
            for entry in manifest.entries:
                row = db.execute(
                    """SELECT src.path, src.hash FROM sessions s JOIN sources src
                       ON src.id = s.source_id WHERE s.session_id = ?""",
                    (entry.item_id,),
                ).fetchone()
                if (
                    row is None
                    or manifest.source_hashes.get(row[0]) != row[1]
                    or (entry.content_hash != row[1])
                ):
                    raise ValueError(f"split source hash mismatch: {entry.item_id}")


def load_labels(path: Path | None, db_path: Path) -> tuple[dict[str, Truth], str | None]:
    """Validate an eval-only JSONL sidecar against source-qualified store rows."""
    if path is None:
        return {}, None
    if not db_path.is_file():
        raise FileNotFoundError(db_path)
    labels: dict[str, Truth] = {}
    with sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True) as db:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            label = EventLabel.model_validate_json(line)
            if label.event_id in labels:
                raise ValueError(f"duplicate label event_id on line {number}")
            row = db.execute(
                """SELECT src.dataset_id, src.path, e.line_no FROM events e
                   JOIN sources src ON src.id = e.source_id WHERE e.event_id = ?""",
                (label.event_id,),
            ).fetchone()
            if row != (label.dataset_id, label.source_path, label.line_no):
                raise ValueError(f"label source/line mismatch on line {number}")
            labels[label.event_id] = label.truth
    return labels, sha256(path)


def session_truths(db_path: Path, labels: dict[str, Truth]) -> dict[str, Truth]:
    """Aggregate event labels without importing the label sidecar into runtime tables."""
    result: dict[str, Truth] = {}
    with sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True) as db:
        for (session_id,) in db.execute("SELECT session_id FROM sessions ORDER BY session_id"):
            events = db.execute(
                "SELECT event_id FROM session_events WHERE session_id = ? ORDER BY ordinal",
                (session_id,),
            ).fetchall()
            result[session_id] = case_truth(
                tuple(labels.get(event_id, Truth.unknown) for (event_id,) in events)
            )
    return result


def coverage(db_path: Path, labels: dict[str, Truth]) -> dict[str, int]:
    """Report candidate coverage with unmatched events kept in the denominator."""
    with sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True) as db:
        total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        unmatched = db.execute("SELECT event_id FROM unmatched_events").fetchall()
        candidates = db.execute("SELECT COUNT(DISTINCT session_id) FROM candidates").fetchone()[0]
        sessions = db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    return {
        "events": total,
        "labelled_events": len(labels),
        "unmatched_events": len(unmatched),
        "labelled_unmatched_events": sum(event_id in labels for (event_id,) in unmatched),
        "sessions": sessions,
        "candidate_sessions": candidates,
    }
