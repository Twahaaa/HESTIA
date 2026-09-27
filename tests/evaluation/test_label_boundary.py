import hashlib
import json
import sqlite3
from datetime import UTC, datetime

import pytest

from hestia.datasets.splits import SplitItem, build_split_manifest, write_split_manifest
from hestia.evaluation.contracts import Truth, case_truth
from hestia.evaluation.datasets import load_labels, load_splits, session_truths, verify_store_splits


def test_mixed_unknown_and_unmatched_policy():
    assert case_truth((Truth.normal, Truth.attack, Truth.unknown)) is Truth.attack
    assert case_truth((Truth.normal, Truth.unknown)) is Truth.unknown
    assert case_truth((Truth.normal, Truth.normal)) is Truth.normal
    assert case_truth(()) is Truth.unknown


def test_labels_join_only_matching_event_source_and_do_not_modify_store(tmp_path):
    db_path = tmp_path / "evidence.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.executescript("""CREATE TABLE sources(id TEXT, dataset_id TEXT, path TEXT);
        CREATE TABLE events(event_id TEXT, source_id TEXT, line_no INTEGER);
        CREATE TABLE sessions(session_id TEXT);
        CREATE TABLE session_events(session_id TEXT, event_id TEXT, ordinal INTEGER);
        INSERT INTO sources VALUES ('src', 'dataset', 'logs/auth.log');
        INSERT INTO events VALUES ('e1', 'src', 17), ('e2', 'src', 18);
        INSERT INTO sessions VALUES ('s1');
        INSERT INTO session_events VALUES ('s1', 'e1', 0), ('s1', 'e2', 1);""")
    before = hashlib.sha256(db_path.read_bytes()).hexdigest()
    path = tmp_path / "labels.jsonl"
    row = {
        "event_id": "e1",
        "dataset_id": "dataset",
        "source_path": "logs/auth.log",
        "line_no": 17,
        "truth": "normal",
        "annotation_source": "reviewed sample",
    }
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    labels, digest = load_labels(path, db_path)
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert session_truths(db_path, labels) == {"s1": Truth.unknown}
    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == before
    row["line_no"] = 19
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source/line mismatch"):
        load_labels(path, db_path)


def test_split_hash_and_duplicate_assignments_rejected(tmp_path):
    manifest = build_split_manifest(
        [
            SplitItem(
                item_id="s1",
                source_path="logs/auth.log",
                timestamp=datetime.now(UTC),
                host="h1",
                content_hash="hash",
                eligible=False,
                eligibility_reason="unknown",
            )
        ]
    )
    path = tmp_path / "split.json"
    write_split_manifest(manifest, path)
    assert load_splits((path,))[0] == {"s1": "excluded"}
    with pytest.raises(ValueError, match="duplicate split session"):
        load_splits((path, path))
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["entries"][0]["split"] = "evaluation"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_splits((path,))


def test_split_bound_to_stored_source_hash(tmp_path):
    db_path = tmp_path / "evidence.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.executescript("""CREATE TABLE sources(id TEXT, path TEXT, hash TEXT);
        CREATE TABLE sessions(session_id TEXT, source_id TEXT);
        INSERT INTO sources VALUES ('src', 'logs/auth.log', 'original');
        INSERT INTO sessions VALUES ('s1', 'src');""")
    manifest = build_split_manifest(
        [
            SplitItem(
                item_id="s1",
                source_path="logs/auth.log",
                timestamp=datetime.now(UTC),
                host="h1",
                content_hash="original",
                eligible=False,
                eligibility_reason="unproven",
            )
        ]
    )
    path = tmp_path / "split.json"
    write_split_manifest(manifest, path)
    verify_store_splits((path,), db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE sources SET hash = 'changed'")
    with pytest.raises(ValueError, match="source hash mismatch"):
        verify_store_splits((path,), db_path)
