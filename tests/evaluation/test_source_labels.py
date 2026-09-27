"""Evaluation-only source labels and the technique-match score.

Every store here is synthetic. The label rules follow the upstream AIT-LDS and
CAM-LDS conventions; the score is checked against hand-calculated values.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hestia.agent.contracts import CaseInput, CaseRun, Finding, Report, RunState
from hestia.config import Settings
from hestia.datasets.profiles import DatasetProfile
from hestia.evaluation.agent_eval import AgentEvalConfig, load_config, score
from hestia.evaluation.contracts import Truth
from hestia.evaluation.datasets import load_labels
from hestia.evaluation.source_labels import (
    AIT_ATTACK_SOURCE,
    AIT_NORMAL_SOURCE,
    CAM_ATTACK_SOURCE,
    ait_label_file,
    build_source_labels,
    normalize_technique,
    parent_technique,
    technique_from_path,
    write_source_labels,
)
from hestia.ingestion.collector import collect_source
from hestia.ingestion.sessionization import sessionize_events
from hestia.store.repository import EvidenceRepository

LOG = """\
Jan  2 03:04:05 host-a sshd[11]: Failed password for invalid user alice from 198.51.100.7 port 2201 ssh2
Jan  2 03:04:09 host-a sshd[11]: Accepted password for alice from 198.51.100.7 port 2201 ssh2
Jan  3 09:00:00 host-a sshd[13]: Accepted password for bob from 203.0.113.9 port 2203 ssh2
Jan  4 11:22:33 host-a sshd[14]: Accepted password for carol from 192.0.2.4 port 2204 ssh2
"""
OTHER_LOG = LOG.replace("host-a", "host-b")
AIT = "ait-auth/full/gather/host-a/logs/auth.log"
CAM_BRUTE = "cam-auth/manifestations_filtered/techniques/T1110-001/run-1/host-a/auth.log"
CAM_VALID = "cam-auth/manifestations_filtered/techniques/T1078-000/run-1/host-a/auth.log"
CAM_SEQUENCE = "cam-auth/manifestations_filtered/sequences/run-1/host-a/auth.log"
CAM_STEP = "cam-auth/manifestations_filtered/steps/run-2/host-b/auth.log"
OPENSSH = "openssh/auth.log"
SOURCES = (
    ("ait-auth", AIT, LOG),
    ("cam-auth", CAM_BRUTE, LOG),
    ("cam-auth", CAM_VALID, LOG),  # same content: one log filed under two techniques
    ("cam-auth", CAM_SEQUENCE, LOG),  # duplicate content outside techniques/
    ("cam-auth", CAM_STEP, OTHER_LOG),  # different content, no technique folder
    ("openssh", OPENSSH, LOG),
)


def _import(repository: EvidenceRepository, tmp_path: Path, dataset: str, path: str, text: str):
    source = tmp_path / path.replace("/", "_")
    source.write_text(text, encoding="utf-8")
    collection = collect_source(
        source,
        DatasetProfile(
            dataset_id=dataset,
            source_path=path,
            default_year=2025,
            timezone="UTC",
            timezone_provenance="synthetic fixture",
            timestamp_uncertainty="none",
            annotation_coverage="none",
        ),
    )
    events = [item.event for item in collection.events]
    sessions, unmatched = sessionize_events(events, gap_seconds=300)
    repository.import_source(
        collection, sessions, ((event, "missing user or source IP") for event in unmatched)
    )


@pytest.fixture
def store(tmp_path: Path) -> dict[str, Path]:
    settings = Settings(
        data_root=tmp_path / "data",
        artifact_root=tmp_path / "artifacts",
        frontend_dist=tmp_path / "no-ui",
    )
    repository = EvidenceRepository(settings.evidence_database)
    repository.initialize()
    for dataset, path, text in SOURCES:
        _import(repository, tmp_path, dataset, path, text)
    raw = settings.data_root / "raw"
    label_file = ait_label_file(raw, AIT)
    label_file.parent.mkdir(parents=True)
    # Upstream JSONL: line 3 (bob's login) is an attacker step.
    label_file.write_text(
        json.dumps({"line": 3, "labels": ["attacker_change_user"], "rules": {}}) + "\n",
        encoding="utf-8",
    )
    return {"db": settings.evidence_database, "raw": raw, "root": tmp_path}


def _sessions(db_path: Path) -> dict[tuple[str, str], str]:
    """(source path, first user) -> session id."""
    with sqlite3.connect(db_path) as db:
        rows = db.execute(
            """SELECT src.path, e.user, s.session_id FROM sessions s
               JOIN sources src ON src.id = s.source_id
               JOIN session_events se ON se.session_id = s.session_id AND se.ordinal = 0
               JOIN events e ON e.event_id = se.event_id"""
        ).fetchall()
    return {(path, user): session for path, user, session in rows}


def test_technique_paths_normalise_like_attack_ids():
    assert technique_from_path(CAM_BRUTE) == "T1110.001"
    assert technique_from_path(CAM_VALID) == "T1078"
    assert technique_from_path(CAM_SEQUENCE) is None
    assert normalize_technique(" t1110.001 (Brute Force: Password Guessing)") == "T1110.001"
    assert normalize_technique("T1078") == "T1078"
    assert normalize_technique("brute force") is None
    assert parent_technique("T1110.001") == "T1110"
    assert ait_label_file(Path("raw"), AIT) == Path("raw/ait-auth/full/labels/host-a/logs/auth.log")


def test_rules_follow_upstream_conventions_and_leave_other_datasets_unknown(store):
    labels, techniques, summary = build_source_labels(store["db"], store["raw"])
    by_source: dict[str, dict[int, tuple[Truth, str]]] = {}
    for label in labels:
        by_source.setdefault(label.source_path, {})[label.line_no] = (
            label.truth,
            label.annotation_source,
        )
    assert by_source[AIT] == {
        1: (Truth.normal, AIT_NORMAL_SOURCE),
        2: (Truth.normal, AIT_NORMAL_SOURCE),
        3: (Truth.attack, AIT_ATTACK_SOURCE),
        4: (Truth.normal, AIT_NORMAL_SOURCE),
    }
    for path in (CAM_BRUTE, CAM_VALID, CAM_SEQUENCE, CAM_STEP):
        assert set(by_source[path].values()) == {(Truth.attack, CAM_ATTACK_SOURCE)}
    assert OPENSSH not in by_source
    assert summary["events_by_dataset_truth"] == {
        "ait-auth:attack": 1,
        "ait-auth:normal": 3,
        "cam-auth:attack": 16,
    }

    sessions = _sessions(store["db"])
    both = ["T1078", "T1110.001"]
    # A technique folder holds both techniques through its content duplicate.
    assert techniques[sessions[(CAM_BRUTE, "alice")]] == {"techniques": both, "via": "path"}
    # A sequence log inherits them through the identical content hash.
    assert techniques[sessions[(CAM_SEQUENCE, "bob")]] == {
        "techniques": both,
        "via": "content_hash",
    }
    # Different content outside techniques/ has no known technique.
    assert sessions[(CAM_STEP, "alice")] not in techniques
    assert all(session != sessions[(AIT, "alice")] for session in techniques)


def test_missing_upstream_labels_directory_refuses(store):
    for path in sorted(store["raw"].rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    with pytest.raises(FileNotFoundError, match="labels directory missing"):
        build_source_labels(store["db"], store["raw"])


def test_written_sidecar_round_trips_through_the_label_loader(store):
    out = store["root"] / "artifacts" / "evaluation" / "labels"
    manifest = write_source_labels(store["db"], store["raw"], out)
    labels, digest = load_labels(Path(manifest["labels_path"]), store["db"])
    assert digest == manifest["labels_sha256"]
    assert len(labels) == manifest["labelled_events"] == 20
    assert "evaluation scoring only" in manifest["scope"]
    assert not list(out.glob("*.tmp"))


def _record(session_id: str, dataset: str, *, verdict=None, techniques=()) -> dict:
    report = None
    if verdict is not None:
        report = Report(
            verdict=verdict,
            severity="none" if verdict == "benign" else "medium",
            confidence=0.5,
            summary="synthetic",
            findings=(Finding(statement="x", evidence_handles=("ev-1",)),),
            known_or_novel="uncertain",
            technique_ids=techniques,
        )
    at = datetime(2026, 1, 1, tzinfo=UTC)
    run = CaseRun(
        run_id="r",
        case=CaseInput(
            case_id=f"case-{session_id[:8]}",
            session_id=session_id,
            opened_at=at,
            session_start=at,
            session_end=at,
            dataset_id="masked-for-evaluation",
            history_before=at,
        ),
        state=RunState.completed if report else RunState.failed,
        provider="groq",
        model="approved-model",
        fixture=False,
        started_at=at,
        finished_at=at,
        report=report,
        incomplete_reason=None if report else "synthetic failure",
    )
    return {"run": run.model_dump(mode="json"), "dataset_id": dataset}


def test_hand_calculated_confusion_and_technique_match(store):
    """Eight cases, hand-scored.

    AIT alice normal/benign -> TN; AIT carol normal/suspicious -> FP; AIT bob
    attack/malicious -> TP (no technique set). CAM sequence alice -> TP, exact
    (T1110.001); CAM sequence bob -> TP, parent (T1110); CAM sequence carol ->
    no report, abstained + no_report; CAM step alice attack/benign -> FN, no
    technique set; OpenSSH -> unknown. So tp=3 fp=1 tn=1 fn=1 abstained=1
    unknown=1, precision 3/4, recall 3/4, F1 6/8; techniques 3 eligible:
    exact 1/3, exact-or-parent 2/3.
    """
    out = store["root"] / "labels"
    manifest = write_source_labels(store["db"], store["raw"], out)
    index = store["root"] / "index.json"
    index.write_text(json.dumps({"documents": [{"source": {"source_uri": CAM_BRUTE}}]}))
    s = _sessions(store["db"])
    records = [
        _record(s[(AIT, "alice")], "ait-auth", verdict="benign"),
        _record(s[(AIT, "carol")], "ait-auth", verdict="suspicious"),
        _record(s[(AIT, "bob")], "ait-auth", verdict="malicious"),
        _record(
            s[(CAM_SEQUENCE, "alice")], "cam-auth", verdict="malicious", techniques=("t1110.001",)
        ),
        _record(s[(CAM_SEQUENCE, "bob")], "cam-auth", verdict="suspicious", techniques=("T1110",)),
        _record(s[(CAM_SEQUENCE, "carol")], "cam-auth"),
        _record(s[(CAM_STEP, "alice")], "cam-auth", verdict="benign"),
        _record(s[(OPENSSH, "alice")], "openssh", verdict="malicious"),
    ]
    result = score(
        records,
        Path(manifest["labels_path"]),
        store["db"],
        techniques_path=Path(manifest["techniques_path"]),
        index_path=index,
    )
    matrix = result["confusion"]
    assert (matrix["tp"], matrix["fp"], matrix["tn"], matrix["fn"]) == (3, 1, 1, 1)
    assert (matrix["abstained"], matrix["unknown_truth"], matrix["labelled"]) == (1, 1, 7)
    assert matrix["precision"] == pytest.approx(0.75)
    assert matrix["recall"] == pytest.approx(0.75)
    assert matrix["f1"] == pytest.approx(0.75)

    technique = result["technique"]
    assert technique["eligible_attack_cases"] == 3
    assert technique["counts"] == {
        "exact": 1,
        "parent": 1,
        "mismatch": 0,
        "none_proposed": 0,
        "no_report": 1,
    }
    assert technique["exact"]["rate"] == pytest.approx(1 / 3)
    assert technique["exact_or_parent"]["rate"] == pytest.approx(2 / 3)
    assert technique["exact"]["ci95"] is not None
    assert technique["cases_with_cam_sibling_in_reference_index"] == 3
    matches = [row["technique"]["match"] for row in result["cases"] if "technique" in row]
    assert matches == ["exact", "parent", "no_report"]

    text = " ".join(result["limitations"])
    assert "rule-derived" in text and "n=7" in text
    assert "inflated" in text and "lenient" in text
    assert "0 eligible sessions" in text
    # Attack and normal cases share ait-auth here, so no dataset confound is claimed.
    assert "Dataset confound" not in text

    confounded = score(
        [records[0], records[3]],
        Path(manifest["labels_path"]),
        store["db"],
        techniques_path=Path(manifest["techniques_path"]),
        index_path=index,
    )
    assert any("Dataset confound" in item for item in confounded["limitations"])


def test_mismatch_and_missing_technique_proposals(store):
    out = store["root"] / "labels"
    manifest = write_source_labels(store["db"], store["raw"], out)
    s = _sessions(store["db"])
    records = [
        _record(s[(CAM_BRUTE, "alice")], "cam-auth", verdict="malicious", techniques=("T1033",)),
        _record(s[(CAM_BRUTE, "bob")], "cam-auth", verdict="suspicious"),
    ]
    result = score(
        records,
        Path(manifest["labels_path"]),
        store["db"],
        techniques_path=Path(manifest["techniques_path"]),
    )
    assert result["technique"]["counts"]["mismatch"] == 1
    assert result["technique"]["counts"]["none_proposed"] == 1
    assert result["technique"]["exact_or_parent"]["rate"] == 0.0
    # No reference index given: nothing is flagged as a retrievable sibling.
    assert result["technique"]["cases_with_cam_sibling_in_reference_index"] == 0


def test_techniques_path_requires_labels_path():
    with pytest.raises(ValueError, match="techniques_path needs labels_path"):
        AgentEvalConfig(
            datasets=("cam-auth",),
            per_dataset=1,
            seed=1,
            reference_index_path="index.json",
            techniques_path="techniques.json",
        )


def test_labelled_config_scores_ait_and_cam_with_groq_only():
    path = Path(__file__).parents[2] / "evaluation" / "configs" / "agent-labelled.json"
    config = load_config(path)
    assert config.datasets == ("ait-auth", "cam-auth")
    assert config.per_dataset == 3
    assert config.labels_path and config.labels_path.endswith("source-labels.jsonl")
    assert config.techniques_path and config.techniques_path.endswith("session-techniques.json")
    assert config.hosted is not None and config.hosted.provider == "groq"
    assert config.budget.max_turns == 16 and config.budget.context_token_budget == 5000


def test_agent_runtime_never_references_evaluation_labels():
    src = Path(__file__).parents[2] / "src" / "hestia"
    for package in ("agent", "mcp", "runs", "api", "store", "knowledge"):
        for module in (src / package).rglob("*.py"):
            text = module.read_text(encoding="utf-8")
            for marker in ("source_labels", "source-labels", "session-techniques", "labels_path"):
                assert marker not in text, f"{module} references {marker}"
