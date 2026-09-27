"""Read-only offline measurement of frozen, pre-existing runs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from hestia.evaluation.contracts import EvaluationConfig, Truth
from hestia.evaluation.datasets import (
    coverage,
    load_labels,
    load_splits,
    session_truths,
    sha256,
    verify_store_splits,
)
from hestia.evaluation.metrics import confusion, false_alert_rate, latency
from hestia.knowledge.contracts import read_index


def _snapshot(path: Path | None) -> str | None:
    if path is None:
        return None
    if not path.is_file():
        raise FileNotFoundError(path)
    return sha256(path)


def evaluate(config_path: Path, db_path: Path, output_root: Path) -> dict[str, object]:
    """Write immutable measured results. Never launches an agent or trains a model."""
    config_path = config_path.resolve()
    config = EvaluationConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
    if not db_path.is_file():
        raise FileNotFoundError(db_path)

    def resolve(value: str | None) -> Path | None:
        return (config_path.parent / value).resolve() if value is not None else None

    split_paths = tuple((config_path.parent / path).resolve() for path in config.split_manifests)
    splits, split_digests = load_splits(split_paths)
    verify_store_splits(split_paths, db_path)
    labels, label_hash = load_labels(resolve(config.labels_path), db_path)
    truths = session_truths(db_path, labels)
    if set(splits) != set(truths):
        raise ValueError("split manifests must account for every prepared session")
    if "evaluation" in splits.values() and config.reference_index_path is None:
        raise ValueError("held-out evaluation requires a frozen reference index")

    reference = resolve(config.reference_index_path)
    model_artifact = resolve(config.model_artifact_path)
    calibration = resolve(config.calibration_path)
    frozen = {
        "config_sha256": sha256(config_path),
        "evidence_sha256": sha256(db_path),
        "split_sha256": split_digests,
        "labels_sha256": label_hash,
        "reference_sha256": _snapshot(reference),
        "model_artifact_sha256": _snapshot(model_artifact),
        "calibration_sha256": _snapshot(calibration),
        "prompt_hash": config.prompt_hash,
        "provider": config.provider,
        "model": config.model,
        "model_revision": config.model_revision,
        "seed": config.seed,
    }
    if reference is not None:
        index = read_index(reference)
        indexed = {
            document.source.source_uri
            for document in index.documents
            if document.source.collection == "cam-auth"
        }
        # Fail closed if any held-out CAM source remains searchable.
        held_out = {sid for sid, split in splits.items() if split == "evaluation"}
        with sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True) as db:
            held_out_sources = {
                row[0]
                for session_id in held_out
                for row in db.execute(
                    """SELECT src.path FROM sessions s JOIN sources src
                       ON src.id = s.source_id WHERE s.session_id = ?""",
                    (session_id,),
                )
            }
        if held_out_sources & indexed:
            raise ValueError("held-out sources are searchable in the reference index")

    rows: list[tuple[Truth, str | None]] = []
    fixture_rows: list[tuple[Truth, str | None]] = []
    usage = {
        "runs": 0,
        "tool_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "estimated_cost_usd": 0.0,
        "citation_valid": 0,
        "citation_checked": 0,
    }
    durations: list[float] = []
    with sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        runs = db.execute(
            """SELECT r.*, p.verdict, p.grounded FROM agent_runs r
               LEFT JOIN agent_reports p ON p.run_id = r.run_id
               ORDER BY r.started_at, r.run_id"""
        ).fetchall()
        latest: dict[str, sqlite3.Row] = {}
        for run in runs:
            if run["session_id"] in splits and splits[run["session_id"]] == "evaluation":
                if not run["fixture"] and not all(
                    (config.provider, config.model, config.model_revision, config.prompt_hash)
                ):
                    raise ValueError(
                        "hosted evaluation requires frozen provider/model/revision/prompt"
                    )
                latest[("fixture:" if run["fixture"] else "hosted:") + run["session_id"]] = run
        for session_id, split in splits.items():
            if split != "evaluation":
                continue
            for prefix, target in (("fixture:", fixture_rows), ("hosted:", rows)):
                run = latest.get(prefix + session_id)
                prediction = run["verdict"] if run and run["state"] == "completed" else None
                target.append((truths[session_id], prediction))
                if run:
                    usage["runs"] += 1
                    details = json.loads(run["usage_json"])
                    for name in ("tool_calls", "input_tokens", "output_tokens"):
                        usage[name] += details.get(name, 0)
                    usage["estimated_cost_usd"] += details.get("estimated_cost_usd") or 0
                    if run["finished_at"]:
                        durations.append(
                            (
                                datetime.fromisoformat(run["finished_at"])
                                - datetime.fromisoformat(run["started_at"])
                            ).total_seconds()
                        )
                    if prediction is not None:
                        usage["citation_checked"] += 1
                        usage["citation_valid"] += int(run["grounded"] == 1)

    result: dict[str, object] = {
        "schema_version": 1,
        "scope": "offline stored runs; no inference performed",
        "frozen": frozen,
        "coverage": coverage(db_path, labels),
        "splits": {
            name: list(splits.values()).count(name)
            for name in ("reference", "validation", "evaluation", "excluded")
        },
        "hosted_held_out": confusion(rows),
        "fixture_mechanics_only": confusion(fixture_rows),
        "usage_on_held_out": usage,
        "latency_on_held_out": latency(durations),
        "false_alerts_per_normal_hour": false_alert_rate(0, 0),
        "semantic_grounding": None,
        "limitations": [
            "Unknown truth is never normal; abstentions are excluded from decided confusion counts.",
            "Fixture runs are mechanics checks, not model accuracy evidence.",
            "No adjudicated normal exposure or human semantic review is available.",
        ],
    }
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"))
    run_id = hashlib.sha256(canonical.encode()).hexdigest()[:20]
    destination = output_root / run_id
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {"run_id": run_id, "results_path": str(destination / "results.json"), **result}
