import hashlib
import json

import pytest
from test_hdfs import _archive

from hestia.evaluation.hdfs import TransitionBaseline
from hestia.evaluation.hdfs_refined import (
    CANDIDATES,
    ScoredTrace,
    candidate_scores,
    choose_validation,
    evaluate_refined_hdfs,
    normal_threshold,
    validation_error_analysis,
)


def test_length_and_peak_candidates_use_only_frozen_training_normal_counts():
    model = TransitionBaseline()
    model.learn(("E1", "E2", "E1"))
    normal_lengths = {"2": 3, "5": 1}
    from collections import Counter

    scores = candidate_scores(model, Counter(normal_lengths), ("E9", "E9"))
    assert tuple(scores) == CANDIDATES
    assert scores["mean_peak"] != scores["mean"]
    assert scores["mean_length"] > scores["mean"]


def test_validation_selection_and_error_sample_ignore_evaluation_labels():
    values = [0.1, 0.2, 0.3, 0.4, 0.8, 1.0]
    records = [
        ScoredTrace(f"blk_{index}", index + 1, 2 + index, {name: value for name in CANDIDATES})
        for index, value in enumerate(values)
    ]
    labels = {f"blk_{index}": index >= 4 for index in range(len(records))}
    labels["blk_999"] = True  # not in validation; may change without affecting selection
    selected, grid = choose_validation(records, labels, min_recall=0.95)
    assert selected["met_recall_target"] is True
    assert len(grid) == 12
    assert selected["confusion"]["recall"] == 1
    assert normal_threshold([0.1, 0.2, 0.3, 0.4], 0.95) == 0.4
    report = validation_error_analysis(records, labels, threshold=0.25)
    assert report["length_bin_counts"]["false_positive"] == {"5": 2}
    labels["blk_999"] = False
    assert choose_validation(records, labels, min_recall=0.95)[0] == selected


def test_refined_run_selects_on_validation_and_does_not_overwrite(tmp_path):
    archive, config_path = _archive(tmp_path, size=20, anomalies=(12, 13, 16))
    config = json.loads(config_path.read_text())
    config["min_validation_recall"] = 0.95
    config_path.write_text(json.dumps(config))
    result = evaluate_refined_hdfs(archive, config_path, tmp_path / "results")
    assert result["split_counts"] == {
        "training": 12,
        "validation": 4,
        "evaluation": 4,
        "cross_boundary": 0,
    }
    assert result["training_normal"] == 12
    assert result["evaluation_selected"]["anomalous"] == 1
    assert len(result["validation_grid"]) == 12
    assert result["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert result["selected"]["candidate"] in CANDIDATES
    with pytest.raises(FileExistsError):
        evaluate_refined_hdfs(archive, config_path, tmp_path / "results")


def test_evaluation_labels_cannot_choose_candidate_or_threshold(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    archive_a, config_a = _archive(first, size=20, anomalies=(12, 13, 16))
    archive_b, config_b = _archive(second, size=20, anomalies=(12, 13, 17, 19))
    result_a = evaluate_refined_hdfs(archive_a, config_a, first / "results")
    result_b = evaluate_refined_hdfs(archive_b, config_b, second / "results")
    assert result_a["selected"] == result_b["selected"]
    assert result_a["validation_grid"] == result_b["validation_grid"]
    assert (
        result_a["evaluation_selected"]["anomalous"] != result_b["evaluation_selected"]["anomalous"]
    )
