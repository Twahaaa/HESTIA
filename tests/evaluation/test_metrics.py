from hestia.evaluation.contracts import Truth
from hestia.evaluation.metrics import confusion, false_alert_rate, latency, wilson


def test_hand_counted_confusion_and_abstention():
    result = confusion(
        [
            (Truth.attack, "malicious"),
            (Truth.attack, "benign"),
            (Truth.normal, "suspicious"),
            (Truth.normal, "benign"),
            (Truth.attack, "insufficient_evidence"),
            (Truth.unknown, "benign"),
        ]
    )
    assert (result["tp"], result["fn"], result["fp"], result["tn"]) == (1, 1, 1, 1)
    assert result["abstained"] == 1
    assert result["unknown_truth"] == 1
    assert result["precision"] == result["recall"] == result["f1"] == 0.5
    assert result["decision_coverage"] == 0.8
    assert result["precision_ci95"] == wilson(1, 2)


def test_undefined_denominators_do_not_imply_perfection():
    result = confusion([(Truth.unknown, "malicious"), (Truth.normal, None)])
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["f1"] is None
    assert result["decision_coverage"] == 0
    assert wilson(0, 0) is None
    assert false_alert_rate(0, 0) is None
    assert false_alert_rate(2, 4) == 0.5
    assert latency([])["p95_seconds"] is None
    assert latency([1, 2, 3, 4, 5])["p95_seconds"] == 5
