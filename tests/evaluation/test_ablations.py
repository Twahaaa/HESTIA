import pytest

from hestia.evaluation.ablations import Arm, ArmRecord, validate_matrix


def test_ablation_comparisons_require_four_distinct_matched_arms():
    rows = tuple(
        ArmRecord(
            arm=arm,
            dataset_hash="data",
            model=None if arm is Arm.normality_only else "provider/model",
            model_revision="rev",
            budget_hash="budget",
            case_ids=("case1",),
            run_order=i,
        )
        for i, arm in enumerate(Arm)
    )
    validate_matrix(rows)
    with pytest.raises(ValueError, match="case_ids"):
        validate_matrix(rows[:-1] + (rows[-1].model_copy(update={"case_ids": ("other",)}),))
    with pytest.raises(ValueError, match="four distinct"):
        validate_matrix(rows[:-1])
