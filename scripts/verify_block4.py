"""Verify Block 4: Recalculate synthetic URL decision-model metrics."""

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "benchmarks" / "results" / "url_evaluation.json"


def main():
    print("===== BLOCK 4 VERIFICATION =====")

    assert EVIDENCE.is_file(), "Block 4 benchmark evidence missing"

    data = json.loads(EVIDENCE.read_text())

    cases = data["cases"]
    assert len(cases) == data["dataset_size"] == 32
    assert data["warning_threshold"] == 60

    outcomes = Counter()

    for case in cases:
        expected = case["expected_label"]
        predicted = case["predicted_label"]
        score = case["sus_score"]

        assert expected in {"benign", "suspicious"}
        assert predicted in {"benign", "suspicious"}
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100

        calculated_prediction = (
            "suspicious" if score >= 60 else "benign"
        )
        assert predicted == calculated_prediction, (
            f"Prediction mismatch: {case['id']}"
        )

        if expected == "suspicious":
            outcome = "tp" if predicted == "suspicious" else "fn"
        else:
            outcome = "fp" if predicted == "suspicious" else "tn"

        assert case["outcome"].lower() == outcome, (
            f"Outcome mismatch: {case['id']}"
        )

        outcomes[outcome] += 1

    tp = outcomes["tp"]
    tn = outcomes["tn"]
    fp = outcomes["fp"]
    fn = outcomes["fn"]

    total = tp + tn + fp + fn

    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    assert (tp, tn, fp, fn) == (4, 14, 2, 12)

    print(f"Scenarios: {total}")
    print(f"TP: {tp} | TN: {tn} | FP: {fp} | FN: {fn}")
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")
    print(f"F1 score: {f1:.2%}")

    assert abs(accuracy - 0.5625) < 1e-6
    assert abs(precision - 2 / 3) < 1e-6
    assert abs(recall - 0.25) < 1e-6
    assert abs(f1 - 4 / 11) < 1e-6

    print("Individual scenario classifications: PASS")
    print("Confusion matrix recalculation: PASS")
    print("Metric recalculation: PASS")
    print("BLOCK 4: PASS (recorded benchmark independently recalculated)")
    print("Limitation: Synthetic labels do not establish real-world accuracy.")


if __name__ == "__main__":
    main()
