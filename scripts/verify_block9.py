"""Verify Block 9: Recalculate recorded Qwen benchmark metrics."""

import json
import math
import statistics
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "block9_comparison.json"

MODES = ("baseline", "tool")
EXPECTED_MODEL = "qwen3.5:4b-q4_K_M"


def close(actual, expected, tolerance=0.001):
    assert math.isclose(
        actual, expected, rel_tol=0, abs_tol=tolerance
    ), f"Metric mismatch: calculated={actual}, recorded={expected}"


def main():
    print("===== BLOCK 9 VERIFICATION =====")

    assert EVIDENCE.is_file(), "Block 9 evidence file missing"

    data = json.loads(EVIDENCE.read_text())

    assert data["status"] == "complete"
    assert len(data["rows"]) == 60

    rows = data["rows"]
    metrics = data["metrics"]

    assert set(metrics) == set(MODES)

    for mode in MODES:
        selected = [row for row in rows if row["mode"] == mode]

        assert len(selected) == 30, f"{mode}: expected 30 executions"

        keys = [(row["id"], row["repeat"]) for row in selected]
        assert len(keys) == len(set(keys)), (
            f"{mode}: duplicate scenario/repeat combination"
        )

        assert set(row["repeat"] for row in selected) == {1, 2, 3}

        counts = Counter(row["repeat"] for row in selected)
        assert all(counts[repeat] == 10 for repeat in (1, 2, 3))

        for row in selected:
            assert row["model"] == EXPECTED_MODEL
            assert row["expected_label"] in {"benign", "suspicious"}
            assert row["status"] in {"ok", "error", "timeout", "failed"}
            assert isinstance(row["elapsed_seconds"], (int, float))
            assert math.isfinite(row["elapsed_seconds"])
            assert row["elapsed_seconds"] >= 0

            if row["status"] == "ok":
                assert row["predicted_label"] in {
                    "benign", "suspicious"
                }
                assert row["correct"] == (
                    row["predicted_label"] == row["expected_label"]
                )
            else:
                assert row["correct"] is False

        correct = sum(row["correct"] is True for row in selected)
        failed = sum(row["status"] != "ok" for row in selected)

        per_run_accuracy = [
            sum(
                row["correct"] is True
                for row in selected
                if row["repeat"] == repeat
            ) / 10
            for repeat in (1, 2, 3)
        ]

        accuracy = correct / len(selected)
        mean_accuracy = statistics.mean(per_run_accuracy)
        sample_sd = statistics.stdev(per_run_accuracy)
        mean_latency = statistics.mean(
            row["elapsed_seconds"] for row in selected
        )

        recorded = metrics[mode]

        assert recorded["total"] == len(selected)
        assert recorded["correct_total"] == correct
        assert recorded["failed_executions"] == failed

        for calculated, saved in zip(
            per_run_accuracy, recorded["per_run_accuracy"]
        ):
            close(calculated, saved)

        close(accuracy, recorded["mean_accuracy"])
        close(mean_accuracy, recorded["mean_accuracy"])
        close(sample_sd, recorded["sample_sd_accuracy"])
        close(mean_latency, recorded["mean_latency_seconds"])

        print(f"\n{mode.upper()}")
        print(f"Executions: {len(selected)}")
        print(f"Correct: {correct}")
        print(f"Accuracy: {accuracy:.2%}")
        print(f"Failed executions: {failed}")
        print(f"Mean latency: {mean_latency:.3f}s")
        print(f"Sample SD of run accuracy: {sample_sd:.2%}")
        print("Recorded metrics: PASS")

    baseline_ids = {
        (row["id"], row["repeat"])
        for row in rows if row["mode"] == "baseline"
    }
    tool_ids = {
        (row["id"], row["repeat"])
        for row in rows if row["mode"] == "tool"
    }

    assert baseline_ids == tool_ids, (
        "Baseline and tool modes use different scenario/repeat sets"
    )

    print("\nScenario pairing: PASS")
    print("BLOCK 9: PASS (recorded benchmark metrics validated)")
    print("Limitation: No Qwen executions were rerun.")
    print("Limitation: Synthetic labels are not real-world fraud labels.")


if __name__ == "__main__":
    main()
