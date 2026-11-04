"""Versioned benchmark evidence consistency and threshold regression."""
import pytest
from dashboard.data import load_benchmark_version, threshold_sweep, DataError

@pytest.mark.parametrize("version,size,tp,tn,fp,fn", [
    ("V1", 32, 4, 14, 2, 12),
    ("V2", 100, 38, 48, 2, 12),
    ("V3", 100, 4, 48, 2, 46),
])
def test_saved_version(version, size, tp, tn, fp, fn):
    benchmark, rows = load_benchmark_version(version)
    assert benchmark.evaluation_version == version[1:]
    assert len(rows) == benchmark.dataset_size == size
    m = benchmark.metrics
    assert (m.true_positives, m.true_negatives, m.false_positives, m.false_negatives) == (tp, tn, fp, fn)

def test_threshold_sweep():
    _, rows = load_benchmark_version("V3")
    result = {row["Threshold"]: row for row in threshold_sweep(rows)}
    assert (result[15]["FP"], result[15]["FN"]) == (33, 15)
    assert (result[60]["FP"], result[60]["FN"]) == (2, 46)

def test_unknown_version_rejected():
    with pytest.raises(DataError):
        load_benchmark_version("V4")
