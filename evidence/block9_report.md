# SUS.NOT — Block 9 measured comparison

Both systems ran locally on Qwen3.5-4B. Synthetic scenario labels are not real-world ground truth.

| System | Runs | Mean accuracy | Sample SD | Errors | Mean latency |
|---|---:|---:|---:|---:|---:|
| baseline | 3 × 10 | 70.0% | 10.0% | 9 | 135.53s |
| tool | 3 × 10 | 90.0% | 0.0% | 0 | 21.15s |

## First observed failure (actual trace)

```json
{
  "id": "benign-05",
  "repeat": 1,
  "mode": "baseline",
  "expected_label": "benign",
  "url": "https://example.org/verify-email-help",
  "scenario_rationale": "Constructed help article explaining email verification; no credentials are requested.",
  "model": "qwen3.5:4b-q4_K_M",
  "label_source": "synthetic scenario; not verified fraud",
  "status": "error",
  "error": "ReadTimeout: ",
  "correct": false,
  "elapsed_seconds": 180.034
}
```

## Limits

URL strings alone do not establish fraud. The SUS score is a heuristic; results are not real-world safety accuracy.
