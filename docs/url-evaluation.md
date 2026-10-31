# Offline URL detector evaluation

## Purpose and scope

This benchmark measures the existing experimental URL SUS Score against a small, explicitly constructed set of labelled scenarios. It is separate from production code: it imports the existing analyzer but does not change scoring, decision-policy thresholds, FastAPI endpoints, MCP tools, or Chrome extension behavior. Qwen is not called or scored. No dependencies were added.

**Synthetic suspicious labels represent constructed test scenarios, not verified fraud.** No website, sender, redirect, or page content was inspected. The SUS Score remains experimental and is not a calibrated fraud probability.

## Dataset construction

`benchmarks/url_cases.json` contains 32 manually authored cases: 16 `benign` and 16 `suspicious`. Each has exactly:

- `id`: a unique stable identifier.
- `url`: a syntactically valid HTTP(S) URL.
- `expected_label`: `benign` or `suspicious`.
- `rationale`: the constructed context supporting the label.

Hosts use reserved example domains (`example.com`, `example.net`, `example.org`, and `.example`) or documentation-only IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). Userinfo and encoded query destinations also use synthetic example names. They must not be visited, fetched, or resolved.

The dataset includes ordinary pages, benign `verify`/`urgent` paths, query strings and fragments, userinfo, alternate ports, encoded spaces, trailing-dot hostnames, IPv4/IPv6 documentation addresses, multi-indicator scenarios, and suspicious scenarios without matching indicators.

Labels are **not assigned merely because a URL matches a scoring rule**. Suspicious rationales describe constructed impersonation, credential/MFA theft, advance-fee, or coercive-payment scenarios. Benign rationales describe ordinary navigation or authorized lab workflows, including two scenarios that trigger every rule. These contexts are fixtures, not observed evidence. In particular, the URL-only analyzer does not receive the rationale: some labels rely on context that cannot be inferred from URL syntax alone. The benchmark intentionally demonstrates this information gap.

This is a hand-selected coverage/challenge set, not a random sample or representative prevalence estimate. It was not used to tune the detector. Changing labels, URLs, or class balance changes the metrics; retain the dataset and code revision alongside results.

## Classification threshold

Prediction is `suspicious` if **SUS Score >= 60**, otherwise `benign`. This matches the start of the existing policy's warning band. A score in the 30–59 review band is therefore a negative prediction for this binary benchmark; that does not mean policy recommends proceeding without review.

The existing analyzer adds 30 for an IP host, 25 for `@` in the authority, and 15 for `verify` or `urgent` in the path. Its maximum currently achievable score is 70. With these rules, all three indicators are needed to reach the warning threshold. This explains many misses; no rule or threshold was changed to improve this dataset's results.

The script validates cases with the existing URL request model and calls `analyze_url` directly in Python. Parsing does not perform DNS, HTTP, or browsing. FastAPI and Ollama need not be running.

## Confusion matrix and metrics

The positive class is `suspicious`:

- **TP (true positive):** suspicious scenario with a score >= 60.
- **TN (true negative):** benign scenario with a score < 60.
- **FP (false positive):** benign scenario with a score >= 60.
- **FN (false negative):** suspicious scenario with a score < 60.

Current dataset results:

| Actual \\ Predicted | suspicious | benign |
| --- | ---: | ---: |
| suspicious | TP = 4 | FN = 12 |
| benign | FP = 2 | TN = 14 |

| Metric | Formula | Result |
| --- | --- | ---: |
| Precision | TP / (TP + FP) | 0.6667 |
| Recall | TP / (TP + FN) | 0.2500 |
| F1 score | 2 TP / (2 TP + FP + FN) | 0.3636 |
| Accuracy | (TP + TN) / total | 0.5625 |

Precision asks how many warnings correspond to suspicious labels. Recall asks how many suspicious labels receive warnings. F1 balances precision and recall using their harmonic mean. Accuracy is the proportion of all cases whose binary predictions match the labels. All zero-denominator ratios are reported as `0.0` by convention, including an empty evaluation; undefined precision/recall must not be interpreted as measured quality.

The terminal report prints the matrix, metrics, and every misclassified case with its ID, URL, score, FP/FN category, and rationale. The JSON artifact retains every case, its prediction, indicators, risk level, and outcome, plus a separate misclassification list.

## False positives, false negatives, and limits

The two false positives (`benign-15`, `benign-16`) are authorized lab workflows. Their syntax alone resembles risky patterns. Such warnings can cause unnecessary concern, interruption, and warning fatigue.

The twelve false negatives (`suspicious-05` through `suspicious-16`) include impersonation and credential requests with ordinary-looking URLs, redirect parameters/fragments that are not scored, and cases with only one or two indicators below the warning threshold. A low score does not establish safety; missing context can hide harmful intent.

These results **do not establish real-world fraud detection accuracy**:

- There are no verified malicious or benign live-site observations, independent adjudication, or representative sampling.
- Class balance and scenarios are artificially selected; precision especially depends on prevalence.
- The detector sees only syntax, while fixture rationales may supply sender intent or workflow context.
- The dataset is tiny, static, and deliberately includes rule coverage and blind spots. It is not a held-out field study or an adversarial robustness evaluation.
- No uncertainty interval, population-level performance claim, or calibrated fraud likelihood follows from these numbers.

Warnings remain advisory and dismissible. Evaluation neither blocks websites nor marks emails as spam. Do not optimize rules against this small set; stronger evidence would require a separately designed, ethically sourced, independently labelled and representative evaluation.

## Reproduce

From the repository root, with the existing environment:

```sh
.venv/bin/python -m benchmarks.evaluate_urls
```

This prints the report and overwrites:

```text
benchmarks/results/url_evaluation.json
```

No network access, running API server, or local model is required. The script uses fixed input order, no randomness, no timestamps, and stable JSON serialization. It includes an evaluation-format version (`"1"`), threshold, dataset size, and SHA-256 of normalized validated cases. The hash identifies dataset content/order, not analyzer source code: identical results require the same code revision as well. There is no model-generated text in the artifact.

Run all tests:

```sh
.venv/bin/python -m pytest -q
node --test tests/guardian.test.cjs
```

Verified for Task 8: **158 Python tests and 14 Node tests pass**. `tests/test_url_evaluation.py` checks dataset shape, minimum size, unique IDs, reserved hosts, label validity, invalid cases, metric arithmetic, zero denominators, threshold inclusion at 60, exact reproducibility and saved-artifact consistency, misclassification reporting, and evaluation with network/DNS calls forbidden. All existing tests remain in the full suite.
