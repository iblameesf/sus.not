# Versioned benchmark evidence (V1 / V2 / V3)

All evaluations use the **same unchanged deterministic URL-only analyzer** and warning threshold **SUS Score ≥ 60**. Scores are heuristic indicators, not calibrated fraud probabilities. Qwen, MCP, browsing, DNS and HTTP requests are not involved. All labels are constructed synthetic scenarios, **not verified fraud**. Case rationales may include sender/page context that the analyzer cannot observe.

| Dataset | Cases | TP | TN | FP | FN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V1 original baseline | 32 | 4 | 14 | 2 | 12 | 56.25% | 66.67% | 25.00% | 36.36% |
| V2 repetitive-pattern stress test | 100 | 38 | 48 | 2 | 12 | 86.00% | 95.00% | 76.00% | 84.44% |
| V3 challenge set | 100 | 4 | 48 | 2 | 46 | 52.00% | 66.67% | 8.00% | 14.29% |

**These are not successive model improvements.** V2 appends 68 synthetic cases with repeated, easily recognized patterns; all 34 new suspicious cases trigger the same three indicators, inflating performance on that constructed distribution. V3 adds single-indicator and context-dependent suspicious cases, which the score-60 threshold misses. V3 is a deliberately challenging development/evaluation set, not a random or independently held-out sample. The datasets have different composition and do not establish population-level precision or recall. Neither tuning a threshold on V3 nor re-testing it on V3 establishes independent improvement.

## Reproduce from repository root

```bash
.venv/bin/python -m benchmarks.evaluate_urls --version 1
.venv/bin/python -m benchmarks.evaluate_urls --version 2
.venv/bin/python -m benchmarks.evaluate_urls --version 3
.venv/bin/python -m pytest -q tests/test_benchmark_versions.py
```

The original `.venv/bin/python -m benchmarks.evaluate_urls` still evaluates V1 and writes `benchmarks/results/url_evaluation.json`. Versioned results live in `benchmarks/results/url_evaluation_v{1,2,3}.json`; source datasets are `benchmarks/url_cases_v{1,2,3}.json`. The dashboard loads saved artifacts without running the analyzer, checks normalized dataset SHA-256, dataset sizes, case alignment and confusion counts. Each version records its correct `evaluation_version`. Re-running evaluation updates saved artifacts using current code; commit the code revision and datasets with evidence for reproducibility.

## V3 threshold exploration (same saved scores, not a new model)

| Threshold | Accuracy | Precision | Recall | F1 | FP | FN |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 15 | 52.00% | 51.47% | 70.00% | 59.32% | 33 | 15 |
| 25 | 53.00% | 53.19% | 50.00% | 51.55% | 22 | 25 |
| 30 | 44.00% | 41.67% | 30.00% | 34.88% | 21 | 35 |
| 40 | 45.00% | 35.29% | 12.00% | 17.91% | 11 | 44 |
| 45 | 44.00% | 31.25% | 10.00% | 15.15% | 11 | 45 |
| 55 | 43.00% | 26.67% | 8.00% | 12.31% | 11 | 46 |
| 60 | 52.00% | 66.67% | 8.00% | 14.29% | 2 | 46 |
| 70 | 52.00% | 66.67% | 8.00% | 14.29% | 2 | 46 |

The 60-point threshold is unchanged. Lowering it increases warnings but also raises false positives substantially; this exploratory comparison is **not** a policy recommendation. The heuristic adds 30 for IP hostname, 25 for `@` authority and 15 for `verify`/`urgent` path. The maximum observed/achievable score is 70 under current rules. Review-band scores below 60 count as negative only in this binary benchmark; they are not a declaration of safety. See the case-level dashboard for false-positive/false-negative rationales.

## Provenance and limitations

All three datasets use reserved documentation domains/IP ranges and must not be visited. The analyzer inspects URL syntax only; it cannot validate the sender, page contents, redirect behavior or real-world maliciousness. Balanced labels are artificial, not deployment prevalence. Synthetic metrics cannot be interpreted as real-world detection accuracy. The SHA-256 in each result is over normalized, validated JSON case data (not raw file bytes). Reproducibility requires the dataset, code revision, evaluation command and saved result. A representative independent labelled evaluation would be needed for performance claims.

---

## Original V1 methodology (retained)

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
