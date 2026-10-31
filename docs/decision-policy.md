# URL decision policy — version 1

## Detection versus decision-making

**Detection** (`backend/main.py:analyze_url`) inspects URL syntax and produces indicators, a heuristic SUS Score, and a risk level without visiting the URL. Existing rules and thresholds are unchanged.

**Decision-making** (`backend/decision_policy.py:evaluate_url_result`) maps that score to a consistent, advisory recommendation. It does not add evidence or change the score. Qwen's text findings are not inputs to this policy and are not combined into a numerical score.

The reusable function accepts an existing validated `AnalyzeURLResponse`. Its score is revalidated as a strict integer from 0 through 100: booleans, strings (including numeric strings), nulls, floats, negative values, and values above 100 are rejected with a Pydantic `ValidationError`. Integer-only validation matches the current analyzer's score domain. It derives the risk level itself rather than trusting an incoming label. Other fields, including indicators, explanatory prose, or attempted AI/action overrides, cannot influence the decision.

Callers must supply results from the trusted analyzer. Schema validation cannot prove provenance: fabricated numerical scores are not authenticated evidence. The HTTP endpoint avoids this issue by accepting a URL and running the analyzer itself, not accepting client-supplied investigation scores.

## Provisional policy v1

`policy_version` is the string `"1"`.

| Integer SUS Score | Risk level | Recommended action |
| --- | --- | --- |
| 0–29 | low | `continue_with_caution` |
| 30–59 | review | `review_before_proceeding` |
| 60–79 | high | `show_warning` |
| 80–100 | critical | `strong_warning` |

Output has exactly `sus_score`, `risk_level`, `recommended_action`, `explanation`, and `policy_version`. Explanations are fixed application text per band. They explicitly state that **SUS Score is experimental and does not represent a calibrated fraud probability**, and that warnings are **advisory and dismissible**.

This is a pure recommendation function: no network calls, model calls, persistence, blocking, email classification, or action execution. It does not automatically block websites or mark emails as spam. There is no new warning UI; any future consumer must keep warnings dismissible. The existing Chrome extension, its permissions, and its behavior are unchanged.

## Why enforce decisions in code?

Code makes score validation and band boundaries explicit, repeatable, reviewable, and testable. An AI prompt cannot guarantee consistent actions or prevent untrusted text from changing a recommendation. Here no AI output is evaluated as policy instructions; the only decision input is the strictly validated numerical score. The same score produces the same complete decision each time. Future changes to this mapping should use a new policy version.

## API and reuse

Optional additional endpoint (clients need not use it):

```sh
curl -sS http://127.0.0.1:8000/evaluate-url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://user@192.0.2.1/verify"}'
```

Returns score `70`, risk `high`, action `show_warning`, the application-owned explanation, and policy version `"1"`. Invalid URLs return 422 using the existing URL request validation. Only the URL is used; extra request fields follow the existing request model's ignore behavior and cannot override the score or policy.

Start FastAPI as before:

```sh
.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Python reuse:

```python
from backend.main import AnalyzeURLRequest, analyze_url
from backend.decision_policy import evaluate_url_result

result = analyze_url(AnalyzeURLRequest(url="https://example.com"))
decision = evaluate_url_result(result)
```

`POST /analyze-url` retains its original five-field response (`url`, `sus_score`, `risk_level`, `indicators`, `message`). `/analyze-text`, `/health`, and MCP `inspect_url`/`inspect_text` are unchanged. The new policy does not require Ollama.

## Limitations and false positives

- These bands are provisional, not statistically calibrated. A low score is not a safety guarantee and a high score is not proof of fraud.
- Legitimate URLs can contain IP addresses, user information, or words such as `verify` and `urgent`; these can cause false positives. Malicious URLs without these features can score zero (false negatives).
- The analyzer does not verify ownership, sender identity, page content, reputation, or context. Policy cannot recover evidence that detection never collected.
- The current scoring rules can produce at most **70** (30 + 25 + 15). The 80–100 policy band is implemented and tested using synthetic validated results; no scoring rule was changed to make it reachable.
- Dismissibility is a requirement for consumers, not a UI implemented by this backend function. Recommendations must not be treated as permission to take autonomous action.

## Tests

```sh
.venv/bin/python -m pytest -q
node --test tests/guardian.test.cjs
```

`tests/test_decision_policy.py` covers every band, boundaries 0/29/30/59/60/79/80/100, strict invalid-score rejection, repeated deterministic decisions for all 101 valid scores, resistance to prose/AI overrides, the new endpoint's URL validation and analyzer reuse, and unchanged `/analyze-url` output. The full suite also exercises existing FastAPI and MCP functionality and extension behavior. No live AI inference is needed for this task.
