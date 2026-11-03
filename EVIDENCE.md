# SUS.NOT — Verified Evidence Register

**Status:** Working evidence document, not an official compliance certificate. All claims below are limited to available source files and user-reported terminal/browser observations. The official university rubric has not been supplied in this conversation.

## Current verified baseline (Mac, 2026-11-02)

| Check | Evidence | Result |
|---|---|---|
| Python regression suite | User terminal: `python -m pytest -q` | **531 passed** in 6.65 s |
| Browser Guardian JS suite | User terminal: `node --test tests/guardian.test.cjs` | **14 passed**, 0 failed |
| Controlled real-Chrome warning | User reported seeing 70/100 after applying patch | **Observed by user**, synthetic fixture only |
| Local model installation | User terminal: `ollama list` | `qwen3.5:4b-q4_K_M`, 3.3 GB |
| MCP implementation | `backend/mcp_server.py`, `tests/test_mcp_server.py`, `docs/mcp-server.md` | Source and automated SDK tests present; external client/live-model integration not independently proven |
| Documentation baseline | User audit of repository | `README.md` and `EVIDENCE.md` previously empty; populated by this patch |

## Technical evidence map (candidate blocks; check exact university rubric)

1. **Custom read-only tool:** `backend/mcp_server.py` (`inspect_url`, `inspect_text`); `tests/test_mcp_server.py` validates discovery/invocation. Capture an actual SDK invocation trace if required.
2. **MCP protocol server:** `backend/mcp_server.py`, `docs/mcp-server.md`. The server runs over stdio; no external client deployment claimed.
3. **Code-enforced guardrails:** `extension/guardian-core.js`, `extension/guardian.js`, `tests/guardian.test.cjs`; OFF-by-default, origin permissions, revocation, cancellation and warning threshold are tested.
4. **Deterministic decision model:** `backend/main.py`, `backend/decision_policy.py`, `benchmarks/evaluate_urls.py`, `docs/decision-policy.md`. Heuristic scores are not probabilities.
5. **Evaluation and comparison:** Existing synthetic URL/email benchmarks are available, **but do not satisfy a repeated-run/three-runs-per-task rubric without further work**. No repeated-run measurements are claimed.

## Existing URL benchmark (synthetic)

32 scenarios, threshold 60: TP=4, TN=14, FP=2, FN=12; precision=0.6667, recall=0.25, F1=0.3636, accuracy=0.5625. Labels are synthetic scenarios, not verified real-world fraud. Some labels depend on context unavailable to a URL-only detector. Source: user-reported contents of `benchmarks/results/url_evaluation.json`.

## Controlled browser warning

The user observed **70/100** in Chrome with the explicit demo fixture. This demonstrates browser/backend/warning integration, not production phishing sensitivity. The production pipeline sends only an origin; its present heuristics cannot normally reach 60 on such inputs. See `docs/step29-e2e-demo.md`.

## Still to substantiate

- [ ] Official assignment PDF and exact block/mark requirements; map line-by-line.
- [ ] README fresh-environment reproducibility, including dependency installation and local inference.
- [ ] Real MCP invocation transcript or screenshot as required by the rubric.
- [ ] Live local Qwen text inference evidence (without sensitive content) if not already captured.
- [ ] Consent/revocation real-browser evidence beyond simulated JS tests.
- [ ] Required repeated-run benchmark, if specified by the rubric; report mean, spread, failures, and methodology.
- [ ] Genuine AI-use log entries; never fabricate prompts, dates, or assistant activity.
- [ ] Review repository diff and secret scanning before any commit/push.

**Git:** No commit, push, or release authorized by this document.


## Final verification update — 2026-11-02

The official university assignment has been reviewed during project
finalization. The selected candidate blocks are 1, 2, 3, 4 and 5.

### Verified executions

| Requirement | Evidence | Result |
|---|---|---|
| Model-selected custom tool | `evidence/qwen-tool-call.json` | Live local Qwen tool invocation captured |
| MCP server | `evidence/mcp-live-trace.json` | Real stdio MCP client/server invocation captured |
| Code-enforced restrictions | `evidence/blocks3-4-verification.json` | 27 targeted tests passed |
| Decision evaluation | `benchmarks/results/url_evaluation.json` | 32 synthetic cases evaluated |
| Persistence across process restart | `evidence/block5-persistence.json` | Separate-process SQLite recovery passed |
| Python regression suite | `evidence/final-python-tests.log` | 531 passed |
| JavaScript regression suite | `evidence/final-node-tests.log` | 14 passed |
| Backend smoke | `evidence/final-smoke.log` | Passed; in-process only |

### Known limitations

- The SUS Score is an uncalibrated heuristic, not a fraud probability.
- Synthetic scenario labels are not verified real-world fraud labels.
- Persisted investigation metadata is not conversational LLM memory.
- Block 5 token-cost evidence remains outstanding.
- Live normal-mode Chrome and Streamlit acceptance remain outstanding.
- Fresh-clone reproducibility remains outstanding.
- The AI-use log still requires genuine conversation/session records.
- The interrupted Block 9 comparison is incomplete and is not
  submitted as a completed repeated-run benchmark.

### Documentation status

Earlier provisional statements in this document and
`docs/requirements-audit.md` predate the verification above.
They must not be interpreted as the latest project status.

## Block 5 — Persistence and measured context cost

SUS.NOT maintains optional, privacy-minimized investigation metadata in local SQLite storage.

**Restart evidence:** `evidence/block5-persistence.json` demonstrates that an investigation record written by one Python process remains available to a separate Python process.

**Measured context cost:** `evidence/block5-token-cost.json` records a controlled comparison using `qwen3.5:4b-q4_K_M`:

- Baseline prompt: 28 tokens.
- Prompt with synthetic investigation note: 51 tokens.
- Additional prompt cost: 23 tokens.
- Configured context budget: 8192 tokens.
- Additional context usage: 0.28%.

The measurement uses Ollama's `prompt_eval_count`.

**Reproduction:** Run `python -m scripts.verify_block5` for persistence verification. The token-cost evidence was collected using two Ollama `/api/chat` requests with identical settings except for an additional synthetic system message.

**Limitation:** The application does not automatically retrieve saved SQLite records into the model's prompt. The token comparison measures the cost of explicitly supplying a note, not autonomous recall.
