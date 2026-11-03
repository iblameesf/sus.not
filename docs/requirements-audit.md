# SUS.NOT — Final Requirements Audit

Updated: 2026-11-02

## University assignment

Official assignment: Coding for AI & Data Science, PGE3, 2026–2027.

Required local model: Qwen3.5-4B Q4_K_M.

Selected technical blocks: 1, 2, 3, 4, and 5.

## Technical evidence

| Block | Evidence | Status |
|---|---|---|
| 1 — Model-selected custom tool | evidence/qwen-tool-call.json | Real local Qwen tool invocation captured |
| 2 — MCP server | evidence/mcp-live-trace.json | Real MCP client/server invocation captured |
| 3 — Code-enforced restrictions | evidence/blocks3-4-verification.json | 27 targeted tests passed; specific violation trace needs final review |
| 4 — Decision model | benchmarks/results/url_evaluation.json | 32 synthetic scenarios evaluated; score is not calibrated |
| 5 — Persistent memory/context | evidence/block5-persistence.json | SQLite process-restart persistence passed; AI-memory interpretation and token-cost evidence remain open |

## Application acceptance

| Component | Result |
|---|---|
| Python tests | 531 passed |
| JavaScript tests | 14 passed |
| Backend smoke | Passed |
| Streamlit dashboard | User verified live |
| URL analysis | User verified live |
| Chrome Guardian normal mode | User verified live |
| Consent and permission revocation | User verified live |
| Local Qwen tool calling | Real execution captured |
| MCP | Real execution captured |
| SQLite persistence | Separate-process recovery passed |

## Decision-model limitations

The SUS Score is an experimental heuristic, not a calibrated
probability of fraud.

Synthetic URL evaluation:
- Cases: 32
- Threshold: 60
- True positives: 4
- True negatives: 14
- False positives: 2
- False negatives: 12
- Accuracy: 56.25%
- Precision: 66.67%
- Recall: 25%
- F1: 36.36%

Synthetic scenario labels are not verified real-world fraud labels.

## Remaining submission requirements

1. Confirm Blocks 4 and 5 satisfy the exact rubric.
2. Complete genuine AI conversation exports and session notes.
3. Verify README installation from a clean environment.
4. Review files for credentials and private information.
5. Review Git changes before committing.
6. Commit and push only after explicit approval.
7. Prepare final presentation and individual defence.

## Release policy

No production-grade phishing detection accuracy is claimed.

No incomplete Block 9 benchmark is presented as completed evidence.

No commit, push, or release occurs without explicit user approval.

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
