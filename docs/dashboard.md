# SUS.NOT dashboard (Task 10)

A local Streamlit workspace with six sections: Overview, URL Investigator, AI
Text Investigator, Investigation History, Benchmarks, and Project Evidence.
Tagline: **Sus? Not on our watch.**

## Files and architecture

- `dashboard/app.py`: Streamlit entry point, sidebar navigation, forms, status
  displays, history pagination/detail views, saved benchmarks and evidence references.
- `dashboard/data.py`: fixed-loopback HTTP client, response validation, safe error
  messages, benchmark loading, confusion matrix and allowlisted history projection.
  Reuses existing backend response models as contracts only; never calls scoring
  or investigator functions. History/health/benchmark schemas are validated locally.
- `.streamlit/config.toml`: dark palette, system sans-serif typography, loopback
  binding and usage-statistics opt-out. No external fonts, tracking scripts or animations.
- `tests/test_dashboard.py`: mocked service/data tests and Streamlit AppTest checks.
- `backend/history.py`: adds read-only `GET /history-status` returning only
  `{"enabled": true|false}`. This disambiguates disabled history from enabled-but-empty
  without changing any existing endpoint response. No database path is exposed.

```text
Browser (localhost:8501) → Streamlit Python process
                           ├─ FastAPI (127.0.0.1:8000)
                           │   ├─ URL analyzer + policy
                           │   ├─ local text investigator → Ollama
                           │   └─ opt-in SQLite metadata
                           ├─ Ollama (127.0.0.1:11434/api/tags), status only
                           └─ local saved benchmark JSON + documentation
```

The dashboard and backend are separate processes. Fixed destinations prevent
submitted URLs or settings from redirecting service requests. HTTP environment
proxies and redirects are disabled. No dependencies were added; installed
Streamlit, httpx and Pydantic are used. Chrome extension behavior, score thresholds,
policy logic and existing API formats remain unchanged.

## Start locally

Run from the repository root in separate terminals, using the existing environment.

### 1. FastAPI

```sh
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

History is disabled by default. To explicitly enable the backend's local store:

```sh
SUSNOT_HISTORY_ENABLED=true .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Optional `SUSNOT_HISTORY_DB` selects a local database path. See
[investigation history](investigation-history.md) for schema, redaction, reset and
filesystem limitations. Do not place the database in a cloud-synced directory.

### 2. Ollama

```sh
ollama serve
```

If Ollama is already running (for example via its desktop app), do not start a
second server. Install the required model if absent:

```sh
ollama pull qwen3.5:4b-q4_K_M
ollama list
```

Pulling a model may require network access; inference uses local Ollama. The
dashboard does not automatically install or start models. A model appearing in
`/api/tags` establishes installation availability, not a successful inference test.

### 3. Streamlit

```sh
.venv/bin/python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

Open `http://127.0.0.1:8501`. Keep Streamlit and FastAPI bound to loopback; this is
not a hardened multi-user deployment. Overview refresh performs new status checks,
not cached or invented health reporting. Backend and Ollama checks are independent.
Unavailable services, invalid responses and missing saved artifacts produce safe
messages, not exception bodies. The text request timeout allows the backend's
90-second inference deadline; other requests have short timeouts.

## Endpoint usage and interaction

- Overview: `GET /health`, Ollama `GET /api/tags`, `GET /history-status`, and a
  one-record history page for the actual total when enabled. If a check fails,
  its status/count is unknown, not inferred from other checks or local environment.
- URL: `POST /analyze-url` displays the original SUS Score, risk, indicators and
  `message`; `POST /evaluate-url` displays the deterministic action, explanation
  and policy version. No scoring logic is duplicated. Policy failure does not hide
  a successful heuristic result. URLs are not visited.
- Text: `POST /analyze-text` displays indicators, explanation, recommendation and
  uncertainty as plain text. Local Qwen through Ollama is fallible, not proof of fraud.
- History: `GET /investigations?limit=…&offset=…` and explicit detail load through
  `GET /investigations/{UUID}`. Page sizes are 10, 20, 50 or 100. The backend validates
  pagination; the client validates pages too. New records may shift offset pages.
  Empty, out-of-range, disabled and unavailable states are distinguished.
- Benchmark: reads `benchmarks/results/url_evaluation.json`, never runs evaluation
  automatically. Displays saved size, threshold, TP/TN/FP/FN, precision, recall, F1,
  accuracy, confusion matrix, version and dataset hash. Synthetic scenario labels
  do not establish real-world fraud accuracy. No saved case URLs are displayed.
- Evidence: local documentation references with expandable source text, presence
  of the MCP implementation and reproducibility commands. MCP process liveness is
  not probed. Historical counts in documents describe those specific runs, not
  current/live testing. `EVIDENCE.md` is shown only if it contains evidence.

## Privacy and recording

Recording requires both backend enablement and an unchecked-by-default form option
for that submission. Forms clear after submission, including the recording choice.
Only the policy request records a URL investigation (one row rather than two);
text requests record only minimized metadata. No consent header is sent by default,
when status is unavailable, or when the backend reports recording disabled.
Recording failure is deliberately nonfatal on the backend: analysis success does
not prove that a record was saved. Check History to confirm.

History projection excludes all URL fields and unknown fields even if a response
contains them. Text history shows only the existing presence marker, not model
prose. Submitted URL values are not echoed in result panels. Untrusted findings
and explanations are rendered as plain text, not active HTML or clickable Markdown.
The dashboard does not log user submissions, cache analyses, write investigations
to disk, execute model instructions, or retain Chrome browsing history.

**Limits:** inputs and results exist transiently in browser/Streamlit process
memory and travel over local HTTP. Model responses may echo private input in the
current result view. Form clearing is not guaranteed memory erasure; use the sidebar
session-clear control to clear current widget/results state. Browser, OS, Streamlit,
Ollama and external debugging/logging configurations may have their own retention.
SQLite metadata is plaintext and the local interfaces have no user authentication.
Do not expose them remotely, enable body tracing, submit secrets unnecessarily or
assume comprehensive/independently audited privacy protection.

## Reproduce evaluation and tests

```sh
.venv/bin/python -m benchmarks.evaluate_urls
.venv/bin/python -m pytest -q
node --test tests/*.test.cjs
```

The evaluation uses only the synthetic fixtures and existing analyzer, requires no
running service, and overwrites `benchmarks/results/url_evaluation.json`. Retain
the dataset and code revision for reproducibility. See
[evaluation methodology](url-evaluation.md), [decision policy](decision-policy.md),
[MCP](mcp-server.md) and [text investigator](text-investigator.md).

Dashboard automated tests mock service requests: backend unavailable/timeouts,
invalid HTTP/JSON/schema responses, local-only transport, explicit consent headers,
model listing, empty/paginated history, UUIDs, minimized field projection, and
saved/missing/invalid benchmarks. AppTest exercises the six sections and form/data
flows. These are not live Qwen integration tests or a browser accessibility or
visual responsiveness audit. The dashboard never runs tests itself.

Task 10 verification: **219 Python tests and 14 Node tests passed**, including
43 dashboard tests. No live Ollama inference or manual browser layout audit was
performed for this task.


## Versioned benchmark dashboard (V1–V3)

The Benchmarks page reads offline saved artifacts only (no live model calls), validates dataset identity against canonical SHA-256 and checks row-level predictions/outcomes. It compares three different synthetic datasets without presenting their accuracy as successive model improvements. Each dataset has a confusion matrix, full case table with FP/FN filtering, and reproducibility command. V3 includes an exploratory threshold sweep calculated from stored scores, without changing the deployed warning threshold. See `docs/url-evaluation.md`.
