# SUS.NOT — Privacy-First Student Security Guardian

SUS.NOT is a local-first university cybersecurity prototype. It combines deterministic URL assessment, local Qwen text investigation, an opt-in Chrome Manifest V3 Guardian, email evidence analysis, MCP tools, and a Streamlit dashboard. Its findings are **advisory**; it does not prove that a site is fraudulent or automatically block navigation.

## Environment
- Python 3.12 (tested on macOS / Apple Silicon)
- Ollama installed and running locally, with model `qwen3.5:4b-q4_K_M`
- Node.js (for JavaScript tests), Chrome (for extension demo)
- Python dependencies pinned in `requirements.txt`

## First-time setup
From the repository root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
ollama pull qwen3.5:4b-q4_K_M
ollama list
```

Ollama must be running on `http://127.0.0.1:11434` before live text inference. Installing the model does not itself prove inference works. Never commit OAuth credentials, tokens, personal emails, or `.env` files.

## Run the application
Open separate terminals at the repository root:

```bash
# Terminal 1 — FastAPI backend
source .venv/bin/activate
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

```bash
# Terminal 2 — Streamlit dashboard
source .venv/bin/activate
python -m streamlit run dashboard/app.py
```

Open the local URL printed by Streamlit (typically `http://localhost:8501`; the port can differ). Backend health: `http://127.0.0.1:8000/health`.

## Chrome Guardian
Open `chrome://extensions`, enable Developer mode, select **Load unpacked**, and choose the `extension/` directory. The Guardian starts OFF. Use **SELECTED_WEBSITES** and grant permission only to origins you intend to monitor. Automatic monitoring sends the **origin only**, not the full URL, and produces advisory warnings at score >= 60. It does not inspect webpage contents. See `docs/guardian-mode.md` and `docs/step29-e2e-demo.md`.

## MCP tools
Run the local stdio MCP server with:

```bash
source .venv/bin/activate
python -m backend.mcp_server
```

The server exposes read-only `inspect_url` and `inspect_text` tools. Standard output is reserved for MCP protocol messages. See `docs/mcp-server.md` and `tests/test_mcp_server.py` for the SDK-client test. No remote MCP deployment is implied.

## Verification

```bash
source .venv/bin/activate
python -m pytest -q
node --test tests/guardian.test.cjs
python -m benchmarks.evaluate_urls
python -m benchmarks.evaluate_emails
```

**Reported Mac baseline, 2 Nov 2026:** 534 Python tests and 14 Node tests passed (548 total). These are user-reported results from the patched local working tree, not a fresh-install validation. URL benchmark results are synthetic and do not establish real-world phishing-detection accuracy.

## Controlled browser demonstration
Only for a local demonstration, run the backend with `SUSNOT_DEMO_MODE=1` and serve a local page at `http://127.0.0.1:8765`. The exact loopback origin receives a synthetic 70/100 result to exercise the actual Chrome warning pipeline. **Stop the demo backend and restart without `SUSNOT_DEMO_MODE` afterward.** See `docs/step29-e2e-demo.md` for the procedure. The demo does not validate production detection sensitivity.

## Evaluation and evidence
- `benchmarks/url_cases.json`: 32 synthetic URL scenarios; see `benchmarks/results/url_evaluation.json` and `docs/url-evaluation.md`.
- `benchmarks/email_cases.json`: 12 synthetic email scenarios.
- `EVIDENCE.md`: observed results, evidence references, and outstanding checks.
- `docs/architecture-final.md`: architecture and trust boundaries.
- `docs/requirements-audit.md`: provisional compliance audit; verify against the official assignment PDF.
- `ai_log/`: add genuine, attributable development records; do not invent historical prompts or results.

## Security limitations
The production origin-only Guardian does not normally reach HIGH using the current URL heuristics; the 70/100 warning is a controlled fixture. The URL benchmark has low recall on synthetic scenarios. A low SUS Score does not mean safe. Gmail live authorization and external integrations require explicit consent and separate validation. This is a research prototype, not production-grade phishing protection.
