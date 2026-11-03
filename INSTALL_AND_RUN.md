# SUS.NOT — Installation and Run Guide

## Prerequisites

- macOS with Python 3.12
- Git
- Ollama
- Google Chrome
- Node.js for JavaScript tests

Required local AI model: `qwen3.5:4b-q4_K_M`.

No paid AI API is required.

## Clone the repository

    git clone https://github.com/iblameesf/sus.not.git
    cd sus.not

The final development changes must be pushed before this clone
contains the completed application.

## Install dependencies

    python3.12 -m venv .venv
    source .venv/bin/activate
    python -m pip install -r requirements.txt

## Install the local model

    ollama pull qwen3.5:4b-q4_K_M
    ollama list

Ollama must be running locally on port 11434.

## Start the backend

From the repository root:

    source .venv/bin/activate
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

Health endpoint: http://127.0.0.1:8000/health

## Start the dashboard

In another terminal, from the repository root:

    source .venv/bin/activate
    python -m streamlit run dashboard/app.py

Open the local address printed by Streamlit.

## Install the Chrome extension

1. Open chrome://extensions.
2. Enable Developer mode.
3. Select Load unpacked.
4. Choose the extension directory.
5. Enable Guardian Mode only when you intend to monitor a site.
6. Grant permissions only to selected websites.

Guardian warnings are advisory and dismissible.

## Run the MCP server

    source .venv/bin/activate
    python -m backend.mcp_server

The MCP server communicates through standard input/output.

## Run tests

    source .venv/bin/activate
    python -m pytest -q
    node --test tests/guardian.test.cjs

Reported development baseline:
- 534 Python tests passed.
- 14 JavaScript tests passed.

Fresh-clone reproducibility has not yet been independently verified.

## Optional synthetic evaluations

    python -m benchmarks.evaluate_urls
    python -m benchmarks.evaluate_emails

The experimental 60-call Qwen benchmark is not required for
installation or normal application operation.

## Security and privacy

- Never commit credentials, OAuth tokens, or private messages.
- Guardian monitoring requires explicit activation.
- SUS Scores are uncalibrated heuristics, not fraud probabilities.
- The application is a university research prototype.

See README.md, EVIDENCE.md, and docs/architecture-final.md
for further details.
