# Controlled investigation orchestration (Task 11)

## Workflow

`POST /investigate` accepts an optional `url` and optional `text`; at least one
must be present. It reuses the existing HTTP(S) URL validator and the nonblank,
5,000-character text limit. Unknown request fields are rejected (422).

Application code generates a UUID, starts the existing local MCP server, initializes
an SDK client session, discovers tools, and executes a fixed plan:

1. For a URL, call `inspect_url`, validate its structured output, then pass its
   original SUS Score to existing Decision Policy v1. No scoring logic or thresholds
   change. Inconsistent risk labels and malformed outputs are rejected.
2. For text, call `inspect_text`, which runs the existing local Qwen/Ollama pipeline.
3. Return separate URL and text assessments, uncertainty, attempted tools, and errors.

The report contains:

- `investigation_id`: ephemeral workflow UUID, generated independently of storage.
- `url_assessment`: original score, risk level, indicators, inspection explanation,
  and a separate deterministic `decision`, or null.
- `ai_text_assessment`: indicators, explanation, recommendation, and the AI's
  uncertainty (including the existing application-owned caveat), or null.
- `recommended_action` and `policy_version`: URL policy values only, otherwise null.
  Text advice stays inside the AI assessment and never overrides URL policy.
- `uncertainty`: URL limitations and/or the text assessment's uncertainty, plus a
  partial-failure warning when necessary.
- `tools_used`: allowlisted tools attempted, in order; a missing tool is not listed.
- `errors`: sanitized per-tool failures. An empty list means both requested
  investigations completed. There is **no combined numerical fraud score**.

## MCP communication

The installed MCP SDK's `stdio_client` and `ClientSession` connect to
`sys.executable -m backend.mcp_server` in the fixed project directory. This is an
actual MCP protocol connection, not a direct Python call to the tool handlers.
A new child/session is closed after each investigation. Tool discovery supports
bounded pagination. Extra advertised tools confer no authority.

Only `inspect_url` and `inspect_text` are permitted. The invocation boundary checks
the allowlist, discovery, and each tool's existing argument schema. Executable,
module, working directory, and argument names are code-owned; submitted inputs
travel as MCP data, never as shell arguments. Ambient secrets are not explicitly
forwarded to the child, and its stderr is discarded to avoid relaying tool errors
or sensitive content into API logs.

## Qwen's role and enforced boundaries

`inspect_text` uses `qwen3.5:4b-q4_K_M` through the existing fixed
`http://127.0.0.1:11434/api/chat` client. The original system prompt, JSON-wrapped
untrusted message, structured response schema, timeouts, no-redirect behavior,
and disabled environment proxies remain unchanged.

Qwen receives no tool definitions and cannot choose, initiate, or chain tool calls.
Model output is validated assessment data only. Neither submitted instructions nor
returned prose can trigger shell commands, file access, browsing, email, or policy
changes. The only process launch is the fixed, application-owned MCP server.
The workflow never fetches submitted URLs or performs DNS lookups for them; URL
inspection is lexical. In a combined request, only the text input is sent to Qwen.

## Failures and privacy

- MCP startup, initialization, or discovery failures return sanitized HTTP 503.
- An overall workflow deadline returns HTTP 504. Startup/discovery are bounded to
  10 seconds after transport startup; each tool call is bounded to 95 seconds.
  An outer deadline also bounds transport startup/shutdown and all tools together.
- An established session returns HTTP 200 with explicit `errors` for tool errors,
  unavailable tools, invalid structured output, or per-call timeouts. Successful
  independent assessments remain available. Clients must inspect `errors`.
- The existing MCP text tool intentionally collapses Ollama unavailability, missing
  model, model timeouts, and invalid model responses into a sanitized tool error.
  The orchestration preserves that contract rather than parsing error prose.
- Tool error bodies and raw exception messages are not returned.

No raw URL, text, or model prose is automatically stored. Existing history requires
**both** `SUSNOT_HISTORY_ENABLED=true` and `X-SUSNOT-Record-History: true`. With both
set, this workflow writes the existing minimized URL/text metadata records (two
records for a combined investigation). URL identifiers are redacted to scheme;
URL tool prose is omitted, and AI indicators become only a fixed presence marker.
History retains its existing record IDs and schema: the response's workflow UUID
is not a history lookup ID. Existing endpoints and extension behavior are unchanged.

## Security limitations

This is controlled orchestration, not an OS sandbox or an autonomous agent.
The local MCP implementation, Python installation, and Ollama service must be
trusted. Structured validation does not prove that AI advice is accurate or free
of prompt-injection influence; treat all model prose as untrusted advisory text,
never executable instructions or HTML. URL heuristics cannot establish safety.
The model may be wrong, and no linked content or sender identity is verified.
There is no new authentication, rate limiting, or concurrency queue; keep this
local experimental service private. Each request starts a subprocess, and large
numbers of concurrent requests can exhaust resources.

## Try it

From the project root, with the existing virtual environment active:

```sh
ollama serve  # if not already running
# Install the existing required model if necessary:
ollama pull qwen3.5:4b-q4_K_M
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
curl -s http://127.0.0.1:8000/investigate \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://user@192.0.2.1/verify","text":"Pay immediately to avoid account closure."}'

# URL-only does not require Ollama:
curl -s http://127.0.0.1:8000/investigate \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/"}'
```

Automated checks (no real Ollama/model needed):

```sh
python -m pytest -q
node --test tests/guardian.test.cjs
```

## Files added

- `backend/orchestration.py`: reusable request/report schemas, fixed MCP SDK
  connection, discovery/invocation guards, output validation, deterministic policy
  application, opt-in minimized history, and `/investigate` router.
- `tests/test_orchestration.py`: real MCP stdio discovery/URL invocation plus
  controlled workflow, validation, injection, failure, network, and privacy tests.
- `docs/orchestration.md`: this workflow, security, API, and testing guide.

`backend/main.py` only registers the new router. No new dependencies are required.
