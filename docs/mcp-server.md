# Local SUS.NOT MCP server

## Architecture

`backend/mcp_server.py` is a thin Model Context Protocol adapter using the already-installed Python MCP SDK **2.3.0** (`MCPServer`, not the old v1 `FastMCP` API). No dependencies were added.

```
MCP client → stdio → MCPServer
                      ├─ inspect_url → existing URL request validation + analyze_url
                      └─ inspect_text → existing text validation + analyze_text → local Ollama
```

The adapter calls the existing Python functions directly, not the FastAPI HTTP endpoints. FastAPI need not be running. The FastAPI endpoints, Chrome extension, Guardian Mode, and URL thresholds are unchanged. The only new response model maps the existing URL `message` to MCP `explanation`; scoring is not duplicated.

Tools:

- `inspect_url(url: string)` → `sus_score`, `risk_level`, `indicators`, `explanation`. The score remains an experimental heuristic, not a fraud probability. No URL is visited.
- `inspect_text(text: string)` → `indicators`, `explanation`, `recommendation`, `uncertainty`. Uses only `qwen3.5:4b-q4_K_M` at `http://127.0.0.1:11434`. There is no text score. See [text investigator](text-investigator.md) for output validation, timeouts, and model limitations.

Both tools advertise read-only, nondestructive, idempotent, closed-world annotations. Idempotent describes absence of side effects, not a guarantee of identical model wording. These annotations are hints; the lack of action capabilities in Python is the actual restriction.

## Start and transport

From the repository root:

```sh
.venv/bin/python -m backend.mcp_server
```

For text investigation, Ollama must already be running with the required model installed. URL investigation works without Ollama. The server never installs models.

**stdio** carries MCP JSON-RPC protocol messages over the process's standard input/output. A client normally launches and owns this child process. No HTTP listener or port is opened by the MCP server; stdout is reserved for protocol traffic, not application prints. Diagnostics may use stderr. Starting it alone in a terminal waits for protocol input; it is not an interactive command prompt.

Configure a stdio-capable MCP client with these launch values (replace the repository path):

```json
{
  "command": "/absolute/path/to/sus-not/.venv/bin/python",
  "args": ["-m", "backend.mcp_server"],
  "cwd": "/absolute/path/to/sus-not"
}
```

Client configuration wrappers vary; this is the launch specification, not a universal configuration file. Clients without `cwd` support must otherwise arrange for `backend` to be importable from the project root.

## Discovery and invocation

A client initializes the session (`initialize`, then initialized notification), sends `tools/list`, and receives names, descriptions, input schemas, output schemas, and annotations. It invokes a tool with `tools/call`, for example:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_url","arguments":{"url":"https://user@192.0.2.1/verify"}}}
```

That example returns score **70**, risk **high**, three indicators, and the existing cautionary explanation. A text call uses `{"name":"inspect_text","arguments":{"text":"Pay a fee immediately to receive your prize."}}`. Results contain structured content and a text representation. Tool failures are marked `isError`; they must not be interpreted as low-risk assessments.

## Python-enforced guardrails

- Existing `AnalyzeURLRequest` rejects non-HTTP(S), missing hosts, invalid ports/hosts, whitespace/control characters, and backslashes. Parsing and scoring do not perform DNS or HTTP requests.
- Existing `AnalyzeTextRequest` requires nonblank string input with at most 5,000 characters, before creating an Ollama client.
- Submitted text is JSON-encoded into a separate untrusted user message, never interpolated into system instructions, model selection, destination, or options.
- No model tools or action dispatcher exist. Submitted commands and model output are never evaluated or executed. There is no browser, email integration, shell tool, file-access tool, secret lookup, or environment-variable tool. The server registers no resources, resource templates, or prompts.
- The sole text-investigation network destination is fixed loopback Ollama; environment proxies are disabled and redirects are not followed. Submitted URLs are never destinations, including links embedded in text.
- Existing response-schema validation rejects malformed/incomplete output; the application appends its own uncertainty caveat. MCP errors are fixed messages, never raw upstream bodies, model output, exception details, or environment contents. The adapter does not log submitted content or persist investigations.
- Local inference is read-only with respect to investigated accounts/content; it still consumes local compute and sends the submitted text to the local Ollama process. Ollama runtime/logging and client-side retention are outside this adapter. Run only with trusted local clients and avoid body/debug tracing.

**Limits:** Python prevents execution of embedded instructions by withholding execution capabilities. Prompt separation does not guarantee that Qwen's prose cannot be manipulated. Model findings remain untrusted data, not instructions or verified facts; clients must not automatically execute them. The server cannot prevent a client from separately acting on output. It does not read runtime secrets into the prompt or response; it cannot recognize every secret a user explicitly submits or prevent model hallucinations. No semantic prompt-injection immunity is claimed.

## Verification

```sh
.venv/bin/python -m pytest -q
node --test tests/guardian.test.cjs
```

Verified: **92 Python tests** (68 existing + 24 MCP tests) and **14 Node tests** pass. `tests/test_mcp_server.py` covers tool discovery and schema/annotation checks, URL invocation and rejection, text validation and the 5,000-character boundary, mocked local Qwen analysis, sanitized Ollama failures/redirects, instruction/data separation, and no URL fetching. Existing text tests also cover deadlines and invalid model output.

An automated test launches the actual server subprocess and uses the installed Python MCP SDK client over **stdio** for initialization, discovery, URL invocation, and rejection cases. Text invocation is tested in-process through the MCP tool registry with mocked Ollama. No desktop/third-party MCP client configuration or live Qwen-through-MCP integration was tested for this task.
