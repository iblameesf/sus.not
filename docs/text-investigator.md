# Local AI text investigator

`POST /analyze-text` investigates text using **qwen3.5:4b-q4_K_M** through the local Ollama server at **http://127.0.0.1:11434**. It is separate from `/analyze-url`: there is no text SUS Score, probability, or confirmed-scam classification. `/health` remains a backend health check, not a model-readiness check. The Chrome extension is unchanged and does not call this endpoint yet.

## Files and request flow

- `backend/text_investigator.py`: Pydantic request/response models, the fixed investigator system prompt, local Ollama HTTP client, error handling, and an API router.
- `backend/main.py`: registers that router; existing URL scoring is unchanged.
- `tests/test_analyze_text.py`: HTTP-level tests with `httpx.MockTransport`, so testing requires neither Ollama nor network access.

FastAPI validates the incoming `{"text": "..."}` body first. Text must be a string, contain non-whitespace characters, and be at most 5,000 characters. Unknown request fields are rejected. Invalid input returns **422** without calling Ollama.

The async endpoint uses the already-installed `httpx` library to POST to Ollama's **`/api/chat`**. The request contains:

- The exact fixed model name, `stream: false`, and `think: false`.
- A system message asking for possible urgency/pressure, advance-payment requests, sensitive-information requests, impersonation claims, and suspicious promises/offers, with cautious advice and limitations.
- A separate user message containing JSON-encoded `{"untrusted_message": submitted_text}`. User text is never interpolated into the system instructions, model name, URL, schema, or options.
- A JSON Schema generated from the Pydantic response model in Ollama's `format` field, low-variance generation (`temperature: 0`), and a 1,024-token output budget.

No tools are offered to the model. The application does not execute model output, fetch links, browse, contact external services, or automatically download models. The only investigator network destination is the fixed loopback Ollama address. Environment proxies are ignored and HTTP redirects are not followed. Client resources close after each request. There is a 90-second overall deadline as well as HTTP timeouts (3-second connect, 10-second write, 90-second read, 3-second pool wait).

## Structured response and its limits

A successful response has exactly these fields:

```json
{
  "indicators": ["The message pressures the recipient to pay immediately."],
  "explanation": "Urgency and an advance-payment request may indicate social engineering.",
  "recommendation": "Do not pay based on this message. Verify through a known official channel.",
  "uncertainty": "The sender's identity and context are unknown.\n\nThis AI assessment may be wrong or incomplete and is not proof of a scam. Sender identity, claims, and linked content have not been independently verified."
}
```

This is illustrative, not a deterministic model result. An empty `indicators` list is valid and does not guarantee safety.

Ollama's JSON-format instruction is not enough by itself: models can still emit invalid or incomplete output. The application checks the Ollama envelope is complete, rejects token-truncated responses, then independently validates the assistant's JSON with Pydantic. No Markdown-fence stripping or JSON repair is attempted. Strings must be nonblank and within bounds, findings must be a list of strings (up to 20 findings of up to 300 characters), explanation/recommendation are limited to 1,500 characters each, and uncertainty to 1,000. Missing fields, wrong types, and extra fields—including an invented score—are rejected.

The application appends its own uncertainty disclaimer, reserving space within the 1,000-character limit, and validates the final response again. Submitted instructions cannot remove that caveat or give the model application capabilities.

**Prompt injection is still a model-behavior risk.** Role separation, JSON encoding, and explicit system instructions treat the submitted message as evidence rather than commands, but do not mathematically guarantee that a generative model will never follow an embedded instruction. Schema validation guarantees shape, not truth, appropriate advice, or immunity to semantic manipulation. Findings remain untrusted AI-generated analysis requiring judgment; never treat them as verified facts or automatically act on them. Any future UI must render strings as text, not HTML. The injection test verifies the instruction/data boundary and application restrictions using a mock; it is not a real-model adversarial evaluation.

## Failure behavior

| HTTP status | Meaning |
| --- | --- |
| 422 | Missing, blank, oversized, or incorrectly typed text; unexpected request fields |
| 503 | Ollama unreachable, or required model unavailable (Ollama 404) |
| 504 | HTTP timeout or overall investigation deadline exceeded |
| 502 | Other Ollama HTTP failure/redirect, invalid envelope, incomplete output, or invalid assessment JSON/schema |

Errors are generic: the application does not include upstream exception messages, response bodies, or model output in them. There are no application logs or persistent storage of submitted text or model results. HTTP access logs may record the path/status, not the body. Do not enable body-logging middleware, reverse-proxy request capture, or third-party tracing of sensitive messages. Ollama receives the text locally; its own logging/runtime configuration is outside this module. Submit only text you intend to share with that local process. FastAPI validation errors may echo rejected input to the requesting client; they are not application logs.

## Local manual check

1. Confirm `ollama list` includes `qwen3.5:4b-q4_K_M`. If the Ollama daemon is not already running, start `ollama serve`. The API will not install or switch models automatically.
2. Start FastAPI from the project root:

   ```sh
   .venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000
   ```

3. Submit a synthetic message, not personal secrets:

   ```sh
   curl --max-time 100 -sS http://127.0.0.1:8000/analyze-text \
     -H 'Content-Type: application/json' \
     -d '{"text":"Your prize expires today. Pay a processing fee now to collect it."}'
   ```

   Expect the four structured fields, cautious possible findings, and the application-owned uncertainty caveat. Model wording may vary. No website is visited.
4. Send `{"text":"   "}`: expect 422. Stop Ollama and retry a valid message: expect 503. A slow first model load may produce 504; retry after local loading completes.
5. Confirm the old endpoints still respond:

   ```sh
   curl -sS http://127.0.0.1:8000/health
   curl -sS http://127.0.0.1:8000/analyze-url \
     -H 'Content-Type: application/json' -d '{"url":"https://example.com/verify"}'
   ```

   URL analysis only parses the URL; its scoring is unchanged.

## Automated tests

```sh
.venv/bin/python -m pytest
node --test tests/guardian.test.cjs
```

The new tests cover valid/benign text, 5,000-character boundaries, invalid input without model calls, unreachable Ollama, missing models, HTTP and overall timeouts, redirects, malformed/schema-invalid/truncated output, privacy-safe errors/logs, client configuration, application caveats, and an instruction-injection payload kept exclusively in the untrusted user message. All Ollama responses are mocked. No live model evaluation or manual Ollama test was performed during implementation.
