# Evidence-Driven Email Guardian — Task 12

## Scope and architecture

This is a reusable, explicit-submission, local email investigation engine, not a
chat interface or an autonomous mail agent. There is **no Gmail integration**,
mailbox access, permission request, background collection, or email modification.
All recommendations are advisory and dismissible.

```text
POST /investigate-email (bounded JSON stream)
  -> stdlib email parser / HTML text extraction
  -> deterministic metadata + link presentation evidence
  -> fixed MCP SDK stdio session: initialize -> discover
       inspect_url for each bounded, deduplicated URL
         -> existing lexical URL analyzer -> existing URL Decision Policy v1
       inspect_text for redacted subject/body
         -> existing prompt/schema -> local Ollama Qwen3.5-4B
  -> validated tool results -> typed evidence -> deterministic correlations
  -> separate Email Advisory Policy email-1 -> minimized structured report
```

The installed MCP SDK and existing server/custom tools are reused. No dependencies
are added. Existing API contracts, URL scoring, dashboard, and Chrome extension
behavior remain unchanged. See [orchestration](orchestration.md),
[MCP server](mcp-server.md), [URL policy](decision-policy.md), and
[history](investigation-history.md) for the underlying contracts.

## Inputs and bounded parsing

Submit exactly one of:

- `raw_email`: a string containing an RFC 5322/MIME message or pasted plain text.
- `email`: structured fields `sender`, `reply_to`, `subject`, `date`, `message_id`,
  `text_body`, and/or `html_body`. Header values must not contain control characters.

Raw RFC input uses Python's `email.parser.BytesParser` with the standard header registry.
The JSON string is encoded as UTF-8 for parsing; non-ASCII MIME bodies must declare
a compatible charset (structured/plain-text input can directly contain Unicode).
Encoded headers, text charsets, base64 and quoted-printable text are decoded locally.
Supported headers are extracted internally, including Date and Message-ID. Invalid
addresses, duplicate supported headers, malformed MIME/encoding and invalid header
syntax are rejected. Missing sender is accepted as limited evidence, not silently
invented. An invalid Date or Message-ID yields an explicit partial metadata error.
Plain-text input has no implied verified sender. Conservative parsing can reject
unusual but legitimate emails; this is not a complete mail-client implementation.

| Bound | Value / handling |
| --- | --- |
| Incoming JSON request | 512 KiB, streamed; larger requests return 413 |
| Raw email | 128 KiB UTF-8; schema also caps at 131,072 characters |
| Combined decoded text + HTML source | 20,000 characters |
| Structured header / each raw header value | 2,048 characters |
| Headers per MIME part / header characters | 50 / 16,384 |
| MIME parts / nesting | 30 / 8; conservative Content-Type preflight also bounds tree construction |
| HTML start elements | 2,000 |
| HTML link records / candidate scan | 100 each |
| Distinct URLs investigated | 10, each at most 2,048 characters |
| Qwen input | first 5,000 characters of redacted subject/body |
| URL tool deadline | 5 seconds each |
| Text tool deadline | 95 seconds; underlying model deadline remains 90 seconds |
| Initialization + discovery / overall workflow | 10 / 165 seconds |

Malformed JSON/schema errors return fixed 422 messages without input echoes. Parser
limit violations return 413; other parser rejections return sanitized 422. Some
schema length violations are 422 before parsing. Over-limit URL counts/candidates,
malformed HTTP candidates, text truncation, and optional metadata failures appear
in the report's `errors`, yielding `status: partial`, not a clean safety result.

MIME attachments, filename-bearing parts, non-text parts and nested `message/rfc822`
messages are omitted, never opened, saved, decompressed, or executed. A completed
investigation means supported checks completed, not that attachments were checked.
Both plain and HTML alternatives may contribute text; exact duplicate text is
removed, but semantic duplicates can remain.

HTML is processed by `html.parser.HTMLParser`, **not rendered**. Script, style,
head, template and noscript content is omitted. Anchor text and destination are
compared; HTTP(S) `href`, `src`, and `action` values are lexical candidates, including
remote image URLs. There is no browser, CSS execution, JavaScript execution, remote
asset loading, URL resolution, or redirect following. Broken HTML recovery is not
browser-equivalent; CSS-hidden text, CSS URLs, obfuscated URLs, relative links,
non-HTTP schemes and all possible attachment/link formats are outside coverage.

## Metadata and URL evidence

Deterministic checks report:

- Missing sender address.
- Different full sender/Reply-To domains (case-insensitive, IDNA-normalized).
- A literal email address in the sender display name using a different domain
  from the actual sender address. Brand impersonation is **not** guessed.
- URL user information before the host, which may obscure the destination.
- Visible HTTP(S) URL/domain label with a different full hostname from the href.
  This compares hostnames, not paths, ownership, registrable domains or reputation.

Different subdomains, support vendors and tracking redirects may legitimately
trigger discrepancies. Mismatch does **not** establish spoofing or fraud.
**SPF, DKIM and DMARC are not verified**, and authentication-result headers are not
accepted as proof. No DNS, reputation, sender identity or page-content verification
is performed.

HTTP(S) candidates in subject/text and HTML attributes are deduplicated by exact
original string and assigned `url-1`, `url-2`, etc. Differently spelled equivalent
URLs can remain distinct. Displayed URL text is also a textual candidate; references
distinguish HTML attributes/anchors from textual occurrences. The first ten valid
distinct candidates are inspected; omissions are explicit errors. Invalid candidates
never become zero-score assessments.

Each URL is submitted to discovered MCP `inspect_url` using the existing validated
application invocation boundary. Its SUS Score remains unchanged, with original
indicators (except necessary privacy redaction), inspection explanation and a
separate URL Policy v1 decision. No scores are combined or converted into email
scores. URLs are **never fetched or visited**, even localhost or credential-bearing
URLs. The full original URL is used only as local lexical-tool input; its response
identifier is redacted to `http://[redacted]` or `https://[redacted]`.

## Qwen participation and code-enforced guardrails

A code-owned plan decides every invocation. The only permitted names are existing
`inspect_url` and `inspect_text`; submitted fields cannot supply tools or commands.
One existing SDK stdio connection is used per email. Extra advertised tools do not
extend the allowlist. The launched Python executable/module/cwd are fixed by code.
Qwen has no dispatcher or execution capability and receives no tool definitions.
There is no shell, file-reading, web-browsing or email-action tool available to it.

Before `inspect_text`, addresses, URLs and recognizable credential values are
redacted from the subject/body; truncation after redaction is explicit. Qwen sees
linguistic evidence, not raw sender headers or credential-bearing destinations.
The existing system prompt, JSON-wrapped untrusted message, strict output schema,
model `qwen3.5:4b-q4_K_M`, fixed loopback Ollama endpoint, disabled environment proxies
and disabled redirects are retained. Email instructions remain untrusted data.

Returned AI indicators, explanation, recommendation and uncertainty are unverified
advisory prose. They are validated and redacted again; uncertainty is retained with
the existing application caveat, subject to redaction and its existing field limit.
No AI recommendation is parsed as a command or policy instruction. Model prose can
still be manipulated; structure and lack of tools are not semantic injection immunity.
Consumers must display prose as text, never execute it or render it as trusted HTML.

## Evidence, correlation and email advisory policy

Every evidence record has:

- `evidence_id`: deterministic report-local ID (`ev-001`, etc.).
- `evidence_type`: typed finding such as `reply_domain_mismatch`, `url_indicator`,
  `url_high_risk`, or `ai_content_indicator`.
- `source_component`: `email_metadata`, `email_parser`, `inspect_url`, or `inspect_text`.
- `finding`, `severity`, `supporting_reference`, and explicit `limitations`.

References point to structural source locations, URL IDs/indicator indices, or AI
indicator indices, not copied raw secrets. Severity is a qualitative evidence
annotation, not a numerical email score. AI findings are labeled low severity and
unverified; they cannot erase or override deterministic findings.

Correlation is deterministic and does not interpret finding prose:

| Rule | Required typed evidence | Meaning |
| --- | --- | --- |
| `sender_and_link_mismatch` | Sender/Reply-To or display-address discrepancy **and** visible/destination host discrepancy | Identity discrepancy co-occurs with misleading link presentation |
| `url_and_content_concern` | Existing URL heuristic indicator **and** AI content indicator | Independent components report possible concerns |

Correlations cite their evidence IDs and state that co-occurrence proves neither
fraud nor common ownership. The second rule is explanatory; it does not by itself
escalate to a warning.

**Email Advisory Policy `email-1`**, in priority order:

1. `show_warning` if an existing URL policy result is high/critical, or if
   `sender_and_link_mismatch` is present.
2. Otherwise `review_before_proceeding` if any evidence exists or any check failed,
   was invalid, omitted due to a limit, or was truncated.
3. Otherwise `continue_with_caution`: only absence of indicators in completed,
   supported checks, **not a safe-email verdict**.

AI finding presence can request review but cannot dictate a warning, lower a
warning, alter evidence, or change policy versions. Sender-domain mismatch alone
only requests review. All actions include reasons and evidence references, are
advisory/dismissible, and never delete, block, report, forward or modify an email.

## Partial failures

Valid parsed requests return a structured HTTP 200 report with `status` and `errors`.
Inspect both; 200 does not mean safe or fully investigated. Errors identify their
component and supporting reference with fixed messages rather than upstream content.
MCP startup/discovery/transport failures retain local metadata evidence; per-tool
failures retain other successful assessments. Unassessed URLs have null assessments,
never invented zero scores. Overall timeouts are partial failures too.

The existing text MCP contract intentionally collapses Ollama unavailability,
missing model, model timeout, and invalid model output into a sanitized `tool_error`.
Client-side call deadlines use `tool_timeout`; malformed structured tool results use
`invalid_tool_output`. No raw tool error or model-error body is returned. If text is
absent, `no_text` records that content assessment could not be done.

## Privacy and auditability

- Raw data is processed ephemerally on the local machine. Bind FastAPI to loopback.
  No Gmail permissions, collection, external intelligence calls or new dependencies.
- Public `parsed_metadata` exposes presence/validity flags and redacted sender and
  Reply-To address placeholders. It omits display names, domains, subject text,
  exact Date and Message-ID. Full headers/bodies are available only to the internal
  parser during processing, not echoed in API responses.
- URLs are identified by report-local IDs, references and scheme-only redaction.
- Credential redaction covers labeled passwords/keys/tokens/OTP values, bearer
  values, JWT/common key formats, private-key blocks, URL user information/query
  values/fragments, and conservative high-entropy-looking source tokens. Matching
  known values echoed without their labels are also redacted. This occurs before
  local inference and again on response prose. `privacy_redactions_applied` signals
  prose/input redaction; metadata/URL minimization always applies.
- Redaction can over-redact and cannot recognize every arbitrary secret, encoding,
  paraphrase or hallucinated credential. Do not submit real credentials. This is
  not a formally verified data-loss-prevention system; local Ollama/OS logging,
  request tracing, reverse proxies, backups and the caller remain trust boundaries.
  Do not enable body/debug tracing. Application code does not log email content,
  and the reused stdio connection discards server stderr.
- Nothing is stored by default. Existing **two-part opt-in** still requires
  `SUSNOT_HISTORY_ENABLED=true` and `X-SUSNOT-Record-History: true`. A consenting
  request writes only one existing `text`-type history record with fixed
  `email_guardian` marker, `email-1` version, advisory action and completed/failed
  status. Partial results use `failed`. There is no score, raw email, address,
  URL, subject, evidence/model prose or new database schema. Dashboard compatibility
  is tested. Parser/schema rejections do not write history.
- The report's investigation UUID is ephemeral and independent of history record
  IDs. Evidence IDs and structural references support explaining the current report,
  not reconstructing private source later. To replay a case, callers must separately
  retain their own source under their own consent/access policy; synthetic fixtures
  supply auditable public examples. No raw evidence archive is silently created.

This is not an OS sandbox, authentication layer, malicious-file scanner or full
mail gateway. Local Python/MCP/Ollama must be trusted. There is no concurrency queue
or new rate limiter; each email starts a child process and model inference consumes
local resources. Keep the service private. No real-world accuracy is claimed.

## API examples

Start the existing backend and local model service:

```sh
source .venv/bin/activate
# Start Ollama if needed, with qwen3.5:4b-q4_K_M already installed.
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Structured fields:

```sh
curl -sS http://127.0.0.1:8000/investigate-email \
  -H 'Content-Type: application/json' \
  -d '{"email":{"sender":"Accounts <notice@example.com>","reply_to":"pay@other.example","subject":"Account notice","html_body":"<p>Pay immediately.</p><a href=\"https://user@192.0.2.1/verify\">https://official.example/</a>"}}'
```

Raw RFC message (or plain text in the same field):

```sh
curl -sS http://127.0.0.1:8000/investigate-email \
  -H 'Content-Type: application/json' \
  -d '{"raw_email":"From: alice@example.com\nSubject: Meeting\nDate: Tue, 01 Apr 2025 12:00:00 +0000\nMessage-ID: <demo@example.com>\n\nOur meeting is at noon."}'
```

The response fields are `investigation_id`, `status`, `parsed_metadata`,
`url_assessments`, `ai_text_assessment`, `evidence`, `correlation_findings`,
`recommended_advisory_action`, `uncertainty`, `tools_used`, `errors`, and
`privacy_redactions_applied`. `tools_used` lists unique attempted allowlisted names;
each URL assessment/error identifies its individual URL reference. Model prose
and missing assessments must never be mistaken for verified facts.

## Reproducible synthetic benchmark

`benchmarks/email_cases.json` contains 12 explicitly labeled synthetic scenarios:
benign, suspicious and ambiguous, with rationales and false-positive/false-negative
candidates. Labels describe stipulated scenarios, not authenticated sender truth.
Expected advisories are **policy regression expectations**, not ideal safety labels.

```sh
python -m benchmarks.evaluate_emails
```

The offline evaluator reuses production parsing, metadata evidence, original URL
analyzer, URL policy, evidence projection, correlations and email policy. It writes
`benchmarks/results/email_evaluation.json` with a canonical dataset SHA-256,
versions, case evidence types, correlations, original URL scores, policy regression
outcomes, benign review/warning examples and suspicious cases missed by the
implemented deterministic checks. It does not visit URLs or call Ollama/MCP.
**AI and MCP are explicitly marked not run in this benchmark.** Actual MCP transport
and mocked Qwen responses are covered by integration tests instead. This separation
avoids fabricated model results or nondeterministic benchmark claims.

The executed initial dataset produced **12/12 policy regression matches**. This is
not fraud detection accuracy: the saved report deliberately includes two benign
review/warning cases and two suspicious cases with no deterministic indicators.
An end-to-end live-Qwen email benchmark has not been run for Task 12.

## Tests and files

```sh
python -m pytest -q
node --test tests/guardian.test.cjs
```

Tests cover raw/plain/MIME/HTML parsing, decoding, headers, bounds, malformed URLs,
deduplication, presentation discrepancies, injection, SDK tool invocation, no
external fetching, failures/partial results, model uncertainty, deterministic policy,
provenance, credential/PII minimization, history opt-in and dashboard compatibility.
The full existing suite remains included. No real model is needed for automated tests.

Files added:

- `backend/email_parser.py`: input contracts, bounded stdlib/MIME/HTML parsing,
  internal headers/text, URL extraction, metadata indicators and public metadata flags.
- `backend/email_privacy.py`: email-specific credential/address/URL redaction before
  inference and on response prose; existing endpoint responses remain unchanged.
- `backend/email_evidence.py`: evidence/correlation/advisory contracts, shared URL
  evidence projection, typed deterministic correlation rules and email-1 policy.
- `backend/email_guardian.py`: reusable MCP-backed investigation engine, partial
  failure handling, minimized report/history and streamed `/investigate-email` route.
- `tests/test_email_guardian.py`: parser/API/security/privacy/failure/provenance and
  real SDK in-memory integration tests with mocked Ollama.
- `tests/test_email_evaluation.py`: reproducibility, saved-result integrity and
  deterministic advisory/instruction-resistance checks.
- `benchmarks/email_cases.json`: labeled synthetic scenarios and regression expectations.
- `benchmarks/evaluate_emails.py`: offline deterministic evaluator and report generator.
- `benchmarks/results/email_evaluation.json`: actually generated, versioned benchmark
  evidence, not fabricated AI results.
- `docs/email-guardian.md`: this architecture, policy, privacy and usage guide.

File modified:

- `backend/main.py`: imports and registers the email router only for Task 12.

No Gmail integration, extension/dashboard changes, new MCP tool permissions, or URL
scoring changes are included.
