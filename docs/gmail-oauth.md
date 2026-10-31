# Gmail OAuth and selected-message integration — Task 13.3A

> Current Task 13.3C-1 setup: see [live setup and readiness](gmail-live-setup.md).
> The callback now uses the documented root-loopback form (not the historical
> random path below), with unchanged state/PKCE binding. Explicit identity/evidence
> views and a non-authorizing readiness command are available.

> Task 13.3B follow-up: the [local verification guide](gmail-local-verification.md)
> documents the new trusted terminal/in-process launcher and successful isolated
> synthetic native Keychain verification on one host. The results/restrictions below
> record Task 13.3A; real Google OAuth/Gmail interoperability is still unverified.

## Implementation status

The backend now implements desktop OAuth/PKCE, token lifecycle management, bounded
read-only Gmail acquisition and explicitly selected-message investigation. It is
**unconfigured and inactive by default**: `app.state.gmail_service` is `None`.
Importing or starting FastAPI does not read Google configuration, access Keychain,
open an OAuth listener/browser, request permissions, or contact Google.

All implementation verification used synthetic credentials, mocked Google HTTP
responses and mocked Keychain storage. A real loopback HTTP receiver was tested
with a synthetic handler only. **No real Google credentials, Gmail account or OAuth
flow were used.** Live Google interoperability and native Keychain access remain
unverified. This is a backend integration, not a completed desktop login UI.

The [Task 13.2 security foundation](gmail-security-foundation.md) remains the control
boundary. This document supersedes its historical statements that OAuth, transport
and Email Guardian wiring were not implemented. Its threat model and restrictions
still apply unless explicitly updated here.

## Architecture and trust boundaries

```text
Trusted local launcher/configuration (no public HTTP bootstrap)
  -> existing control session: bearer + independent CSRF capability
  -> authenticated POST /gmail/oauth/start + explicit consent
       -> fixed Google authorization URL, state and PKCE S256
       -> temporary 127.0.0.1:<ephemeral-port>/oauth/callback/<random-path>
            -> validate callback -> consume state once
            -> fixed Google token endpoint -> Gmail profile identity
            -> connected account binding / optional macOS Keychain persistence
  -> user-requested GET /gmail/messages (bounded metadata only)
       -> opaque account/session/generation-bound selection references
  -> user confirms POST /gmail/investigate with selected references
       -> atomic claims and single-use retrieval leases
       -> MIME skeleton preflight (no body data)
       -> bounded raw MIME, only for supported attachment-free messages
       -> existing investigate_email engine, also used by POST /investigate-email
            -> stdlib MIME parser and metadata evidence
            -> actual MCP SDK inspect_url / inspect_text
            -> local Qwen via Ollama
            -> deterministic URL policy and separate email-1 advisory policy
       -> minimized reports, explicit errors and optional existing history
```

OAuth and Gmail requests are initiated by application code, not Qwen. Gmail is not
exposed as a model tool or MCP capability. Credentials are not placed in MCP
arguments, child-process environment, shell arguments, model configuration or
history. The existing MCP tool allowlist remains exactly `inspect_url` and
`inspect_text`. No scoring, correlation or advisory policy was duplicated or changed.

This is not a chatbot wrapper: deterministic parsing, URL tooling, evidence provenance,
correlation and decisions are independent of model instructions. The model supplies
one unverified evidence stream and cannot authorize retrieval or mailbox actions.

## Google Cloud setup requirements — for a later authorized operator

These are configuration requirements, **not actions performed during Task 13.3A**:

1. Use a Google Cloud project with the Gmail API enabled.
2. Configure the OAuth consent screen/audience and designated test users as appropriate.
3. Create an OAuth client of type **Desktop app**, not Web application, service
   account, browser-only/implicit-flow client, or domain-wide delegation client.
4. Keep the downloaded client configuration outside the repository and outside logs.
   Never paste it, access tokens, refresh tokens or authorization codes into Pi.
5. A trusted launcher may pass an already-loaded configuration to
   `DesktopClient.from_google_config`. It requires an `installed` configuration,
   rejects a `web` configuration and arbitrary authorization/token endpoints, and
   accepts Google's known legacy/v2 authorization URI declarations. The actual
   authorization URL always uses the application's fixed v2 endpoint.
6. The launcher can construct `GmailService(client, app.state.gmail_control)` and
   assign it to `app.state.gmail_service` before serving requests. No public endpoint
   accepts client configuration or issues control capabilities.
7. Deliver control capabilities only through trusted, user-bound local IPC/native
   integration. That launcher/IPC/UI is **not implemented by this task**. Ordinary
   clients cannot bootstrap Gmail access merely by visiting localhost.

The Google client ID identifies a public native application. A packaged desktop
client secret is not a confidential-client authentication boundary; PKCE, callback
state, local capability protection and OS security remain necessary. Configuration
and credentials must still be kept out of logs and model input.

### Minimum scope

Only `https://www.googleapis.com/auth/gmail.readonly` is requested and accepted.
It is needed for message bodies and Gmail profile identity. `gmail.metadata` cannot
supply the email content required by Email Guardian. No additional OpenID Connect,
Contacts, Drive, send, compose, modify or full-mail scope is requested.

**Read-only is mailbox-wide access. Google does not restrict this grant to messages
selected in SUS.NOT.** The start response includes this permission notice. The local
UI must display it before opening the authorization URL and explain the independent
selection restriction. Per-message consent is enforced by application code.

Gmail read-only is a restricted scope. Before distribution, review Google's current
verification, Limited Use, testing-mode, Workspace administrator and security-assessment
requirements. Testing grants/refresh tokens can expire or be revoked; do not assume
indefinite availability. Local inference does not automatically waive provider policies.

References:
- https://developers.google.com/identity/protocols/oauth2/native-app
- https://developers.google.com/workspace/gmail/api/auth/scopes
- https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get

## OAuth authorization and callback validation

`POST /gmail/oauth/start` requires the existing bearer and mutation CSRF headers,
Host/Origin/peer checks, and JSON `{"consent": true, "remember": false}`. Consent
must be a real boolean true; omitted, false, numeric or string consent is rejected.
Unknown JSON fields are rejected and streamed request bodies are limited to 4 KiB.

Starting authorization:

- Requires a disconnected/revoked/error context with no outstanding credential
  cleanup obligation. Connected users must explicitly disconnect before switching.
- Generates independent cryptographic state, an 86-character PKCE verifier, its
  SHA-256 base64url challenge and a random callback path.
- Starts an ephemeral listener on **127.0.0.1 only**, not all interfaces.
- Uses a fixed authorization endpoint, response type `code`, PKCE method `S256`,
  and exactly the read-only scope. It does not enable incremental broader grants.
- Returns the authorization URL, expiry and permission notice only to the authenticated
  caller. It contains no access token, refresh token, client secret or verifier.
- Does not open a browser automatically. A trusted local UI must open the returned
  URL in the **system browser**, not an embedded login webview, after user review.

The separate callback listener is necessary because Google redirects cannot supply
SUS.NOT's local bearer/CSRF headers. It does **not** create an authentication exception
under `/gmail` and does not broaden CORS. There is no `/gmail/oauth/callback` route.

The receiver checks loopback peer, exact Host/port, GET method, exact random path,
header uniqueness, absence of a request body/transfer encoding and an 8 KiB request
limit. Header reads have a five-second deadline. Callback query parsing is bounded;
duplicate parameters, unknown parameters, mismatched redirect URI/state and unexpected
issuer values are rejected. If Google supplies `iss`, it must be its fixed expected
issuer. OAuth error descriptions are never reflected.

State comparisons use constant-time digest comparison. Transactions expire after
five minutes, also obey the independent control-session deadline, and are consumed
**before** exchanging a code. Invalid-state noise cannot consume a legitimate flow;
a valid-state denial, expiry or exchange failure consumes it and requires a new
explicit attempt. The stored verifier is rechecked against the stored challenge;
Google receives that verifier with the same client ID and exact redirect URI.

The receiver returns fixed plain text with no-store, no-referrer and nosniff headers;
it logs no query, code, state or error body. Listener/timer cleanup occurs on completion,
expiry, local session closure and application shutdown. Browser history/OS tracing
are external trust boundaries; short-lived code+PKCE binding is not guaranteed
secure erasure of a browser's navigation history.

## Token validation, storage and lifecycle

Token responses must contain a nonempty bounded ASCII access token, Bearer token
type, a positive integer lifetime no greater than one day and the exact read-only
scope. Booleans/string lifetimes, header-control characters, extra scopes and malformed
responses are rejected. Refresh responses may omit scope when retaining the existing
grant. Tokens are opaque; no unsupported JWT/identity verification claim is made.
Google's fixed HTTPS token endpoint and authenticated Gmail profile response establish
the connection identity, not an email's untrusted From header.

### Session-only versus remembered access

- `remember: false` is the default: credentials stay in process memory only.
- `remember: true` explicitly requests offline access/consent. A refresh token is
  required before claiming the connection was remembered. Credentials use the existing
  `MacOSKeychainStore`; no token JSON file or environment fallback is created.
- The Keychain item is keyed by an opaque account UUID. Its credential envelope now
  also stores the verified account identity as masked `SecretStr`, so a trusted
  restore cannot silently bind the UUID to a different mailbox. This identity is
  protected credential metadata, not investigation history.
- `GmailService.restore(session, account_id)` is an explicit trusted-launcher method,
  **not an HTTP endpoint or an automatic startup action**. It validates stored data,
  refreshes if necessary and checks the profile against the stored identity. Legacy
  entries without that identity require reauthorization.
- Native Keychain library/access-control behavior has not been live-verified in this
  task. Locked/denied storage fails closed; tests use the mock backend exclusively.

### Refresh and failure behavior

Credentials are checked on operations rather than by inbox/background monitoring.
Refresh starts within 30 seconds of access-token expiry and is serialized per
connection. Returned refresh-token rotation is persisted; when no replacement is
returned, the previous refresh token is retained. Every refresh verifies the same
account identity. Storage failure prevents continued mailbox access; rotated tokens
may remain in memory solely so explicit disconnect can revoke them.

An actually expired/rejected access token transitions through `expired`; successful
refresh creates a new authorization generation. **Old selections/leases are not
silently rebound.** A forced refresh after a 401 is bounded, and a generation change
returns `authorization_changed_reselect` (409) before retrying an operation under a
stale selection. Users must reload metadata and explicitly select again. There is
no unlimited retry loop. A proactive refresh while the original token is still valid
need not change the generation.

`invalid_grant` stops access, marks local authorization revoked and attempts removal
of remembered credentials. Identity/scope/protocol/storage failures fail closed;
transient rate/network failures remain explicit failures, not safe-email results.
Token expiry/authorization state is evaluated on use; status polling alone does not
perform background refresh. Provider revocation or expiry still requires reauthorization.

### Disconnect versus local session close

`POST /gmail/disconnect` first stops local authorization and invalidates selections,
then attempts remote revocation and Keychain deletion independently. Its response
reports `google_revocation_performed`, `credentials_removed` and explicit error codes.
HTTP 200 is not proof that every cleanup step succeeded: inspect those fields/errors.
A failed deletion can be retried; there is no plaintext fallback. Google-side grant
revocation may affect other connections using the same application's grant.

Failed initial setup attempts best-effort revocation of validated newly issued tokens
and removal of attempted persisted entries. Remote cleanup is not guaranteed during
network failure; use Google Account security controls when confirmation is unavailable.

`POST /gmail/session/close` and process shutdown clear the local capability, pending
listener and in-memory credentials, **not Google's grant or explicitly remembered
Keychain entries**. They report no Google revocation. They are not substitutes for
Disconnect. Guaranteed secret zeroization is not possible in ordinary Python memory.

## Bounded read-only transport and selection

The transport offers only fixed code-owned endpoints:

- Google token exchange and revocation, POST bodies only.
- Gmail `users/me/profile`, GET.
- Gmail `users/me/messages`, GET.
- Gmail `users/me/messages/{validated_id}`, GET.

No caller supplies URLs, user IDs, arbitrary API paths or mailbox actions. All Google
requests use TLS, disabled environment proxies, disabled redirects, a three-second
connect timeout, ten-second HTTP inactivity timeout and 15-second overall deadline.
Streamed decoded JSON response limits are 4 KiB for identity, 16 KiB for listings/
metadata, 24 KiB for token/revocation, 64 KiB for MIME skeletons and 180,000 bytes for
raw-message envelopes. Non-JSON 401/429 statuses retain their correct error meaning.
Bodies and provider exception text are not returned or logged by application code.

Metadata listing is explicitly requested, never performed automatically on connection:

- At most 20 IDs and allowlisted From/Subject/Date metadata per page.
- No message-body data in listing requests, no snippets or thread expansion.
- No automatic pagination. Optional next-page tokens are bounded opaque query values,
  never network destinations. An entire metadata operation has a 45-second deadline.
- Returned picker strings are redacted and bounded, still untrusted text—not HTML.
  There is no picker UI in this task; a future UI must escape them.
- Gmail IDs are replaced with random server-issued selection references.

Investigation requires another explicit boolean consent and one to five references.
The existing registry checks account, control session, authorization generation,
expiry, atomic whole-batch reservation and duplicate Gmail IDs. Raw message IDs are
not accepted by the investigation endpoint. New handles for an already claimed ID
cannot evade duplicate prevention. Five unexpired claimed/running retrieval jobs
and 256 total registry/job records bound retained work. One analysis worker serializes
investigations across connections. There is no mailbox-wide investigation operation.

### Attachments: conservative unsupported-message policy

A raw RFC message can itself contain attachment bytes. Therefore, simply avoiding
`attachments.get` would not be sufficient. **Before requesting raw data**, the
connector requests a bounded MIME skeleton with a fixed fields projection that
excludes all body `data`. It rejects filename-bearing parts, attachment dispositions,
attachment IDs, non-text parts, nested forwarded-message parts and over-limit MIME
structures/sizes. Only attachment-free plain/HTML and supported multipart structures
proceed to raw retrieval.

Consequently, attachment-bearing mail is currently **unsupported as a whole** and
returns an explicit failed/review result; SUS.NOT does not fetch the attachment and
then silently omit it. No attachment endpoint exists in the transport allowlist.
This deliberately sacrifices coverage. It relies on Google's immutable message IDs
and accurate MIME representation, not a hostile provider ignoring fields projections.
Disguised content labeled as text is still untrusted evidence, never executable.

Base64url and actual decoded raw bytes are validated against the existing 128 KiB
limit; a size estimate alone is insufficient. Raw bytes enter the shared MIME parser
without lossy UTF-8 conversion, preserving declared charsets. Existing limits remain:
20,000 body characters, 30 MIME parts/depth eight, ten URLs and 5,000 redacted Qwen
characters. Invalid/oversized MIME is never converted into an empty safe message.

Authority is rechecked between skeleton and raw retrieval and after responses.
Disconnection cannot undo an already-sent request or completed inference, but prevents
new stages and release of a report under a stale context. No submitted link, remote
image or model-generated destination is followed.

## API and report contracts

All routes inherit the existing loopback-peer, exact Host/Origin, bearer, CSRF,
fetch-metadata, no-cookie-auth and no-CORS protections. Do not weaken them for Google
redirects. With the default unconfigured application, authenticated integration routes
return `gmail_not_configured` (503); unauthenticated callers remain denied first.

| Route | Input / result |
| --- | --- |
| `POST /gmail/oauth/start` | `consent: true`, optional `remember: false`; authorization URL, notice, 300-second expiry |
| `GET /gmail/status` | State, configured flags, safe last OAuth/refresh error when configured; no account/token data |
| `GET /gmail/messages?limit=20&page_token=...` | One bounded redacted metadata page with selection references |
| `POST /gmail/investigate` | `consent: true`, `references: [opaque_reference, ...]`; per-selection reports/errors |
| `POST /gmail/disconnect` | Independent local/remote cleanup outcomes |
| `POST /gmail/session/close` | Existing local capability shutdown; no revocation claim |

Mutation headers remain `Authorization: Bearer <local capability>` and
`X-SUSNOT-CSRF: <independent capability>`. These are not Google access tokens. Never
put any of these values in a query string. There are no token-upload, arbitrary
scope, account-switch, state-transition, attachment, email-send or email-modify routes.

The Gmail investigation route calls the **same reusable `investigate_email` engine**
as `POST /investigate-email`, not a duplicated policy or an internal HTTP roundtrip
that re-encodes MIME. Existing public email/URL API contracts remain unchanged.

Batch responses have `status: completed|partial` and ordered `results` with
`selection_index`. Successful/partial engine results contain the existing EmailReport:
investigation UUID, minimized metadata, separate original URL scores/decisions, AI
assessment/uncertainty, evidence, correlations, advisory action, tools and errors.
Failures instead contain a safe error code and `review_before_proceeding` advisory.
There is no combined fraud probability, email score or automatic mailbox action.
**Inspect status/errors; HTTP 200 alone never means safe.**

Selections are consumed on claim and leases on retrieval. Duplicate tombstones
survive analysis failures until the control session ends. There is no in-place
retry/reinvestigate endpoint, durable job queue or cross-restart exactly-once guarantee.
A five-minute lease can expire while a slow batch waits: remaining items fail explicitly
rather than receiving silently extended consent. Large/slow batches are not guaranteed
to complete. New authorization generations require fresh selection; a new authorized
control session is needed to deliberately repeat consumed investigations.

## Privacy and evidence

- No automatic message collection or body persistence. Bodies are ephemeral bytes.
- Qwen stays on existing fixed loopback Ollama; no external AI provider or cloud fallback.
- Redaction before inference and on AI prose remains active. If decoded evidence contains
  the application's own known credential literals, investigation is blocked before MCP.
  Manipulated model prose is also checked for those literals. These guards never rewrite
  code-owned scores, policy versions/actions or provenance IDs.
- OAuth credentials are not accepted or returned through the public API. Account identity
  is kept in memory/Keychain for binding, not copied into investigation history.
- Picker metadata is an explicitly requested privacy disclosure. Redaction is imperfect;
  arbitrary PII/secrets cannot all be recognized. Treat the response as sensitive.
- Existing history still requires **both** `SUSNOT_HISTORY_ENABLED=true` and
  `X-SUSNOT-Record-History: true`. It stores only the existing fixed email marker,
  advisory, version and completion/failure metadata—not Gmail IDs, bodies, subject,
  tokens, account address, AI prose or raw evidence. Parser rejections retain their
  existing non-recording behavior.
- Evidence IDs/references are report-local. `selection_index` links results to the
  user's in-memory selection; source evidence is not secretly archived for replay.
- Application code does not log bodies, codes, credentials or upstream error descriptions.
  Disable body/debug tracing, proxy capture and access logging for secret-bearing OAuth
  URLs. Third-party HTTP logs may contain Google request paths/message identifiers.
  Keychain/OS/browser/process instrumentation and backups remain operator boundaries.

The existing synthetic email benchmark remains the deterministic parser/URL/policy
slice, not a live Gmail or Qwen accuracy benchmark. New synthetic HTTP fixtures and
real MCP SDK in-memory integration tests provide reproducible acquisition/guardrail
checks. They do not establish real-world fraud detection accuracy or prompt-injection
immunity. Header mismatches remain indicators, and SPF/DKIM/DMARC are not verified.

## Tests and security review

Run without Google credentials, Gmail authorization or a real model:

```sh
.venv/bin/python -m pytest -q
node --test tests/guardian.test.cjs
.venv/bin/python -m benchmarks.evaluate_emails
```

`tests/test_gmail_oauth.py` uses network-denied synthetic Google/Keychain fixtures,
fixed token sentinels, fake callback transactions, mocked local Ollama and actual MCP
ClientSession/server memory streams. The separate native receiver test connects only
to its own loopback synthetic handler. Existing tests also cover real MCP stdio.

Checks include state/PKCE/redirect/code replay and denial, control-session expiry,
Desktop configuration, strict scope/token validation, refresh and rotation, persistent
identity-bound restore, Keychain errors, revocation/delete independence, cross-account
selection rejection, forged/stale/duplicate references, bounded batches and HTTP bodies,
rate limits/timeouts/redirect denial, attachment preflight, no mailbox modification,
MIME charset preservation, partial model failures, policy independence, prompt-injection
isolation, credential/log redaction and both history-consent conditions. Full Python
and Node regressions include the unchanged dashboard and Chrome Guardian behavior.

Final verification: **437 Python tests and 14 Node tests passed**. The deterministic
synthetic email benchmark also reproduced **12/12 policy regression matches**; this
is not real-world fraud accuracy or a live Gmail/Qwen benchmark.

## Remaining deployment restrictions / unverified work

- No real Google exchange, consent-screen approval, Desktop redirect interoperability,
  refresh/revocation behavior or native Keychain read/write was live-tested here.
- Trusted launcher, private IPC capability delivery, user-facing Gmail picker/login UI
  and installation/configuration packaging remain unimplemented. The API is not an
  out-of-the-box browser login demo; do not add an unauthenticated bootstrap workaround.
- Keep FastAPI on `127.0.0.1:8000`, single worker, without reverse proxies/forwarded headers.
  Recommended flags: `--host 127.0.0.1 --port 8000 --no-proxy-headers --no-access-log`.
  The legacy non-Gmail API remains unauthenticated and must not be publicly exposed.
- Session/selection state is process-local and ephemeral; deduplication is session-local,
  not a global/durable mailbox ledger. There is no production rate limiter, durable retry
  queue, retention scheduler or shared multi-worker coordination.
- Attachment-bearing, large and unsupported MIME messages are rejected, not analyzed
  partially by silently downloading attachments. Broader mail coverage needs another review.
- Keychain ACL/code-signing review, secure capability delivery and provider-policy review
  are prerequisites to broader distribution. Same-user malware, compromised local Python,
  trusted MCP code or OS compromise are outside this boundary; this is not an OS sandbox.
- Remote revocation/cleanup may fail; response flags must be respected and users need a
  Google Account security recovery path. Native secure-store calls do not have a Python
  network-style deadline, though interaction UI is disabled and failures have no fallback.
- In-flight requests/inference cannot be retracted; subsequent stages and report delivery
  recheck authority. Redaction and AI advice remain fallible.
- No automatic inbox monitoring, Pub/Sub, Gmail write permission or Task 13.3B functionality
  is included.

## Files created or modified for Task 13.3A

Created:

- `backend/gmail_callback.py`: temporary bounded desktop loopback receiver, fixed responses,
  no query logging and lifecycle cleanup.
- `backend/gmail_google.py`: fixed Google endpoints, streamed response/time limits, token
  response validation, metadata/MIME preflight/raw retrieval and safe protocol errors.
- `backend/gmail_oauth.py`: Desktop configuration, PKCE transactions, lifecycle/Keychain
  coordination, identity-bound restore, explicit selected investigations and prose guards.
- `backend/gmail_routes.py`: protected consent, metadata, selection/investigation and
  disconnect API routes with bounded sanitized inputs.
- `tests/test_gmail_oauth.py`: synthetic integration, actual SDK, callback, privacy and
  protocol regression tests; no real Google/Keychain credentials.
- `docs/gmail-oauth.md`: this architecture, configuration, privacy, testing and limitations guide.

Modified:

- `backend/main.py`: registers Gmail routes, keeps service unconfigured by default and
  cleans up configured local sessions/listeners at shutdown.
- `backend/gmail_connector.py`: concrete selected-message Google adapter; preserves
  abstract/fake connector compatibility and safe error codes.
- `backend/gmail_security.py`: private lifecycle cleanup hook, configured status flags/
  safe last error and event-loop-safe local session closure. Authentication is unchanged.
- `backend/gmail_state.py`: live control-session checks usable during pending authorization
  and refresh, not just an already-connected mailbox operation.
- `backend/gmail_tokens.py`: masked persisted account-identity binding for safe restore;
  existing Keychain-only storage and no-fallback rules remain.
- `backend/email_parser.py`: internal bytes ingestion preserving MIME octets/charsets;
  existing JSON request contracts and limits remain unchanged.
- `backend/email_guardian.py`: shared engine accepts internal bytes and an internal-only
  known-credential block before tool dispatch; no duplicated scoring/policy.
- `docs/gmail-security-foundation.md`: historical-scope note linking this implementation.

Existing selection guards, MCP permissions/tools, URL scoring, email-1 policy, history
schema, dashboard, extension and dependency list are reused without changes for this task.
