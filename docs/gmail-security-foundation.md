# Gmail security foundation — Task 13.2

> Historical Task 13.2 scope. Task 13.3A now implements the OAuth, bounded transport
> and selected-message wiring described as future work below. See
> [Gmail OAuth integration](gmail-oauth.md) for current behavior, setup and remaining
> restrictions. The control-plane protections in this foundation remain enforced.

## Scope

This task implements a local security foundation, **not Gmail integration or login**.
There are no authorization URLs, OAuth callbacks, permission requests, real Gmail
API calls, automatic inbox monitoring, real credentials, or concrete Google connector.
No dependencies were added. Existing URL scoring and email advisory policy are unchanged.

```text
Trusted future local launcher / private IPC (not yet implemented)
  -> in-process issue_session(): bearer + independent CSRF capability
       -> protected /gmail namespace
            loopback peer + exact Host + Origin/fetch-metadata checks
            bearer authentication + mutation CSRF check
            -> private authorization state machine
            -> bounded, account/session/generation-bound selection registry
            -> abstract read-only connector (synthetic hooks in tests only)

Future OAuth coordinator (not implemented)
  -> explicit remember-connection consent -> macOS Keychain credential-store protocol
  -> verified account binding -> authorization state -> connector
  -> selected MIME bytes -> existing Email Guardian -> MCP tools -> local Qwen
```

## Backend exposure and compatibility

`backend/main.py` previously exposed analysis and history routes without application
authentication. Loopback binding alone did not authenticate callers. Task 13.2 adds
an ASGI middleware boundary around the entire `/gmail` prefix, including unknown
future routes, encoded paths, mounted/root-path deployments and preflights. Gmail
websockets are denied. This is not a router dependency that can accidentally be
omitted from a future Gmail handler.

Existing non-Gmail analysis/history routes retain their contracts and client access
behavior. No CORS grants were added, no existing checks were removed, and neither
the dashboard nor extension needs new headers. Their existing tests still run.
**This does not retrofit authentication onto the legacy API** or make that API safe
to expose publicly. Gmail authority must never be reachable through a legacy route.

Keep the service private. Recommended direct deployment for this foundation:

```sh
.venv/bin/python -m uvicorn backend.main:app \
  --host 127.0.0.1 --port 8000 --no-proxy-headers --no-access-log
```

No public/reverse-proxy deployment is supported by the Gmail boundary. Forwarded
headers are rejected. External tracing/access-log configuration is outside the
application: never log bodies, authorization headers, OAuth callback queries, or
secret-bearing URLs. In particular, do not put capabilities in query strings.

## Local control-plane authentication

The default canonical control origin is exactly `http://127.0.0.1:8000`.

Every Gmail HTTP request requires:

1. An ASGI peer address that is an actual loopback IP.
2. Exact configured Host, including port; no forwarded-host inference.
3. If Origin is present, exact equality with the canonical origin. `null`, other
   ports, other websites and alternate loopback spellings are rejected.
4. If `Sec-Fetch-Site` is present, it must be `same-origin`.
5. `Authorization: Bearer <unguessable capability>`.
6. For mutations, an independent `X-SUSNOT-CSRF` capability.

Duplicate critical headers are rejected. OPTIONS/preflight requests are not
approved. Cookies do not authenticate. Responses are `Cache-Control: no-store`,
receive `nosniff`, and do not grant cross-origin access. Invalid capabilities/CSRF
return generic 401, origin/peer/host/preflight failures 403, ambiguous headers 400.
Error bodies do not echo request values.

A non-browser client may omit Origin/fetch metadata, but **must still possess both
capabilities for mutations**. Origin is not treated as authentication: arbitrary
local programs can forge it, but cannot obtain capabilities through HTTP.

`GmailControl.issue_session()` is a trusted **in-process** API. It returns independent
256-bit random bearer/CSRF values and a session UUID; it is not an HTTP endpoint.
The server retains digests, not plaintext copies of these capabilities. Sessions
expire after 30 minutes and are limited to 16 per process. Closing/expiring one
permanently invalidates its authorization context and selections. Contexts also
check the control deadline during internal operations, not only HTTP requests.

**No public bootstrap or UI is implemented.** Ordinary HTTP clients cannot currently
obtain a Gmail control session. A future trusted desktop launcher must use private,
user-bound IPC to deliver capabilities, never a public local bootstrap URL, shared
static password, terminal log, browser storage or query parameter. This deliberate
closed-by-default behavior is not an OAuth login feature.

Current protected routes:

| Route | Behavior |
| --- | --- |
| `GET /gmail/status` | Reports the private session state and that OAuth/connector are disabled |
| `POST /gmail/session/close` | Invalidates the local capability/context/selections; explicitly reports that Google revocation was **not** performed |

There are no token-upload, account-connect, state-transition, message-selection,
message-fetch or investigation HTTP routes in this task.

## Authorization state machine

New machines begin `disconnected`. Only trusted application code can transition
them; no HTTP request can supply a target state or account binding.

| Current | Allowed next states |
| --- | --- |
| `disconnected` | `authorization_pending` |
| `authorization_pending` | `connected`, `disconnected`, `error` |
| `connected` | `expired`, `revoked`, `disconnected`, `error` |
| `expired` | `connected`, `authorization_pending`, `revoked`, `disconnected`, `error` |
| `revoked` | `authorization_pending`, `disconnected` |
| `error` | `authorization_pending`, `disconnected`, `revoked` |

Self-transitions and all other transitions are rejected. Entering `connected`
requires a local opaque account UUID. Refresh from `expired` to `connected` must
retain the same account. Reauthorization is required to change accounts. Every
transition increments a generation, invalidating older selections and leases.
Explicit local shutdown is idempotent; closing the control session additionally
makes that machine permanently unusable. A new control session needs a new machine.

`expired` represents authorization/token lifecycle state; the control-session
capability deadline is an independent restriction. No real token refresh, OAuth
state/PKCE transaction, account verification or state restoration is implemented.
A future coordinator must verify Google identity, scopes and token expiry before
calling `connected`; the state machine itself cannot establish those facts.

## Secure token-storage abstraction

`CredentialStore` defines `save`, `load`, and idempotent `delete`. `MacOSKeychainStore`
implements it with macOS **Security.framework generic-password items**, using stdlib
`ctypes` and CoreFoundation. Native libraries are loaded lazily; importing/starting
FastAPI does not access Keychain.

- Fixed service: `SUS.NOT.Gmail.OAuth`.
- Item account: an app-owned opaque UUID, not the mailbox address.
- Values: bounded, validated credential JSON held in memory and stored only inside
  Keychain. Access/refresh fields use masked `SecretStr` representations.
- Only the planned `gmail.readonly` scope is accepted; its constant does not request
  permission or create a grant.
- No `security -w ...` subprocess or shell command: token values never enter command
  arguments or a process listing.
- Keychain interaction UI is disabled for these calls. Locked/denied/unsupported
  storage fails closed with a fixed error, without plaintext or environment fallback.
- Invalid, oversized or overbroad stored credentials are rejected. Native exception
  text and secret-bearing validation inputs are not returned in storage errors.
- No SQLite, config file, Git file, environment variable or application log receives
  credentials. This store is never automatically invoked by current HTTP routes.

Tests inject a fake in-memory Keychain backend and synthetic credential strings.
**Native Keychain writes/reads and access-control behavior have not been live-tested
in this task.** No real Keychain item or OAuth credential is generated by the tests.
Platform integration should be verified later with an explicitly approved disposable
fixture before handling genuine credentials.

Future persistence must require separate “Remember connection” consent. Session-only
operation should not call `save`. A future disconnect coordinator must delete local
credentials even if remote revocation fails and distinguish local removal from
confirmed Google revocation. Keychain does not protect against a compromised OS,
malicious same-user code or a broadly trusted Python executable. Code signing,
application identity/Keychain ACL review and secure launcher IPC remain future work.
Python memory does not offer guaranteed credential zeroization.

## Explicit message-selection security

Only trusted listing code may issue selections, for message IDs actually obtained
from the authorized account. Raw IDs are bounded opaque ASCII strings, never URLs
or arbitrary paths. A future HTTP API must not expose `issue()` as a way to submit
arbitrary message IDs.

The connector's picker output replaces IDs with random 256-bit references. The
registry retains reference digests and binds each selection to:

- Control session UUID.
- Verified future account's local UUID.
- Current authorization generation.
- Original message ID and a ten-minute monotonic expiry.

Claiming requires the same connected context and explicit submitted references.
Whole batches are validated atomically under locks. Forged, tampered, stale,
cross-account, cross-session and repeated references fail without partial claims.
A lifecycle transition cannot race a registry claim into a different account.

Bounds:

| Item | Limit |
| --- | --- |
| Metadata listing / selection issuance | 20 messages |
| Claim batch | 5 messages |
| Outstanding unexpired claimed/running jobs | 5 per registry |
| Live selection records | 256 per registry |
| Retained job records/tombstones | 256 per registry |
| Selection lifetime | 10 minutes |
| Retrieval lease lifetime | 5 minutes |
| Raw message bytes | Existing 128 KiB limit |

A claim creates a private lease. Retrieval consumes it before invoking a connector
hook, so replay/concurrent duplicate fetches cannot both start. Results are checked
against the claimed ID, size and still-current authorization. Failures, cancellation,
expired leases and completion do not silently make a message eligible again.

Duplicate identity is session + account + Gmail message ID, **not the email's
untrusted RFC Message-ID**. Tombstones survive authorization refreshes/generation
changes. They are not evicted merely to make room; a full registry rejects work.
Ending a control session clears its in-memory registry data. Nothing is persisted.

This is session-local duplicate prevention, not exactly-once processing across
restarts. Explicit retry/reinvestigation, cross-restart deduplication, durable queues
and worker scheduling are not implemented. Retrieval completion is not a claim
that Email Guardian analysis completed; the connector is not wired into that engine
yet. Future orchestration must retain deduplication through analysis and use one
bounded worker rather than spawning unbounded concurrent investigations.

## Connector and network boundaries

`GmailConnector` is abstract; no production implementation is instantiated.
Its concrete wrappers check lifecycle and bounds around synthetic/future hooks for:

- Authorized account identity.
- Bounded metadata listing, returning selection handles rather than raw IDs.
- Retrieval from a claimed single-use selection lease.
- Local disconnection followed by a remote-revocation hook.

There are no send, modify, label, mark-read, delete, thread-crawl or attachment
operations. Disconnect stops local operations before awaiting revocation. A failed
revocation hook returns a generic error and does not restore access or claim success.

The endpoint planner only constructs these application-owned read destinations:

- `https://gmail.googleapis.com/gmail/v1/users/me/profile`
- `https://gmail.googleapis.com/gmail/v1/users/me/messages`
- `https://gmail.googleapis.com/gmail/v1/users/me/messages/{validated_id}`

Fixed future OAuth service constants are `https://oauth2.googleapis.com/token` and
`https://oauth2.googleapis.com/revoke`. Neither is called. There is no generic URL
parameter, transport client, arbitrary API path or model-controlled operation.

The future HTTP transport must use only these plans, TLS verification, explicit
stream/decoded-byte/time limits, encoded query parameters, no environment proxies
and no redirects. A size estimate is not a hard boundary. The planner is **not an
OS egress sandbox**; trusted future transport code must not bypass it. Network-denial
tests exercise the connector wrappers with synthetic hooks only.

OAuth credentials must never go into MCP arguments, prompts, environment or model
responses. Future acquired MIME should enter existing Email Guardian parsing,
redaction, actual MCP `inspect_url`/`inspect_text`, local loopback Qwen, typed evidence
and deterministic policy. The existing MCP allowlist is unchanged. Qwen must never
obtain Gmail connector capabilities or choose messages/network destinations.

## Privacy and threat model

Protected against within this boundary:

- Arbitrary websites: exact Origin/fetch checks, rejected CORS preflight, bearer and
  independent mutation CSRF tokens; cookies are not authority.
- Unauthorized local clients: loopback alone grants nothing; no HTTP session bootstrap.
- DNS rebinding/host confusion: exact Host, no forwarded-header trust, duplicate-header
  rejection, and scoped checks using routing's root-path semantics.
- Forged/replayed selections: random references, server-side binding, monotonic TTL,
  atomic claims, consumed leases, retained duplicate tombstones and capacity bounds.
- Credential disclosure by application storage paths: Keychain only, masked objects,
  sanitized errors, no shell argv/files/history, and no credential HTTP responses.
- Model-driven mailbox actions: no Gmail tools exposed to Qwen or MCP and no real
  connector/transport in the running app.

Remaining limitations:

- Trusted local Python, OS, MCP implementation, future launcher and Google endpoints
  remain trust boundaries; this is not an OS sandbox or protection from local malware.
- The legacy API remains unauthenticated; keep the entire service private.
- Capability delivery/UI, OAuth/PKCE, consent screens, scope/account verification,
  refresh coordination, actual revocation/deletion orchestration, native Keychain
  integration verification and production transport remain unimplemented.
- State/selection registries are per-process and ephemeral. Deploy as a single worker
  for this foundation; multi-worker sharing/coordinated locks are not implemented.
- Bounded memory is not a complete rate limiter or denial-of-service defense.
- Origin checks cannot authenticate a native client; capabilities are indispensable.
- Mailbox-wide read-only permission cannot enforce per-message consent at Google;
  a future connector must disclose that and enforce selection in application code.
- Email redaction/AI remain fallible. No new claim of credential-detection completeness,
  SPF/DKIM/DMARC verification or real-world fraud accuracy is made.

No email is collected, processed automatically, persisted, sent to external AI, or
modified by this foundation. Existing investigation-history opt-in is unchanged;
Gmail status/close, state, selections and token storage do not write history even
when its global flag and consent header are set. Future processing must reuse the
existing minimized marker/advisory/version storage without Gmail IDs or message prose.

## Tests and reproducibility

```sh
.venv/bin/python -m pytest -q
node --test tests/guardian.test.cjs
```

New tests cover unauthorized clients, cross-origin/fetch metadata/Host rejection,
CSRF, preflights, duplicate headers, mounted paths, expiry/closure, transition matrix,
account/session isolation, concurrent duplicate claims, bounded batches/registries,
single-use leases, synthetic connector result failures, fixed endpoints, secure-store
errors and account isolation, masked representations, sanitized logs and existing
endpoint contracts. They do not request Gmail permissions or contact Google. Existing
email, MCP, benchmark, dashboard and extension tests remain part of the full suite.

## Future implementation gates

1. Implement trusted launcher/private IPC capability delivery and an escaped local UI;
   never add an unauthenticated HTTP bootstrap to make testing convenient.
2. Add the approved desktop authorization-code + PKCE flow using a separate temporary
   loopback callback listener, short-lived state and system browser. Do not weaken
   `/gmail` authentication or broaden CORS to accommodate a Google redirect.
3. Verify granted read-only scope and actual account identity; bind the local UUID.
   Add explicit connection and remember-connection consent. Request no write scopes.
4. Verify Keychain platform behavior and coordinate refresh/revocation with safe local
   deletion and honest remote-failure reporting.
5. Implement fixed-endpoint Google transport with mocks first, bounded metadata picker,
   then explicit confirmation/lease-based fetching. Never fetch bodies on selection-list
   display alone.
6. Preserve original MIME bytes into a byte-aware Email Guardian adapter; do not perform
   lossy UTF-8 conversion. Keep existing parser/URL/model limits and partial-result rules.
7. Add bounded single-worker investigation scheduling, explicit retry/reinvestigate policy,
   privacy-minimized history and synthetic/live-test evidence before real-account use.
8. Review optional event-driven monitoring separately; it remains disabled and unimplemented.

## Files created or modified

Added:

- `backend/gmail_security.py`: scoped ASGI control boundary, ephemeral trusted-bootstrap
  capability registry and two inert protected control routes.
- `backend/gmail_state.py`: locked authorization state machine and lifecycle-bound contexts.
- `backend/gmail_selections.py`: bounded ephemeral selections, atomic claims, leases and
  duplicate tombstones; no email content or persistent storage.
- `backend/gmail_tokens.py`: credential/store protocols and lazy macOS native Keychain
  implementation; no token files, shell subprocesses or HTTP endpoints.
- `backend/gmail_connector.py`: abstract read-only connector, result contracts/bounds and
  fixed endpoint planner; no concrete Google network implementation.
- `tests/test_gmail_security.py`: control-plane, state, selection, race and compatibility tests.
- `tests/test_gmail_tokens.py`: mocked secure-store, failure and privacy tests.
- `tests/test_gmail_connector.py`: synthetic connector lifecycle, selection, bounds and
  destination restriction tests with network access forbidden.
- `docs/gmail-security-foundation.md`: this design, threat model, limitations and next gates.

Modified:

- `backend/main.py`: creates the empty control registry and registers the scoped middleware
  and Gmail foundation router. No existing scoring, policy, history, dashboard, extension,
  MCP permissions or API response contracts are changed by Task 13.2.
