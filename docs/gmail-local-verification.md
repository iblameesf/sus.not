# Local Gmail security verification and trusted launcher — Task 13.3B

> Current follow-up: [Task 13.3C-1 live setup/readiness](gmail-live-setup.md) adds
> non-authorizing configuration checks, root-loopback compatibility and explicit
> identity/evidence views. The results below remain the historical Task 13.3B record;
> no live Gmail authorization has been performed.

## Status and scope

Task 13.3B adds an explicit local terminal launcher and a separate native macOS
Keychain verifier. **No real Google credentials were created or loaded, no browser
was opened for Google authorization, no real OAuth flow was initiated and no real
email was retrieved during this task.** There is no automatic monitoring.

Observed results on this host, recorded 2026-10-31 UTC:

| Category | Result | Scope |
| --- | --- | --- |
| Complete Python suite | **473 passed** | Google, browser, Ollama and credential storage mocked where applicable; real MCP protocol/local transports also exercised |
| Complete Node suite | **14 passed** | Existing Chrome Guardian behavior |
| Native Keychain procedure | **7 checks passed; cleanup confirmed** | Actual Security.framework, synthetic data in a separate service only |
| Fresh native cleanup recheck | **Item absent** | Separate native store instance, exact synthetic account UUID |
| Agent-driven terminal smoke check | **Passed** | Real launcher process under a local PTY: START, status, quit; no OAuth configuration |
| Agent-driven security probes | **Passed** | Actual application via ASGI; unauthorized/forged capabilities, foreign Host/Origin and missing CSRF denied |
| Real Google OAuth/Gmail | **Not performed / unverified** | Requires later explicit authorization |
| Real system-browser/Google redirect integration | **Unverified** | Browser openers and Google responses mocked in automated tests |

These are implementation checks, not a penetration-test certification, formal proof,
or fraud-detection accuracy measurement. A local PTY can be driven by software;
its successful use is not proof of physical human presence.

Related architecture: [OAuth integration](gmail-oauth.md),
[security foundation](gmail-security-foundation.md), and
[Email Guardian](email-guardian.md).

## Launcher architecture: no capability IPC is necessary

```text
Operator explicitly starts terminal command
  -> real TTY required; explicit START confirmation
  -> private Python process imports existing FastAPI app
  -> trusted in-process GmailControl.issue_session()
       bearer and independent CSRF capability stay in memory
  -> HTTPX ASGITransport executes existing protected /gmail routes in-process
       exact virtual Host/Origin + bearer + CSRF + expiry checks still execute
       NO TCP listener, NO request to an existing localhost server
  -> only explicitly requested commands
       status / authorize / list / more / investigate / disconnect / quit
  -> close/invalidate local session on exit; pending listeners cleaned up
```

This intentionally chooses a simpler boundary than an HTTP pairing endpoint,
capability-bearing browser URL, shared token file or Unix-socket credential handoff.
There is **no public bootstrap**, no newly exposed route and no launcher daemon.
The in-process transport does not bypass the Gmail middleware or call route functions
directly. It supplies the same canonical `http://127.0.0.1:8000` Host/Origin, bearer,
CSRF and fetch-metadata headers that the protected API requires.

The apparent port in ASGI requests is a virtual canonical origin, not a network
connection. A malicious process squatting on port 8000 cannot capture these launcher
requests. An existing dashboard/extension backend can continue separately; its
in-memory control registry is not shared with the launcher. No extension, dashboard,
URL score, email policy or existing public API contract was changed.

The launcher only maps fixed operation names to existing Gmail paths. It cannot
accept arbitrary network URLs or mailbox actions. There is no email send/modify,
thread crawl, attachment download or model-controlled action command.

### Explicit local initiation and terminal behavior

- CLI stdin **and** stdout must be TTYs. Non-interactive invocation exits with code 2
  before reading configuration or issuing a session. This prevents accidental piped
  automation/logging, not malicious same-user code execution.
- `START` creates a 30-minute local control session. It does not start OAuth, load
  message metadata or read Keychain.
- `status` is explicit; there is no background polling or automatic inbox collection.
- Future `authorize` requires typing `AUTHORIZE` after the mailbox-wide read-only
  disclosure. `REMEMBER` is a separate choice; Enter means session-only credentials.
- The system browser is opened only after validating the fixed Google authorization
  endpoint, exact read-only scope, PKCE/state shape, redirect strategy and expected
  client ID. Unexpected URLs, extra secret parameters or local capabilities in the
  URL are rejected and the local session is closed.
- Browser opening is offloaded from the async loop. Terminal input uses a bounded
  Unix file-descriptor reader, so waiting for a command does not stall future OAuth
  callbacks, expiry timers or native shutdown. Injected test input also does not
  block the loop. Oversized terminal input is rejected; cancelled readers are removed.
- `list` requests at most 20 metadata entries. `more` requests a next page only after
  another explicit command. Neither automatically retrieves bodies.
- Metadata display is JSON-escaped (including ANSI/control/bidi characters), not
  rendered as HTML. Selection references and Gmail IDs are not printed; the operator
  chooses current-page numeric indices.
- `investigate` requires one to five unique valid indices and typing `INVESTIGATE`.
  The existing registry performs atomic account/session/expiry/duplicate checks.
  The local page is cleared after submission; no implicit retry/stale selection reuse.
- Typing `RECORD` is a separate per-investigation history opt-in, still requiring
  `SUSNOT_HISTORY_ENABLED=true`. The header is not sent on other operations.
- Terminal investigation output contains IDs, completion/advisory status, policy
  version and evidence/error counts, **not raw email or model prose**. The underlying
  engine still produces the full structured, evidence-linked report in memory.
- `disconnect` requires `DISCONNECT` and displays independent revocation/storage
  outcome booleans. A false result must not be treated as successful remote cleanup.
- `quit`, EOF, exceptions and interruption close the local capability/context. They
  do not claim to revoke Google or erase deliberately remembered Keychain entries.

### Local trust boundary

Authorization is possession of unguessable capabilities in a trusted process, not
merely being on localhost or having an Origin header. A website cannot call the
launcher, issue its capabilities or obtain them through a browser bootstrap. Native
local code can forge Origin/Host but does not gain a capability via HTTP.

The CLI's TTY check and typed phrases are consent/accident-prevention affordances,
not an OS authentication challenge or hardware user-presence attestation. The trusted
boundary is the operator's OS user, Python process and verified application code.
Code already running with that user's privileges may inspect memory, modify Python
or fake a PTY. This is not an OS sandbox or protection from local malware.

Local bearer/CSRF capabilities, Google access/refresh tokens, client secret and PKCE
verifier are never put in browser URLs, command arguments or files by the launcher.
OAuth necessarily puts public client ID/state/challenge in the authorization URL;
Google's later callback contains a short-lived, single-use authorization code bound
to PKCE. That protocol URL is not a local capability bootstrap and is not printed by
the launcher. Browser history/OS tracing cannot be promised secure erasure.

## Safe reproduction now: no Google configuration

Run from a real local terminal, not redirected input/output:

```sh
source .venv/bin/activate
python -m backend.gmail_launcher
```

Type only:

```text
START
status
quit
```

Expected status is `disconnected`, with `oauth_enabled: false` and
`connector_enabled: false`. No HTTP server or OAuth callback listener is started.
No model, Gmail or Keychain operation is needed for this smoke check. **Do not select
`authorize`, provide a real client configuration or begin Google login for this task.**
Without an interactive terminal, the command should print only a rejection message
and return exit code 2. `--help` is also safe and has no configuration/session effects.

## Isolated native macOS Keychain verification

### Isolation and behavior

The verifier is a separate command, not a normal pytest test or launcher startup step.
It uses the existing Keychain implementation, with one narrowly allowlisted additional
service namespace:

- Production: `SUS.NOT.Gmail.OAuth` — **not queried or modified by this procedure**.
- Verification: `SUS.NOT.Gmail.LocalVerification`.
- Account: a fresh UUID per run. An existing item at that UUID causes rejection before
  any overwrite/delete; normal UUID collision probability is negligible, not assumed
  impossible by the code.
- Values: explicitly synthetic, non-sensitive access/refresh strings and
  `synthetic@example.invalid`. These are not valid Google credentials and never go
  to any network endpoint. They are not printed or passed as process arguments.

The native backend still disables Keychain interaction UI. No shell `security -w`
command, password argument, SQLite token storage or plaintext fallback is used.
Native failures preserve only a numeric OSStatus for diagnostic reporting; credential
values and raw exception messages remain suppressed.

### Run and expected checks

This command **does write temporary synthetic Keychain data**, and requires an
explicit opt-in flag:

```sh
.venv/bin/python -m backend.gmail_keychain_verify --run-native
```

Without `--run-native`, it prints help and exits 2 without touching native Keychain.
With the flag, it prints only service/account cleanup metadata and a sanitized report:

1. Missing item reads as absent.
2. Write and read a synthetic credential envelope.
3. Update token values and read the updated envelope.
4. Write deliberately malformed synthetic data and verify safe validation rejection.
5. Recover by writing a valid envelope and read it.
6. Delete and verify absence.
7. Delete an already missing item without failure.
8. Independently attempt cleanup in `finally`, including after partial-write failure
   or interruption. Read back to confirm absence.

Exit 0 requires **all seven checks and confirmed cleanup**. Any failure returns 1,
identifies only the failed stage/optional numeric OSStatus, and never claims success
when cleanup cannot be confirmed. No report or credential file is automatically
persisted. The initial account UUID/service locator is printed before mutation so
an interrupted run can be inspected without displaying a password.

### Native result actually observed

Environment: macOS **27.0.1**, build **26A434**, Python **3.12.4**.
The run used verification account **`b98b64a4-e36c-4f6d-bd9a-32e1210167ea`**.
This UUID is non-sensitive cleanup metadata, not a credential.

Observed report:

```json
{
  "checks": {
    "missing_read": true,
    "write_read": true,
    "update_read": true,
    "invalid_data_rejected": true,
    "recovery_read": true,
    "delete_read": true,
    "missing_delete": true
  },
  "cleanup": "confirmed_absent",
  "errors": [],
  "success": true
}
```

A subsequent read using a fresh native `MacOSKeychainStore` instance in that same
verification namespace confirmed the exact UUID was absent. No Keychain prompt or
user password interaction was observed. This demonstrates native CRUD/interoperability
and malformed-data handling for this interpreter/user/OS context, **not** a review of
all Keychain ACLs, encryption internals, production item access or app code-signing.

### If native access is unavailable or interaction is needed

Do not disable fail-closed behavior or use a plaintext workaround. `-25308` commonly
indicates interaction is not allowed; other OSStatus values need their own diagnosis.
Locked/permission-denied/ACL/user-presence failure modes were tested with mocks, not
by locking the operator's real login keychain during this task.

For a later operator-authorized retry:

1. Use the same trusted interpreter and intended logged-in desktop user.
2. Open macOS Keychain Access through the normal OS interface. If needed, unlock the
   login keychain there, using **only the OS-owned password dialog**.
3. Do not paste any password into Pi, this CLI, command arguments or environment.
4. Review app identity/access-control issues rather than granting broad access merely
   to force a passing test. The code continues to request no interaction UI.
5. Rerun the isolated synthetic command and inspect both check and cleanup outcomes.
6. If cleanup is unconfirmed or a process was killed, search Keychain Access for
   `SUS.NOT.Gmail.LocalVerification`, match the printed account UUID and remove only
   that test item. Do not choose Show Password or delete a production entry.

`finally` cannot survive power loss, SIGKILL or a native process crash. Absence of the
item is not proof of secure erasure from OS caches, Keychain backups or memory.

## Security review and test mapping

| Property | Implementation/check | Verification scope |
| --- | --- | --- |
| Explicit trusted initiation | TTY + START; no HTTP bootstrap; in-process capability issuance | Mocked tests and actual PTY smoke check |
| Bearer/CSRF/Host/Origin | Existing middleware runs on ASGI requests, including mutations | Regression tests and actual-app ASGI probes |
| Session expiry and cleanup | Existing 30-minute control deadline; no automatic renewal; close in async context cleanup | Mocked expiry/exception tests |
| Callback responsiveness | Nonblocking terminal reader; browser helper off event loop | Reader/cancellation/heartbeat tests |
| OAuth state, PKCE and replay | Exact redirect/state, S256, one-use transactions, bounded callback | Existing mocked OAuth and local receiver tests; no Google exchange |
| Idle pending expiry | Expected control expiry handled without unhandled timer error | New regression test, fake clock/listener |
| Account isolation | Verified provider identity binding, generation/session-bound refs | Existing mocked profile/restore/cross-account tests |
| Selection expiry/duplicates | Registry claims and tombstones reused, not bypassed by CLI | Existing tests plus launcher repeat-submission tests |
| Limits/destinations | Fixed command paths; bounded pages/batches/body sizes; Google URL validation before browser open | Mocked negative tests; no arbitrary endpoint opens |
| Credential redaction | Capabilities stay in memory; fixed errors; source/prose guards; summary excludes prose | Captured-output/log tests; no formal DLP guarantee |
| Native token storage | Dedicated synthetic service, CRUD/update/error/recovery/final cleanup | Native procedure above; production namespace untouched |
| Local AI and MCP | Existing actual SDK tools and fixed local Ollama client | Integration tests with synthetic input/mocked Ollama |
| No collection/side effects | No startup listing/OAuth; explicit list/selection/consent only | No-provider-call tests and unconfigured PTY smoke check |

Code review confirmed Ollama remains `http://127.0.0.1:11434`, with environment proxies
and redirects disabled; Qwen receives no Gmail or shell capabilities. Existing MCP
calls use the fixed stdio server and exactly the two investigation tools. Submitted
URLs/images are not fetched. No URL scoring, email-1 policy, history schema or Chrome
Guardian behavior changed. No dependency was installed.

An expected idle-expiry edge case was fixed during review: a pending OAuth timer
now checks the control-session lifetime before attempting an error-state transition,
so an expired/closed control session does not cause an unhandled timer exception.

### Separately observed local smoke checks

- **Real child process under PTY:** START → status → quit; disconnected/unconfigured
  status observed, clean exit 0. `lsof` restricted to the child PID showed no TCP
  listener. No capability-shaped token appeared in the captured transcript. This was
  agent-driven, not a human-driven browser test or a proof against arbitrary leakage.
- **Actual application via ASGI:** missing/forged bearer denied (401), foreign Origin/
  Host denied (403), mutation without CSRF denied (401), valid status allowed (200),
  and a proposed `/gmail/launcher` public bootstrap route absent (404 with valid auth).
- **Actual non-TTY CLI:** exited 2 with an interactive-terminal requirement; no config
  read, session issuance or Google operation.
- **Fresh native store read:** synthetic verification item absent after cleanup.

No human browser login, real Gmail account isolation test, or external network
penetration test was performed. Automated mocked checks must not be presented as
those live checks.

## Reproduction: automated tests

```sh
.venv/bin/python -m pytest -q
node --test tests/guardian.test.cjs

# Focused offline checks, all native storage/provider/browser behavior mocked:
.venv/bin/python -m pytest -q \
  tests/test_gmail_launcher.py tests/test_gmail_keychain_verify.py \
  tests/test_gmail_security.py tests/test_gmail_tokens.py tests/test_gmail_oauth.py
```

Normal pytest does not create actual Keychain items or contact Google. Native
verification is the separate, explicit command above. Tests retain actual MCP SDK
communication while using synthetic email and mocked Ollama/Google responses.

## Requirements for a future, separately authorized live Gmail test

**The following is a future gate, not authorization to run it now.**

1. Obtain explicit approval naming the account and test scope. Prefer an already-owned,
   dedicated test mailbox containing only synthetic messages; do not use a personal inbox
   full of private data for the first test.
2. The operator must configure a Google **Desktop app** client and consent/test-user
   settings under the provider's current restricted-scope policies. Do not create or
   paste Google credentials in Pi. Review verification/Workspace restrictions separately.
3. Store the downloaded installed-client config outside the repository, owned by the
   operator, mode 0600, a regular non-linked file no larger than 16 KiB. The launcher
   rejects repository paths, direct symlinks, hard-linked, shared, malformed or oversized
   files. It only accepts the fixed Google Desktop configuration endpoints.
4. Rerun synthetic native verification with the intended interpreter/user first. Native
   production-namespace ACL/app-signing behavior remains a separate live-test concern.
5. A later operator can explicitly provide the existing private config path through
   `--client-config PRIVATE_PATH`. That reads configuration only after START; it does
   not itself begin OAuth. Do not use this flag with real credentials during this task.
6. Only a separate `authorize` command plus AUTHORIZE confirmation opens the validated
   Google URL. Use the system browser and verify the intended account before approving.
   Gmail read-only access is mailbox-wide; SUS.NOT selection is an application restriction,
   not a provider per-message permission.
7. Prefer session-only (Enter at REMEMBER) for the first live test. First verify status,
   then explicitly list metadata, choose a single synthetic message index and confirm
   INVESTIGATE. Keep history off unless separately wanted and globally enabled.
8. Verify the expected evidence/policy output without treating it as calibrated fraud
   accuracy. No attachment or remote-image retrieval should occur. Test failures must
   remain partial/review outcomes, never safe verdicts.
9. Explicitly DISCONNECT when done. Check both remote-revocation and credential-removal
   booleans. Quit is local session shutdown, not remote revocation. Use Google Account
   controls if remote cleanup is unconfirmed.

There is no saved-account picker/restore UI yet, though the trusted restore method
exists. A remembered account UUID is not automatically enumerated or resumed by
this terminal. Use session-only for initial testing; do not assume quitting removes
remembered credentials. No Gmail browser dashboard or private cross-process IPC has
been added; the terminal's in-process design deliberately avoids that complexity.

## Remaining limitations

- Real Google authorization, redirect/browser interoperability, refresh/revocation and
  real mailbox processing remain untested. No permission for such a test is implied.
- Native CRUD passed only for this machine/user/interpreter and synthetic namespace.
  Locked/denied ACL conditions, production items, other macOS versions, signed packaging
  and user-presence requirements have not been live-verified.
- Same-user malware, modified Python/dependencies, terminal capture, browser configuration,
  OS compromise and process-memory access are outside the boundary. File permission
  checks and private ASGI are not a sandbox or configuration-authenticity attestation.
- Terminal metadata may still contain PII despite redaction. The operator's scrollback,
  screenshot tools, OS logs/backups and debug/body tracing require separate care.
- Idle session authorization expires on use; there is no guaranteed erasure of every
  memory copy exactly at its deadline. In-flight work cannot be retracted. Native OS
  browser/Keychain helpers are not covered by network-style Python deadlines.
- Registries/deduplication remain per-process/session, not durable or cross-session
  exactly-once. No production rate limiter, durable retry queue or automatic recovery
  of consumed selections was added.
- Attachment-bearing/unsupported/large messages remain rejected. Partial failures and
  lease expiration need explicit handling; this task does not expand analysis coverage.
- Existing non-Gmail API routes remain unauthenticated. Do not expose the legacy server
  publicly or infer that this private launcher secures every existing endpoint.
- The launcher is intended for macOS/Unix TTYs and a single process/event loop. No
  cross-platform GUI or browser-based bootstrap is included.

## Files created or modified

Created:

- `backend/gmail_launcher.py`: trusted TTY entry point, private ASGI client, fixed-command
  consent UI, native callback-responsive input, safe browser URL checks, metadata escaping,
  bounded selections, opt-in history and privacy-minimized terminal summaries.
- `backend/gmail_keychain_verify.py`: explicit synthetic native verification, separate
  namespace, validation/recovery checks, safe OSStatus reporting and `finally` cleanup.
- `tests/test_gmail_launcher.py`: offline launcher, ASGI/header, lifecycle, file-permission,
  browser-destination, terminal responsiveness/output, consent and history tests.
- `tests/test_gmail_keychain_verify.py`: mocked procedure gates, namespace separation,
  partial-write/error/cleanup behavior and secret-free output; no automatic native access.
- `docs/gmail-local-verification.md`: this architecture, observed evidence, reproduction
  guide, limitations and future live-test gate.

Modified:

- `backend/gmail_tokens.py`: fixed verification-service allowlist and optional sanitized
  OSStatus propagation. Production service remains the default; no fallback was added.
- `backend/gmail_oauth.py`: expected idle control-session expiry handled safely in the
  pending-authorization timer; OAuth/PKCE policy and scope are unchanged.
- `docs/gmail-oauth.md`: links the Task 13.3B launcher/native-verification follow-up while
  retaining the historical Task 13.3A test record and live-Google restrictions.

Existing FastAPI registration, dashboard, extension, URL scoring, email decision policy,
MCP tools, selection rules, history schema and dependencies were not modified for this task.
