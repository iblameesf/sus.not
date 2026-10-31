# First controlled Gmail test: setup and readiness — Task 13.3C-1

## Stop boundary and current result

**This is a preparation guide, not permission to connect an account.** During this
task no real client configuration was supplied, no Google client/project was created,
no authorization was started, no Gmail permission was requested and no real email
was read. Only public official documentation was fetched from Google.

Current local command result:

- **Blocked:** a private Google Desktop client configuration path has deliberately
  not been supplied. The checker does not search your computer for credentials.
- Passed: imported FastAPI security probes, trusted launcher, fixed runtime read-only
  scope, root-loopback callback strategy, local Ollama destination and MCP allowlist.
- Passed separately with explicit opt-in: synthetic native Keychain write/read/update/
  validation/delete checks, with cleanup confirmed in the verification namespace.
- Unverified: Cloud project/API enablement, consent/audience/test-user settings,
  provider registration and actual browser/Google interoperability. The readiness
  command also does not contact Ollama to prove its server/model is running.

**Do not paste client configuration, client secrets, tokens, authorization codes,
private email or passwords into Pi, ChatGPT, Git, screenshots or this document.**
Future configuration is performed privately by the operator on their Mac.

## 1. What the existing implementation expects

| Setting | Exact requirement |
| --- | --- |
| OAuth client | Google **Desktop app**; exported JSON has an `installed` object, not `web` or a service-account key |
| Client ID | Nonempty Google client ID ending in `.apps.googleusercontent.com`; local syntax checking cannot prove it exists at Google |
| Client secret | Downloaded installed-client configuration field, kept private; not an access/refresh token and not a confidential native-app security boundary |
| Token endpoint | Fixed `https://oauth2.googleapis.com/token` |
| Authorization endpoint | Fixed `https://accounts.google.com/o/oauth2/v2/auth`; known legacy/v2 endpoint declarations accepted in the download |
| Scope requested by SUS.NOT | Exactly `https://www.googleapis.com/auth/gmail.readonly` |
| Redirect | **`http://127.0.0.1:<OS-assigned-port>/`**, temporary listener, exact callback Host and URI checks |
| PKCE | New random verifier per transaction, SHA-256/S256 challenge; verifier remains in process memory |
| OAuth state | Independent random value, digest comparison, five-minute lifetime, one-use transaction |
| Local API authorization | Private launcher capabilities, bearer + separate mutation CSRF, Host/Origin/peer/expiry protections |
| Token persistence | Session-only by default; explicit REMEMBER uses macOS Keychain, never token files |
| Message access | Explicit bounded metadata listing, then account/session/generation-bound selected references; no mailbox-wide investigation |
| AI/tools | Existing local Qwen/Ollama and actual MCP `inspect_url` / `inspect_text`; model cannot retrieve messages or select tools |

The review aligned the callback to Google's documented **root-loopback** form,
instead of depending on unverified acceptance of an arbitrary random callback path.
The previous random path is no longer used. Random state and PKCE remain mandatory;
matching the root path alone never authorizes a callback. There is no callback route
on the public FastAPI `/gmail` namespace, and no CORS/authentication exception was added.
The port is chosen when the listener binds, not entered into the downloaded JSON.

Optional `installed.redirect_uris` declarations must be HTTP loopback **roots**
(`localhost`, `127.0.0.1`, or `[::1]`); remote hosts, credentials, whitespace/control
characters, queries, fragments and arbitrary paths are rejected. Exports without
that field can still be locally validated against the application's runtime strategy.
Neither case proves Google's registration/acceptance without a later authorized test.

Standard downloaded OAuth client JSON does **not** normally contain a scopes list.
Scopes are declared under Google Auth Platform Data Access and independently requested
in code. Do not edit JSON to add scopes or use environment variables to broaden access.

Read-only scope is required because `gmail.metadata` omits message bodies. Add-on
current-message scopes require a different add-on architecture. No `gmail.modify`,
`gmail.send`, full-mail `https://mail.google.com/`, OpenID Connect or external AI scopes
are requested. **Read-only grants mailbox-wide reading at Google. It does not limit
Google's grant to the messages selected in SUS.NOT.** Selection is enforced locally.

## 2. Google Cloud setup — operator instructions, not executed here

The UI labels below follow current official Google documentation reviewed on
**2026-10-31**. Console layout can change; use the official references at the end.
Do these preparation steps in your own browser only when you choose to configure
the project. Stop before any Gmail authorization until the separate live test is approved.

### A. Create or select a project

1. Open [Google Cloud Console](https://console.cloud.google.com/).
2. Use the project selector to choose an appropriate project, or create a new one
   through **IAM & Admin → Create a Project**.
3. Prefer a separate project named something like **SUS.NOT Local Test**. Keep unrelated
   OAuth clients out of it: Google's revocation can invalidate a user's grants across
   all OAuth clients/scopes in the project.
4. Confirm the selected project in the Console header before each configuration step.
   Project name/ID and OAuth client ID are different identifiers.
5. If an organization controls project creation or asks for approval/billing, follow
   its policy; this guide cannot verify your entitlements or waive requirements.

### B. Enable only the needed API

1. In that project, open **APIs & Services → Library**.
2. Search for **Gmail API**, open Google's API entry and select **Enable**.
3. Check it appears in the project's enabled APIs.

No Google AI, Vertex, remote MCP service, Gmail push notifications or Pub/Sub is needed.
SUS.NOT's custom MCP server and inference remain local. Enabling the Gmail API does
not grant access to any mailbox.

### C. Configure branding and audience

1. Open **Google Auth platform → Branding**. If it is not configured, choose
   **Get Started**.
2. Enter the app name, a monitored support email and developer contact information.
   Review Google's user-data policy before accepting the setup terms.
3. Choose the audience based on the **actual intended test account**:
   - Personal `@gmail.com` account or users outside your Workspace organization:
     **External**. Keep publishing status **Testing** for this controlled development test.
   - **Internal** is only appropriate for a project in a Google Cloud Organization
     and accounts belonging to that organization. It is not a general way to make
     a personal Gmail app private or bypass verification.
4. Under **Audience → Test users → Add users**, add the dedicated Google test account
   for an External/Testing project, then save. Use a mailbox with Gmail enabled and
   only synthetic test mail; don't begin with a personal/university production inbox.
5. Workspace administrators, Advanced Protection or service restrictions may still
   prevent authorization. Obtain the required approval; do not disable security to
   get the test to pass.

### D. Declare the single scope

1. Open **Google Auth platform → Data Access → Add or Remove Scopes**.
2. Select **`https://www.googleapis.com/auth/gmail.readonly`** (use manual scope entry
   if the search UI requires it). Save the selection.
3. Confirm the Gmail read-only scope is listed under **restricted scopes** and that
   you have not added sending, modification or full-mail permission.

This Cloud declaration is distinct from the code's request. The readiness command
checks the code but cannot inspect the Console. Declaring the scope does not itself
request the user's permission. A fresh dedicated project also avoids confusion from
older grants containing extra scopes, which SUS.NOT's token validator rejects.

### E. Create a Desktop OAuth client and download its configuration

1. Open **Google Auth platform → Clients → Create Client**.
2. Choose **Application type: Desktop app**, and give it a recognizable test name.
   Do not choose Web application, Chrome Extension, service account, API key, or
   domain-wide delegation. Chrome Guardian does not need Gmail permissions.
3. If Console offers an AI-agent designation, review Google's current definition
   before choosing: this implementation is a user-driven Desktop flow; Qwen has no
   Gmail action tools. Agent-specific delegation/policies are not implemented or
   certified here. Pause for review if the provider requires a different policy.
4. Create the client and use **Download JSON** in the creation dialog/client details.
   Store the download privately. Do not copy its contents into a chat or a code file.
5. The exported file should contain an **`installed`** object. If it contains `web`,
   create the correct Desktop client; **do not rename the JSON object to disguise it**.

Desktop loopback uses a dynamically assigned port. Do not create a Web client merely
to add JavaScript origins or register `http://127.0.0.1:8000/gmail/...` as a redirect.
Port 8000 is the local API's virtual origin, not the OAuth callback listener. Do not
use deprecated out-of-band code copy/paste or custom mobile redirect schemes.

### F. Secure the local file

Use a private, non-synced directory **outside the repository**, for example:

```sh
mkdir -p "$HOME/.config/sus-not"
chmod 700 "$HOME/.config/sus-not"
```

In Finder, move the **one intended downloaded file** into that directory and name it
`gmail-desktop.json`. Use Finder's Go to Folder for hidden directories if needed.
Avoid ambiguous wildcard moves, shared folders, symlinks, hard links and cloud-synced
Downloads/Desktop locations. Then, in your own terminal:

```sh
chmod 600 "$HOME/.config/sus-not/gmail-desktop.json"
```

The loader requires an operator-owned regular file, no group/other permissions,
a single link and at most 16 KiB. The file is read, not executed. Client ID/secret
are not printed. Do not run `cat` on it in a recorded terminal or share a screenshot
of the client-secret display. A native app cannot keep its packaged client secret
confidential against local code; PKCE and the local trust boundary are still essential.

**Do not copy Google's quickstart's `credentials.json`/`token.json` storage pattern
into this repository.** SUS.NOT already has its bounded transport and Keychain store;
no additional Google SDK installation is required for this task.

## 3. Local readiness command — does not authorize

From the project root:

```sh
source .venv/bin/activate
python -m backend.gmail_readiness
```

With no path, expect **blocked / missing configuration**, not automatic credential
search or authorization. The command is deliberately safe to run non-interactively.

After the operator privately supplies a valid configuration, these commands remain
**non-authorizing**:

```sh
python -m backend.gmail_readiness \
  --client-config "$HOME/.config/sus-not/gmail-desktop.json"

# Explicit extra permission for temporary SYNTHETIC Keychain data only:
python -m backend.gmail_readiness \
  --client-config "$HOME/.config/sus-not/gmail-desktop.json" --verify-keychain
```

### What is checked

- Existing launcher file-loading rules; installed-client shape, ID/secret syntax and
  fixed Google endpoint declarations. Neither ID nor secret/path is printed.
- Optional declared loopback roots and actual runtime root/ephemeral-port strategy.
- The single runtime `gmail.readonly` scope and credential schema's scope default.
- Static local Ollama destination and exactly the two allowed MCP tools.
- **Actual imported-app ASGI probes**: fresh private launcher status, denied missing/
  forged bearer, foreign Host/Origin, preflight and mutation without CSRF; successful
  local close and rejection of the closed capability.
- Keychain: default **read-only** probe of a fresh UUID in
  `SUS.NOT.Gmail.LocalVerification`, never production token entries.
- With `--verify-keychain`, the existing full synthetic CRUD/error/recovery verifier
  runs in that isolated namespace and must confirm cleanup. It never prints fixture
  values. The namespace/account locator is safe cleanup metadata.

The command does **not** create `GmailService`, start PKCE/state transactions, open a
callback socket, browser or public server, call Google/Gmail/Ollama/MCP, request a
scope, enumerate production Keychain entries or alter existing sessions. Its temporary
ASGI capability is closed; it does not enter/shut down another app's lifespan.
It tests the imported application, not a separate running reverse proxy/server.

### Exit codes and honest interpretation

| Exit | Status | Meaning |
| --- | --- | --- |
| 0 | `local_checks_passed` | Config/local guards/full synthetic Keychain check passed; **not** Google approval or permission to start live OAuth |
| 1 | `blocked` | Missing/invalid config or a failed local prerequisite; see safe `blocking_reasons` |
| 2 | `needs_local_verification` | Config/guards/read access pass, but Keychain write/update/delete have not been verified by this run |

Default read access is not claimed as proof of write capability. Google API enablement,
registered client type, Data Access, test-user/audience policy, browser interoperability
and a running/installed Qwen model remain explicitly **unverified/manual prerequisites**.
The standard JSON download has no authoritative Console-scope setting for the checker
to read. `google_cloud_verified` and `authorization_started` remain false.

A locally valid file can be synthetic, stale, deleted at Google or from the wrong
project. Do not interpret a 0 exit as a successful live account connection.

### Result actually observed for Task 13.3C-1

No real configuration path was supplied or searched. Both the default and explicit
synthetic-Keychain readiness runs returned exit **1**, with only the missing client
configuration as a local blocking reason. Scope/redirect/launcher/security/static
analysis-guard checks passed. With `--verify-keychain`, all seven native synthetic
checks passed and cleanup was `confirmed_absent` for verification UUID
`a6d81ca3-f2fa-4ad8-a952-6ef5062fda79`. No production credential was read.
No callback listener, authorization, Gmail request or model request was performed.

## 4. Controlled live test plan — STOP until separately approved

This section is a later operator checklist. **It was not executed during this task.**
Use one dedicated test account, one synthetic attachment-free email, one selection,
no history persistence and session-only credentials for the first attempt.

### 1. Prepare synthetic input and start local components

Privately place a simple email in the dedicated mailbox, with no attachments, inline
images, image signature or forwarded `.eml` parts. A suitable harmless test is:

- Subject: `SUS.NOT synthetic test 001`
- Body: `This is a synthetic test; do not act on it. Simulated pressure: your account
  will close today unless you verify at https://user@192.0.2.1/verify .`

`192.0.2.1` is a documentation address and `user` is dummy URL user information,
not a credential. **Do not click the URL.** SUS.NOT inspects it lexically, not by
visiting it. Prepare the message manually; SUS.NOT has no send capability.

Activate the existing virtual environment. Ensure the local Ollama service is running
and `ollama list` shows **`qwen3.5:4b-q4_K_M`**. If the service is not already running,
an operator can start `ollama serve` separately. If the model is absent, stop and
resolve that prerequisite before the live test; readiness did not download it.

Run the configuration/full-synthetic-Keychain readiness check above, and complete
all manual Cloud/account checks. There is no need to start a second uvicorn server
for the Gmail terminal: it imports FastAPI privately through ASGI. An existing
extension/dashboard backend can stay separate; it does not provide the terminal's
capabilities. Do not expose either server publicly.

### 2. Start the trusted launcher

In a real local terminal, only after approval:

```sh
python -m backend.gmail_launcher \
  --client-config "$HOME/.config/sus-not/gmail-desktop.json"
```

Type `START`, then `status`. Expected before authorization: disconnected, with OAuth/
connector **configured** flags true. This means configuration loaded, not that Google
has granted access. No message should have been listed or retrieved.

### 3. Authorize the dedicated account explicitly

Type `authorize`, read the mailbox-wide permission notice, then type `AUTHORIZE`.
Press Enter at `REMEMBER` for session-only operation. Only now should the system browser
open Google's authorization page. Do not sign in inside Pi, an embedded webview or
an unofficial page. Local capabilities and access/refresh tokens are never browser
query parameters; OAuth state/challenge and the later one-use authorization code are
protocol parameters, not a local bootstrap.

Verify the intended project/app and dedicated account before accepting **only Gmail
read-only** access. Warnings can occur for an owned development/test app; do not
blindly bypass a warning for an unknown app, unexpected scope or policy block.
If your account cannot authorize the app, stop instead of weakening app/account security.

Return to the terminal and explicitly request `status`. Wait for connected state;
there is no automatic message collection or listing on successful authorization.

### 4. Confirm the backend's account identity before listing

Type `identity`, then `IDENTITY`. The explicit read-only action gets the authenticated
Gmail profile and displays its address with `source: gmail_profile`. Compare it with
the dedicated account you approved. This is the connection's account, not verification
of the sender of any email.

If it is wrong, **disconnect immediately before listing or selecting anything**.
Review the system browser's Google account selection, then start another deliberate
attempt only after cleanup. Do not silently continue against a personal mailbox.
The displayed address is PII; do not share terminal captures without redaction.

### 5. Select exactly one synthetic message

Type `list`. It loads only one bounded metadata page (up to 20 entries), with redacted,
escaped fields and numeric indices. No body is fetched. Locate the unique synthetic
subject and note its current index. Use `more` only as another explicit action if needed;
it replaces the current page rather than scanning the mailbox automatically.

Do not select private/production email. If the message is ambiguous or absent, stop.

### 6. Investigate the selection

Type `investigate`, enter that single index, then type `INVESTIGATE`. Press Enter at
`RECORD` to keep history off. The server's global history flag alone is insufficient
to store a record without this per-request consent.

The connector claims the reference atomically, checks its account/session/generation/
expiry and does a body-free MIME preflight. Attachment-bearing and unsupported mail
is rejected as a whole; no attachment endpoint is available. Only the authorized
selection's bounded raw MIME enters the shared Email Guardian engine.

### 7. Inspect actual evidence and policies

First inspect the terminal summary's status, UUID, advisory, policy version and counts.
Then type `evidence` and `EVIDENCE` to explicitly display the latest structured report
held in memory. It is JSON text, not executed or rendered HTML. The report can contain
private findings despite redaction: do not log/share it casually. This view does not
fetch more email or rerun AI, and is invalidated by account/session/generation changes,
new authorization, disconnect, expiry or exit.

For this synthetic URL, confirm the **unchanged URL heuristic** produces score **70**
(IP +30, URL authority user information +25, `verify` path +15), with separate URL
policy `1`. Confirm email policy `email-1` recommends an advisory/dismissible warning
from explicit evidence rules. This is not a fraud probability or an email score.

Check report-local evidence IDs, types, source components, supporting references,
limitations, correlations, `tools_used` (`inspect_url`, `inspect_text`), AI uncertainty
and `errors`. The actual wording of Qwen findings is not fixed ground truth. A partial
or failed check is not a successful safe-mail assessment; HTTP 200 alone is insufficient.
Do not follow instructions contained in email/model prose.

No credentials, complete body, Gmail ID or account address should be persisted in
investigation history. The public report is privacy-minimized, not a guaranteed
secret/PII detector. Only the latest batch is cached by the launcher, not a disk archive.

### 8. Disconnect and revoke

Type `disconnect`, then `DISCONNECT`. Confirm:

- `disconnected: true`
- `google_revocation_performed: true`
- `credentials_removed: true`

Inspect failure flags rather than assuming 200/quit means remote revocation. Google
notes revocation can take time and can remove the user's grants for **all clients
and scopes in that Cloud project**. This is another reason for a dedicated test project.
If unconfirmed, use Google Account → Security / third-party connections to remove the
owned test application's connection, without sharing tokens or authorization URLs.

### 9. Verify cleanup and end the session

Type `status` and confirm disconnected. The explicit disconnect clears the connection's
in-memory credentials and the launcher's cached report/selections. In session-only
mode no Keychain credential item was written in the first place. For remembered
connections, disconnect now verifies its own Keychain binding is absent after deletion;
read failure or a remaining item reports `credentials_removed: false`, retaining a
cleanup handle for a deliberate retry.

Never delete other saved-account items blindly. If Keychain is unavailable, resolve
it through the OS-owned interface and retry explicit disconnect before closing the
control session. The isolated readiness Keychain check is **not** proof that a real
Google grant was revoked or a production item was deleted.

Finally type `quit`. Quit closes local authority but is not a substitute for disconnect:
it does not revoke Google or remove deliberately remembered entries. OS/browser
history, backups and process-memory erasure remain outside these guarantees.

## 5. OAuth restrictions and troubleshooting

### Current official Testing restrictions

Google's Manage App Audience guidance states:

- External projects in **Testing** are limited to **up to 100 listed test users**.
- Test-user authorizations expire **seven days after consent**. Offline refresh tokens
  for that consent also expire. The basic name/email/profile-only exception does **not**
  apply to `gmail.readonly`.
- There is a separate unverified-app new-user cap (currently 100), distinct from test-user
  slots and from refresh-token issuance limits. Removing a test user is not a way to
  reset a lifetime unverified-app cap.
- Workspace policies, unavailable Gmail service or Advanced Protection may block access
  even for a listed test user. Internal projects still need appropriate administrator policy.

Do not publish the app merely to avoid seven-day expiry or tell users to disable security.
Google permits experimental/test builds under its current development guidance, but this
is not an assurance that your app is verified, unlimited or approved for distribution.

`gmail.readonly` is **restricted**. Google documents restricted-scope verification and
security-assessment requirements, including assessment when restricted data is stored
on servers or transmitted. Current exemptions/deployment details must be reviewed
before distribution. Local Qwen/no cloud AI does not automatically certify compliance.
Google recommends maintained OAuth libraries; SUS.NOT's existing bounded implementation
is not claimed to be Google-certified. Optional DPoP/device-bound tokens and autonomous
Google-agent authorization are not implemented.

### Common failures

| Symptom | Safe next step |
| --- | --- |
| Missing/unreadable config | Check the single intended file, owner, private permissions and path outside Git; never paste it into chat |
| Wrong client type / invalid config | Re-download a Desktop/installed configuration; don't rename a Web/service-account JSON wrapper |
| Redirect incompatibility / `redirect_uri_mismatch` | Confirm Desktop type and current root-loopback strategy; don't register port 8000, switch to OOB, loosen URI checks or disable TLS |
| `access_denied` / user not allowed | Check Testing audience and dedicated test-user membership; refusal is not permission to retry automatically |
| `org_internal` | Account is outside the project's organization; review the correct audience/project with the administrator |
| `admin_policy_enforced` / blocked app | Obtain proper administrator/provider approval; do not disable account protection |
| Invalid/broader scope | Confirm only read-only in Data Access and runtime; review older grants on this dedicated project rather than broadening SUS.NOT |
| `invalid_grant` | Seven-day Testing expiry, revocation, password/security changes, code/PKCE failure or other provider restrictions can apply; stop and reauthorize only deliberately after diagnosis |
| Keychain unavailable / `-25308` | OS-owned Keychain Access may need unlocking/review; never enter passwords into Pi, command arguments or a plaintext fallback |
| Local request rejected / expired selections | Recheck session, reload metadata and explicitly select again; consumed investigations remain duplicate-blocked within that session |
| Ollama unavailable / model timeout | Result must remain partial/review; repair the local prerequisite before planning another explicit test |
| Unsupported/large MIME | Do not raise limits or fetch attachments just to pass; prepare one small attachment-free synthetic message |
| Revocation/deletion unconfirmed | Inspect both outcomes, retry local cleanup when available and use Google Account connection controls if necessary |

The terminal intentionally suppresses raw provider error bodies. Record only safe
status/error codes, operation stage and non-sensitive test IDs. Never enable body,
authorization-header, OAuth callback query or credential-config logging to troubleshoot.
If an investigation failed, do not bypass duplicate protection with hidden retries:
stop, disconnect and plan a fresh explicit test/session after correcting the problem.

## 6. Verification, files and remaining unknowns

Automated verification for this task:

```sh
.venv/bin/python -m pytest -q
node --test tests/guardian.test.cjs
```

The new tests cover valid/missing/invalid/private configs, Desktop shape, loopback
compatibility, scope drift, disabled guards, secret-free output, namespace isolation,
Keychain failure/cleanup, non-disruption of other sessions, explicit identity/evidence,
cached-report expiry and deletion readback. Google/Keychain/browser responses are
mocked in pytest; actual MCP SDK tests remain included. Native synthetic Keychain
readiness was run separately, not presented as a Google test.

Files created:

- `backend/gmail_readiness.py`: command-only local config/runtime/security/Keychain checks,
  safe JSON outcomes and exit codes; no authorization or network-provider requests.
- `tests/test_gmail_readiness.py`: synthetic validation and operator-view/cleanup tests.
- `docs/gmail-live-setup.md`: this official-source-backed operator guide and test plan.

Files modified:

- `backend/gmail_callback.py`: shared strict loopback validation and documented root callback.
- `backend/gmail_oauth.py`: declared redirect validation/reuse; exact URI/S256/state rules
  retained; remembered credential deletion now includes an absence readback.
- `backend/gmail_launcher.py`: shared redirect guard, explicit `identity` and consent-gated
  in-memory `evidence` views; cache tied to current authorization context and cleared on exit.
- `backend/gmail_routes.py`: protected explicit read-only `/gmail/account` profile action;
  no new scope or message operation.
- `tests/test_gmail_oauth.py`: synthetic callback fixture aligned to the root-loopback form.
- `docs/gmail-oauth.md`, `docs/gmail-local-verification.md`: link this current follow-up
  while retaining their historical implementation/test records.

Still unverified: real client registration, project/audience/API settings, provider
redirect/browser interoperability, token exchange/refresh/revocation with Google,
actual mailbox operation and provider-policy eligibility. Native testing covers one
Mac/user/interpreter and an isolated service, not production Keychain ACLs or code signing.
Readiness does not attest against modified Python, local malware, browser/OS tracing,
reverse proxies or public exposure of the legacy unauthenticated non-Gmail API.
Deduplication is session-local, no durable retry queue exists, and the terminal has no
saved-account restoration picker. No monitoring, new dependencies, remote AI inference,
Chrome Guardian behavior change, URL-score change or email-policy change is included.

## Official sources consulted

Public pages fetched and reviewed **2026-10-31** (no sign-in, credentials or OAuth
requests were used to consult them). Recheck current provider policy before a later test:

1. [Create a Google Cloud project](https://developers.google.com/workspace/guides/create-project)
2. [Gmail Python quickstart: API enablement and Desktop client setup](https://developers.google.com/workspace/gmail/api/quickstart/python)
3. [Configure OAuth consent and scopes](https://developers.google.com/workspace/guides/configure-oauth-consent)
4. [Create access credentials](https://developers.google.com/workspace/guides/create-credentials)
5. [Google Auth Platform setup](https://support.google.com/cloud/answer/15544987?hl=en)
6. [Manage App Audience: Internal/External, Testing, test users and expiry](https://support.google.com/cloud/answer/15549945?hl=en)
7. [Choose Gmail scopes: read-only, metadata and restricted-scope requirements](https://developers.google.com/workspace/gmail/api/auth/scopes)
8. [OAuth 2.0 for Desktop Apps: PKCE, loopback redirects and revocation](https://developers.google.com/identity/protocols/oauth2/native-app)
9. [OAuth overview: refresh-token expiration and limits](https://developers.google.com/identity/protocols/oauth2)
10. [Unverified apps: warnings, development builds and user caps](https://support.google.com/cloud/answer/7454865?hl=en)

**Stop after readiness and preparation. A later live Gmail authorization requires
separate explicit approval; Task 13.3C-1 does not perform or authorize it.**
