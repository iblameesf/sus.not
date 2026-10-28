# Guardian Mode v1

Guardian Mode extends the existing popup and uses `guardian.js`, an MV3 service worker, for automatic analysis. It is **OFF by default**. Enable it in the popup to approve the current website via Chrome's optional permission request. If already enabled, use **Approve this website** to add another site. Approval does not analyze immediately: reload or navigate afterward. Disabling retains approvals for later use, but stops automatic requests and removes warnings. Manual **Analyze URL** remains independent.

Only completed top-level HTTP(S) navigation (including same-document URL updates) on approved origins is analyzed. Chrome-restricted pages cannot be monitored. Credential-bearing URLs are never submitted. Results at **60 or above** produce a dismissible, nonblocking in-page warning with indicators and a heuristic disclaimer. All automatic scores appear in the popup's **Latest automatic assessment** section, independently of the **Manual assessment** section. Lower scores do not interrupt the page. Warnings for the same URL are suppressed for five minutes, across tabs. The website may obscure/remove the warning; this is not a security boundary or blocking feature.

## Permissions and privacy

- `activeTab` (existing): user-initiated URL access for manual analysis and website approval in the popup.
- `storage`: two local settings (`guardianEnabled`, default false; `approvedOrigins`, default empty). Session-only state holds one current result/error per tab and a bounded, expiring warning-suppression map. Results are removed on navigation/tab close; disabling clears session results and suppression. No persistent URL history or analysis log.
- `scripting`: inserts/removes the warning UI on approved websites only, in Chrome's isolated world. It does not read page text, forms, passwords, cookies, or browsing history. It uses DOM creation and `textContent`, not HTML injection or remote scripts.
- Mandatory `http://127.0.0.1:8000/*` (existing): permits requests only to the local backend endpoint. All fetches use that fixed endpoint, omit credentials, reject redirects, and have a timeout. The backend only parses URLs; it does not visit them.
- Optional `http://*/*` and `https://*/*`: declare the schemes on which users may opt in; **not** a blanket permission request. Each approval requests just `scheme://hostname/*`, never all websites or wildcard subdomains. Chrome host permissions cover all paths and ports for that scheme/hostname; SUS.NOT separately checks the exact approved origin, including port. HTTP and HTTPS are distinct. This broad optional declaration is necessary to let the user choose arbitrary individual websites at runtime.
- No `tabs`, `webNavigation`, `history`, `cookies`, `notifications`, or blanket required website permission. `tabs.onUpdated` does not require the `tabs` permission; approved host access supplies the URL metadata needed for monitoring. No content scripts run on every page.

Use **Revoke monitoring** beside an approved origin to remove its setting and Chrome permission. If another approved origin shares the same scheme/hostname at a different port, Chrome's shared host permission stays until the last such approval is revoked. Chrome cannot remove a host grant also required by the manifest (the local backend); the exact-origin allowlist still stops monitoring. Revocation through Chrome's extension controls is also respected. If Chrome itself removes access while a warning is visible, reload the page to remove any UI that Chrome no longer lets the extension remove.

Disabling aborts pending automatic fetches and invalidates late responses. It cannot retract a URL request already sent. No automatic analysis or warnings occur while disabled. Manual analysis is still user-initiated and available. Scores are preliminary heuristics, never proof of malicious activity.

## Automated checks

From the repository root:

```sh
python3 -m json.tool extension/manifest.json > /dev/null
for file in extension/*.js; do node --check "$file"; done
node --test tests/guardian.test.cjs
.venv/bin/python -m pytest
```

The Node tests exercise the service worker and popup together with mocked Chrome APIs, including separate loading/URL/completion events, same-URL reload cancellation, stored score-70 assessments, live popup updates after manual analysis, warning-injection failures, default OFF, permission gating, exact-origin checks, threshold 59/60, suppression, disable/late-response handling, revocation, backend failure, and the manual popup flow. They do not demonstrate actual browser permission prompts, script injection, service-worker wakeup, or rendering.

## Manual Chrome testing (not performed by the coding agent)

1. Start the backend: `.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000`.
2. Start a benign local test website in another terminal: `python3 -m http.server 8765 --bind 127.0.0.1 --directory extension`. Open `http://localhost:8765/` (not the backend URL).
3. Load/reload `extension/` as an unpacked extension at `chrome://extensions`. Use a fresh install/profile for the default test; reloading an existing installation intentionally preserves settings.
4. Open the popup: confirm **OFF**, no approved websites, and no automatic backend POST on reload. Click **Analyze URL**: confirm score, indicators, and explanation still work while OFF.
5. Click **Enable Guardian for this website**. Confirm Chrome requests access only to `http://localhost/*`, not every site. Deny first: confirm OFF and no monitoring. Retry and approve: confirm ON and the exact origin in the list. (Chrome may skip a new prompt for a grant already held; the approval click is still explicit.)
6. Reload the test website and confirm the backend logs a POST. Its actual score is below 60: no warning, result visible under **Latest automatic assessment** in the popup without clicking Analyze URL. Navigate to another path on the same origin; confirm a fresh result. Open a harmless unapproved site, another port, and `http://127.0.0.1:8765/`: confirm no automatic POST. Approve a second site only through **Approve this website**.
7. For warning testing, use the temporary worker-only fixture below. Reload the approved test website: confirm a visible, dismissible, nonblocking warning with score 70, indicators, and preliminary heuristic language, plus 70 under **Latest automatic assessment**. Test a fixture score of 59 on a different path: no warning, popup shows 59. Restore 70, navigate to a new path, dismiss, and reload it within five minutes: no repeat warning. A different path should warn. After five minutes, the original URL may warn again.
8. While a warning is visible, turn Guardian OFF. Confirm the warning disappears; navigating/reloading approved and unapproved sites produces no further automatic POSTs/warnings. Manual analysis should still work. Also test disabling during a delayed backend response: its late result must not warn.
9. Re-enable, then **Revoke monitoring**. Confirm the origin disappears, Chrome access is removed (subject to shared/mandatory grants above), and reload no longer causes an automatic POST. Test revocation through Chrome's extension settings too.
10. Stop the backend. Approved-site navigation should not block the website or throw an uncaught UI error; the popup should report automatic analysis unavailable. Manual Analyze URL should report offline. Restart the backend and retry.
11. Close worker DevTools, repeat navigation after the service worker becomes inactive, and verify it wakes and reads the saved settings. Restart Chrome: ON/OFF and approved origins persist; temporary results and warning suppression do not.

### Temporary high-score fixture (testing only)

The unchanged current scorer cannot reach 60 for a credential-free URL; credential URLs are deliberately rejected by the extension. Do not weaken that guard or change scoring to test warnings.

For browser UI testing only, inspect the extension's **service worker** from `chrome://extensions`. Paste in its DevTools console:

```js
globalThis.guardianOriginalFetch = globalThis.fetch;
globalThis.fetch = async () => new Response(JSON.stringify({
  sus_score: 70,
  risk_level: "high",
  indicators: ["Local test fixture — not a real detection"],
  message: "Preliminary heuristic test only."
}), { status: 200, headers: { "Content-Type": "application/json" } });
```

Change 70 to 59 in the fixture to test a silent result; use 60 to test the exact warning boundary. Use distinct benign paths to avoid the five-minute suppression. This fixture does not send requests and affects only this worker, not manual popup analysis. Keep DevTools open during the fixture test; worker suspension may discard it. Restore normal operation with `globalThis.fetch = globalThis.guardianOriginalFetch`, then reload the extension (which also removes the fixture). Never ship this fixture in extension code. Check real backend POSTs before/after, not while the fixture is installed.
