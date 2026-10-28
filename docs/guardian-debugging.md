# Guardian automatic-result debugging

## Findings and fixes

- **Navigation detection:** `guardian.js` registers `chrome.tabs.onUpdated` at the top level. The MV3 manifest points to that worker and its local `importScripts("guardian-core.js")` is allowed by the existing CSP. No new permissions are needed for this listener. Tests dispatch navigation events into the registered worker listener; actual Chrome delivery has not been tested here.
- **Origin policy:** `Guardian.origin()` uses `new URL(url).origin`, followed by an exact approved-origin comparison and `chrome.permissions.contains()`. `https://example.com` matches its paths and fragments, but not HTTP, `www.example.com`, or another port. Tests confirm those boundaries. Credentials are deliberately rejected. The backend accepting `http://user@192.0.2.1/verify` does not make that URL eligible for Guardian monitoring, and does not make `https://example.com` score 70. Do not navigate to the credential/IP URL to test this.
- **Confirmed popup problem:** the previous `manualStarted` flag permanently suppressed automatic rendering after any manual Analyze click in that popup session. Automatic and manual output also shared the same result elements. They now have separate labeled sections; automatic updates never depend on clicking Analyze and never overwrite manual output. The popup also refreshes its current URL if kept open through navigation, and ignores out-of-order settings responses. It explicitly explains OFF, unapproved, or no-assessment-yet states rather than silently displaying nothing.
- **Confirmed reload problem:** a reload can send `status: "loading"` without `change.url`. Previously that did not invalidate the old request/result, and completion could deduplicate against the old document's pending request. Loading now cancels it and clears its result; completion starts fresh work. Queued writes additionally verify the job is still current.
- **Confirmed result-loss problem:** warning injection errors reached the outer backend-error handler and replaced a valid stored assessment with an error. Injection failures now preserve the score and indicators, explain that the warning could not be displayed, and release suppression so the next navigation can retry.
- **Storage:** successful assessments remain in `chrome.storage.session.results[tabId]` as `{url, data}`. The worker returns only a result matching the popup's current tab and URL while Guardian is enabled. The popup reads it on opening and on session-storage changes. Only temporary per-tab results are retained; navigation, tab closure, or disabling clears them.

The backend/scoring rules, permission declarations, dependency list, approval requirement, warning threshold (60), and manual Analyze URL action are unchanged. Enabling still starts analysis on the **next navigation/reload**, not retroactively.

## Precise Chrome checks for the reported example.com case

These are manual instructions, not claims of browser testing.

1. Start the normal local FastAPI backend. At `chrome://extensions`, reload the unpacked SUS.NOT extension from this checkout. Inspect its **Errors** panel for startup, CSP, or import errors. Open `https://example.com/` (a benign test site), confirm Guardian ON and approval for exactly `https://example.com`.
2. Click the extension's **service worker** inspection link. In the worker console run:

   ```js
   await chrome.storage.local.get(["guardianEnabled", "approvedOrigins"])
   await chrome.permissions.contains({origins: ["https://example.com/*"]})
   ```

   Expect `guardianEnabled: true`, an array containing `https://example.com`, and `true` for permission. If the grant is missing, approve the site through the popup; do not broaden site access to all websites.
3. To observe real event delivery temporarily, run this in the **worker** console:

   ```js
   globalThis.guardianDebugNavigation = (id, change, tab) => {
     if (tab.url && new URL(tab.url).origin === "https://example.com") {
       console.log("Guardian navigation", id, change, tab.status);
     }
   };
   chrome.tabs.onUpdated.addListener(globalThis.guardianDebugNavigation);
   ```

   Reload example.com. Expect loading/completion events (URL updates need not appear on a same-URL reload), and a POST in the local backend log. If the worker does not start or events do not appear, record the extension's Errors panel and the exact site-access setting; mocked tests cannot establish Chrome's behavior on that installation.
4. In the worker console run `await chrome.storage.session.get("results")`. Locate the entry for the example.com tab: its URL must match the address bar and `data.sus_score` should match the backend. Open the popup **without clicking Analyze URL**: **Latest automatic assessment** should show that result. The normal example.com assessment is below 60, so no warning is expected. **Manual assessment** is separate and appears only after Analyze URL.
5. For a score-70 warning without visiting a suspicious site or modifying scoring, install the temporary worker-only fixture from [guardian-mode.md](guardian-mode.md#temporary-high-score-fixture-testing-only). It returns `sus_score: 70`. Keep worker DevTools open, navigate to `https://example.com/#guardian-test-70`, then reload if necessary. Expect a dismissible, nonblocking warning with score/indicators and heuristic language. Open the popup and confirm **Latest automatic assessment** shows 70. Dismiss and reload the same URL within five minutes: the assessment remains available but there should be no repeat warning.
6. Change the fixture score to 59 (risk level `"review"`) and navigate to `https://example.com/#guardian-test-59`. Expect no warning and automatic score 59. Use 60 with a fresh fragment to test the exact boundary. Distinct URLs avoid existing suppression; a previous warning is removed when its URL changes.
7. Click **Analyze URL**: this popup request uses the real backend, not the worker fixture. It should display its own result while the stored automatic fixture assessment remains visible. To test a live update in a popup kept open using popup DevTools, reload the same example.com URL with the worker fixture changed to 70: automatic output should update independently of the manual output.
8. Turn Guardian OFF, then reload and inspect session results: no new automatic assessment or warning should appear. Manual Analyze URL must still work. Re-enable and try `https://www.example.com` only if desired as a benign distinct origin, or use an unapproved local test site from the main guide: it must not create an automatic result. Do not approve additional sites just to bypass matching.
9. Restore the worker fetch with `globalThis.fetch = globalThis.guardianOriginalFetch`. Remove the temporary event observer with `chrome.tabs.onUpdated.removeListener(globalThis.guardianDebugNavigation)`, or simply reload the extension to remove both diagnostic modifications. With the real backend restored, repeat the below-60 automatic test and manual test.
10. Close worker DevTools, allow the worker to become inactive, then reload the approved site. Reopen the popup and check for the fresh assessment; inspecting the worker continuously prevents testing normal suspension/wakeup.

For a warning-injection failure test, in worker DevTools temporarily replace `chrome.scripting.executeScript` with an async function that throws, install the score-70 fetch fixture, and navigate to a fresh example.com fragment. The popup should still show 70 plus the warning-display error. Reload the extension immediately afterward to restore the real API. This is a fault-injection test only, not a production change.

## Automated checks

```sh
node --test tests/guardian.test.cjs
for file in extension/*.js; do node --check "$file"; done
.venv/bin/python -m json.tool extension/manifest.json > /dev/null
.venv/bin/python -m pytest
```

Regression tests include a mocked score-70 backend response flowing from separate navigation events through worker storage and the real popup scripts, below-threshold silence, unapproved/OFF filtering, manual/automatic separation, same-URL reloads, and injection-failure result retention. Chrome APIs, DOM nodes, and backend responses are mocked; these checks do not prove browser rendering or MV3 event delivery.
