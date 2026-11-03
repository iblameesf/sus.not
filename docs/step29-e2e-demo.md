# Step 29 — Controlled End-to-End Guardian Demonstration

## Purpose and scope
Prove the actual browser-to-backend-to-warning UI path without asserting that hostname-only detection can reliably identify phishing. This is a **synthetic test**, not a live threat verdict. The default production algorithm is unchanged.

## Safety and privacy invariants
- `SUSNOT_DEMO_MODE` is absent by default. The fixture activates only when it equals `1`.
- Only the exact origin `http://127.0.0.1:8765` returns the synthetic score 70.
- Guardian sends only the origin; no path, query, fragment, or page content is transmitted.
- Browser permission must be granted by the user. The warning is advisory and dismissible.
- Do not enable ALL_WEBSITES for this demonstration; use SELECTED_WEBSITES.
- Never demonstrate this with real phishing domains, user accounts, or credentials.

## Mac demonstration — two terminals
From the project root, with the virtual environment active:

Terminal A (backend with explicit fixture):

```bash
SUSNOT_DEMO_MODE=1 python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Terminal B (synthetic webpage):

```bash
python -m http.server 8765 --bind 127.0.0.1
```

In Chrome, open `chrome://extensions`, reload the unpacked SUS.NOT extension, and visit `http://127.0.0.1:8765/`. In SUS.NOT popup select **SELECTED_WEBSITES**, explicitly approve this origin, and reload the tab. A banner should display **SUS Score 70 / 100** and **SYNTHETIC DEMO FIXTURE**. Dismiss it, disable Guardian, and confirm no new warnings occur. If Chrome restricts extension injection on this page, capture the error and mark the browser demo unverified; do not claim success.

## Automated validation
```bash
python -m pytest -q
node --test tests/guardian.test.cjs
```

## Completion evidence (fill after running on Mac)
- Date/time:
- Browser/extension version:
- Permission granted/revoked:
- Banner screenshot filename:
- Dismiss/disable behavior:
- Privacy verification (origin only):
- Full Python and JavaScript test results:
- Remaining issue(s):

## Known limitations
The production URL analyzer scores IP-address origins at 30 and ignores path and userinfo during automatic Guardian monitoring. As a result, the production origin-only pipeline cannot normally reach the warning threshold of 60. The controlled fixture proves UI integration only; it does **not** validate phishing-detection sensitivity. Synthetic benchmark results must not be presented as real-world accuracy. The experimental hostname-risk and domain-impersonation modules are not integrated into production.
