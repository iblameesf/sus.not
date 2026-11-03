# SUS.NOT — Architecture and Security Boundaries

## System context
SUS.NOT is a local-first, advisory cybersecurity system combining deterministic URL inspection, local text inference, email evidence analysis, a consent-based Chrome Guardian, an MCP server, and a Streamlit dashboard. It does not autonomously block websites.

## Logical architecture
```mermaid
flowchart LR
  U[User] --> E[Chrome MV3 Extension]
  E -->|Approved origin only; HTTP JSON| A[FastAPI localhost:8000]
  U --> D[Streamlit Dashboard localhost:8502 (configurable)]
  D --> A
  A --> R[Deterministic URL Rules and Decision Policy]
  A --> T[Local Text Investigator]
  T --> O[Local Ollama / Qwen]
  U --> C[Local MCP Client / Agent]
  C -->|stdio| M[MCP Server and Allowlisted Tools]
  A --> G[Email and Gmail Integration]
  A --> H[Opt-in Redacted History]
  H --> S[(Local SQLite Database)]
  R -->|Score and indicators| E
  E -->|Consent and threshold| W[Advisory Page Warning]
```

## Browser trust boundary
Chrome MV3 permission grants are a prerequisite to monitoring. OFF mode must not analyze or inject. SELECTED_WEBSITES requires exact approved origins and host permissions; ALL_WEBSITES requires explicit broad host permission. Automatic requests minimize full URLs to origins. Results are stored in session storage without the URL; URL fingerprints are SHA-256. The browser warning does not read page contents and is dismissible. Suppression, stale-response cancellation, and revocation behavior are covered by JavaScript tests; real-browser confirmation is separate.

## Backend trust boundary
FastAPI accepts URL input only after Pydantic validation. URL inspection parses strings and does not fetch the destination. Its heuristic score is not a probability of fraud. Local AI output is advisory. Email/Gmail data access requires explicit authorization and separate controls; automated tests and a successful live Gmail OAuth and investigation demonstration provide separate evidence of integration functionality. Opt-in history retains redacted metadata. Do not store access tokens or user messages in evidence artifacts.

## MCP and AI
`backend/mcp_server.py` implements MCP tools; the MCP server communicates over stdio with local clients, including the orchestration module. Runtime interoperability requires separate evidence. Local text inference uses Ollama; model availability is distinct from a successful inference call. Orchestration is constrained by application tool allowlisting.

## Detection limitations
The origin-only Guardian pipeline excludes paths and userinfo. The current deterministic URL rules cannot reach HIGH on normal origins. The optional, exact-loopback synthetic fixture described in `docs/step29-e2e-demo.md` tests warning integration only and is disabled by default. Hostname heuristics and domain impersonation prototypes are not production classifiers. The 32-case synthetic URL benchmark has limited recall and labels that depend on message context unavailable to URL-only analysis.

## Deployment and operational limits
This is a local prototype on macOS, not a production-grade phishing prevention service. It has no verified domain reputation feed, certificate intelligence, safe-browsing provider, or demonstrated generalization to unseen threats. Real-browser and live external-service tests require user-controlled environments and consent.
