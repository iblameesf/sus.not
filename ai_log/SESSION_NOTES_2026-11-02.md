# SUS.NOT — AI Development Session Notes

Date: 2026-11-02

## Project
SUS.NOT — Student Security Guardian

## AI tools
- ChatGPT: development guidance, debugging, verification planning,
  documentation and evaluation support.
- Local Qwen3.5-4B Q4_K_M: local AI investigation and tool-selection tests.

## Activities

### 1. Model-selected tool calling
A local Qwen execution selected the inspect_url tool.

Evidence:
- evidence/qwen-tool-call.json

### 2. MCP integration
A real MCP client initialized the local server, discovered its tools,
and invoked inspect_url.

Evidence:
- evidence/mcp-live-trace.json

### 3. Security verification
Targeted automated tests exercised existing security restrictions.

Result:
- 27 tests passed.

Evidence:
- evidence/blocks3-4-verification.json

### 4. Decision evaluation
The URL evaluation was executed against 32 synthetic scenarios.

Observed:
- TP: 4
- TN: 14
- FP: 2
- FN: 12

The results are not real-world phishing accuracy.

Evidence:
- benchmarks/results/url_evaluation.json

### 5. Persistence verification
A synthetic investigation was saved to SQLite and retrieved by
a separate Python process.

Result:
- PASS

Evidence:
- evidence/block5-persistence.json

### 6. Final regression verification
Python:
- 531 passed.

JavaScript:
- 14 passed.

Backend smoke:
- Passed.

### 7. Application verification
The developer reported successful live verification of:
- Streamlit dashboard.
- URL analysis.
- Chrome Guardian normal mode.
- Browser permission revocation.

### 8. AI assistance limitations
AI-generated suggestions were reviewed through actual execution
and automated tests.

The Block 9 repeated benchmark was interrupted and remains incomplete.

The SUS Score is an uncalibrated heuristic.

SQLite history persistence does not establish conversational LLM memory.

## Evidence integrity
These notes summarize the reported development session.
They are not verbatim AI conversation exports.
No unverified AI outputs are represented as executed results.
