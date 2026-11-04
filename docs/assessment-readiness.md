# SUS.NOT — Assessment Readiness Dashboard

The **Project Evidence** tab provides repository-linked evidence for selected blocks **1–5** and optional **9**, plus **R1–R4** readiness. It is read-only and does not run tests or MCP/model invocations.

## How evidence is presented

- **Availability** means the referenced file exists, not that its claims are current or independently verified.
- **Recorded evidence** (JSON, Markdown, logs) documents prior runs. `verify_block1.py`, `verify_block2.py`, and `verify_block9.py` validate recorded artifacts rather than rerunning the original live experiments.
- **Fresh verification** requires running the commands shown in Terminal. R1 clean-install reproducibility is not automatically proven by the dashboard.
- **R3 PDF:** `ai_log/AI LOG FILE FOR SUS NOT .pdf` is provided as a clickable PDF download in the R3 section. The evaluator should inspect the contents for authentic AI conversations; a PDF filename is not itself proof.
- **R4:** Explanatory documents support an oral defense but cannot demonstrate the student's comprehension automatically.

## R1–R4

- **R1:** `README.md`, `INSTALL_AND_RUN.md`, `requirements.txt` and run commands.
- **R2:** `evidence/final-python-tests.log`, `evidence/final-node-tests.log`, `evidence/final-smoke.log`; run tests again to verify current code.
- **R3:** `ai_log/AI LOG FILE FOR SUS NOT .pdf`, session notes, AI use template.
- **R4:** `docs/architecture-final.md`, `docs/requirements-audit.md`, `EVIDENCE.md`.

## Blocks

- **1:** Qwen model-selected tool; `scripts/verify_block1.py` validates recorded model/tool evidence.
- **2:** MCP server; `scripts/verify_block2.py` validates recorded MCP client/server evidence.
- **3:** Code-enforced restrictions; `scripts/verify_block3.py` executes targeted tests.
- **4:** Decision threshold and confusion matrix; `scripts/verify_block4.py` checks original V1, with V2/V3 separately explored in Benchmarks. Synthetic datasets are not real-world accuracy estimates.
- **5:** SQLite persistence and Qwen token-cost artifact; `scripts/verify_block5.py` tests restart persistence. Not proof of conversational model recall.
- **9 (optional):** Synthetic comparison with recorded latency and outcomes; `scripts/verify_block9.py` checks the saved experiment artifact.

## Privacy and safety

The dashboard reads only known local paths, offers downloads, and previews text/JSON. It never sends repository evidence to a remote service. PDF content is offered for download; the browser can open the downloaded file. There is no arbitrary path input or shell execution from the dashboard.
