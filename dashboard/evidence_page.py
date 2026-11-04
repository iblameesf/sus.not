"""Read-only assessment evidence explorer; no subprocesses or external links."""
from __future__ import annotations

import json
from pathlib import Path
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]

BLOCKS = [
    ("1", "Model-selected custom tool", "Qwen selected inspect_url; recorded invocation arguments match.",
     ["scripts/qwen_tool_agent.py", "backend/mcp_server.py"],
     ["evidence/qwen-tool-call.json", "evidence/block1_evidence.json"],
     ".venv/bin/python scripts/verify_block1.py", "Recorded trace validation, not a new model invocation."),
    ("2", "MCP server and invocation", "stdio MCP server and recorded client/server tool execution.",
     ["backend/mcp_server.py", "scripts/capture_mcp_evidence.py"],
     ["evidence/mcp-live-trace.json", "evidence/block2_evidence.json"],
     ".venv/bin/python scripts/verify_block2.py", "Recorded trace validation; MCP not started by dashboard."),
    ("3", "Code-enforced restrictions", "Guardrails and adversarial tests for MCP and Guardian.",
     ["backend/mcp_server.py", "extension/guardian-core.js", "tests/test_mcp_server.py", "tests/test_guardian_demo_fixture.py"],
     ["evidence/blocks3-4-verification.json", "evidence/final-node-tests.log"],
     ".venv/bin/python scripts/verify_block3.py", "Fresh local tests must be rerun for current-state proof."),
    ("4", "Decision model and errors", "Threshold policy and synthetic URL evaluations, including V1/V2/V3.",
     ["backend/decision_policy.py", "benchmarks/evaluate_urls.py", "docs/url-evaluation.md"],
     ["benchmarks/results/url_evaluation.json", "benchmarks/results/url_evaluation_v1.json",
      "benchmarks/results/url_evaluation_v2.json", "benchmarks/results/url_evaluation_v3.json"],
     ".venv/bin/python scripts/verify_block4.py", "V1 is the original block verification; V2/V3 are distinct constructed datasets, not model upgrades."),
    ("5", "Persistence and token cost", "SQLite restart persistence and local Qwen prompt-token comparison.",
     ["backend/history.py", "scripts/verify_block5.py"],
     ["evidence/block5-persistence.json", "evidence/block5-token-cost.json"],
     ".venv/bin/python scripts/verify_block5.py", "Persisted metadata is not conversational model recall; token comparison is prompt overhead."),
    ("9", "Optional comparative evaluation", "Recorded Qwen-only vs Qwen+MCP synthetic task comparison.",
     ["scripts/final_benchmark.py", "scripts/verify_block9.py"],
     ["evidence/block9_comparison.json", "evidence/block9_report.md"],
     ".venv/bin/python scripts/verify_block9.py", "Optional extra block, not a substitute for the five selected blocks."),
]


def safe_path(relative: str) -> Path:
    """Resolve only known repository-relative evidence paths."""
    candidate = (ROOT / relative).resolve()
    if not candidate.is_relative_to(ROOT.resolve()):
        raise ValueError("Outside project root")
    return candidate


def file_card(relative: str, *, preview: bool = False, key_prefix: str = "file"):
    path = safe_path(relative)
    if not path.is_file():
        st.warning(f"Missing: {relative}")
        return False
    st.caption(f"Available in repository · `{relative}` · {path.stat().st_size:,} bytes")
    if path.suffix.lower() == ".pdf":
        st.download_button("Open / save PDF · " + path.name, data=path.read_bytes(),
                           file_name=path.name, mime="application/pdf", key=f"{key_prefix}_pdf_{relative}")
    else:
        st.download_button("Download · " + path.name, data=path.read_bytes(),
                           file_name=path.name, mime="application/json" if path.suffix == ".json" else "text/plain",
                           key=f"{key_prefix}_download_{relative}")
        if preview:
            with st.expander("View file · " + relative):
                try:
                    content = path.read_text(encoding="utf-8")
                    if path.suffix == ".json":
                        st.json(json.loads(content))
                    else:
                        st.code(content[:35000], language="markdown" if path.suffix == ".md" else "text")
                        if len(content) > 35000:
                            st.caption("Preview truncated; download the complete file.")
                except (UnicodeError, ValueError, OSError) as exc:
                    st.warning(f"Preview unavailable: {type(exc).__name__}")
    return True


def evidence_page():
    st.header("Project Evidence · Assessment Readiness")
    st.caption("SUS.NOT | Source-grounded artifacts · locally reproducible verification · no tests run automatically")
    st.info("A file existing is evidence availability, not proof of a current successful run. Verification scripts and logs are labeled separately. Blocks 1–5 are selected; Block 9 is optional.")

    st.subheader("Assessment overview")
    for cols, block in zip((st.columns(3) for _ in range(2)), (BLOCKS[:3], BLOCKS[3:])):
        for col, (number, title, _, sources, artifacts, command, _) in zip(cols, block):
            present = sum(safe_path(p).is_file() for p in sources + artifacts)
            total = len(sources) + len(artifacts)
            with col:
                st.metric(f"Block {number} · {title}", f"{present}/{total}", help="Files present / files referenced; not a grade or execution result")

    st.subheader("R1–R4 · Assessment readiness")
    requirements = [
        ("R1", "Reproducible setup and run", ["README.md", "INSTALL_AND_RUN.md", "requirements.txt"],
         "Follow README.md in a clean environment; start FastAPI, Ollama and Streamlit. Source instructions exist, but the dashboard does not prove a clean install."),
        ("R2", "Automated tests and verification", ["evidence/final-python-tests.log", "evidence/final-node-tests.log", "evidence/final-smoke.log"],
         "Saved logs show historical test runs. Re-run the test commands below for current-state verification."),
        ("R3", "Authentic AI use record", ["ai_log/AI LOG FILE FOR SUS NOT .pdf", "ai_log/SESSION_NOTES_2026-11-02.md", "ai_log/AI_USE_LOG_TEMPLATE.md"],
         "PDF is supplied in the repository as an AI log. Review its contents to verify that it meets the university requirement for authentic conversation exports; session notes and a template alone do not prove this."),
        ("R4", "Explain and defend implementation", ["docs/architecture-final.md", "docs/requirements-audit.md", "EVIDENCE.md"],
         "Architecture and evidence documents support a defense; ability to explain code is assessed by the professor, not by file presence."),
    ]
    for code, title, paths, caveat in requirements:
        present = sum(safe_path(p).is_file() for p in paths)
        with st.expander(f"{code} — {title} · {present}/{len(paths)} files available", expanded=(code == "R3")):
            st.caption(caveat)
            for p in paths:
                file_card(p, preview=p.endswith((".md", ".log")), key_prefix=f"requirement_{code}")

    st.subheader("Technical blocks · Source → Trace → Verification")
    selection = st.selectbox("Select assessment block", [b[0] for b in BLOCKS],
                             format_func=lambda n: next(f"Block {b[0]} — {b[1]}" for b in BLOCKS if b[0] == n))
    number, title, description, sources, artifacts, command, limitation = next(b for b in BLOCKS if b[0] == selection)
    st.markdown(f"#### Block {number} — {title}")
    st.write(description)
    st.caption("Limitation: " + limitation)
    a, b = st.columns(2)
    with a:
        st.markdown("**Implementation and tests**")
        for path in sources:
            file_card(path, preview=path.endswith(".md"), key_prefix=f"block_{number}_source")
    with b:
        st.markdown("**Recorded evidence**")
        for path in artifacts:
            file_card(path, preview=True, key_prefix=f"block_{number}_evidence")
    st.markdown("**Reproduce locally (repository root)**")
    st.code(command, language="bash")
    st.caption("Run in Terminal. The dashboard does not execute commands, alter evidence, or start the MCP server.")

    st.subheader("Reproduce R1 and R2 locally")
    st.code("""# R1: Follow the full setup in README.md; run in separate terminals:
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
.venv/bin/python -m streamlit run dashboard/app.py

# R2: Fresh automated checks
.venv/bin/python -m pytest -q
node --test tests/*.test.cjs
.venv/bin/python scripts/final_smoke.py

# Blocks 1–5 + optional 9: recorded evidence checks / targeted tests
.venv/bin/python scripts/verify_block1.py
.venv/bin/python scripts/verify_block2.py
.venv/bin/python scripts/verify_block3.py
.venv/bin/python scripts/verify_block4.py
.venv/bin/python scripts/verify_block5.py
.venv/bin/python scripts/verify_block9.py

# Versioned synthetic benchmarks
.venv/bin/python -m benchmarks.evaluate_urls --version 1
.venv/bin/python -m benchmarks.evaluate_urls --version 2
.venv/bin/python -m benchmarks.evaluate_urls --version 3""", language="bash")
    st.warning("Some commands overwrite generated result artifacts or require running services. Preserve original evidence before re-evaluating. Block 1/2/9 verifiers check recorded evidence, not a fresh live model or MCP call.")
    st.subheader("Source documents")
    for path in ("README.md", "EVIDENCE.md", "docs/requirements-audit.md", "docs/architecture-final.md", "docs/orchestration.md"):
        file_card(path, preview=True, key_prefix="source_documents")
