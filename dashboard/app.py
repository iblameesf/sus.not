"""Run from the repository root: streamlit run dashboard/app.py."""

import sys
from pathlib import Path

# Streamlit executes this file as a script, not as a package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from dashboard.data import (
    DashboardClient, DataError, OLLAMA_MODEL, confusion_matrix,
    history_rows, load_benchmark, qwen_available,
)

st.set_page_config(page_title="SUS.NOT | Safety Guardian", page_icon="🛡️", layout="wide")


def findings(indicators):
    if not indicators:
        st.caption("No indicators reported. This does not establish safety.")
    for indicator in indicators:
        st.text(f"• {indicator}")


def risk_label(level):
    labels = {"low": "LOW · Caution", "review": "REVIEW · Verify first",
              "high": "HIGH · Warning", "critical": "CRITICAL · Strong warning"}
    if level == "low":
        st.info(labels[level])
    elif level == "review":
        st.warning(labels[level])
    else:
        st.error(labels[level])


def recording_option(client, key):
    try:
        enabled = client.history_status().enabled
    except DataError:
        st.caption("History status unavailable. This request will not be recorded by the dashboard.")
        return False
    if not enabled:
        st.caption("Local history recording is disabled on the backend.")
        return False
    return st.checkbox(
        "Save minimized metadata for this investigation", value=False, key=key,
        help="No raw text or full URL is saved. URL analysis saves one policy-evaluated record. This choice resets after submission.",
    )


def overview(client):
    st.header("Overview")
    st.caption("Live checks against local services · refresh to check again")
    st.button("Refresh status")
    left, right = st.columns(2)
    with left:
        try:
            client.health()
            st.success("FastAPI · Connected")
        except DataError as error:
            st.error("FastAPI · Unavailable or invalid health response")
            st.caption(str(error))
    with right:
        try:
            models = client.models()
            st.success("Ollama · Connected")
            if qwen_available(models):
                st.success("Qwen · Required model installed")
            else:
                st.warning("Qwen · Required model not listed")
            st.caption(OLLAMA_MODEL + " · availability is not an inference test")
        except DataError:
            st.warning("Ollama · Unavailable or invalid response")
            st.caption("Qwen availability unknown. Start Ollama and refresh.")
    st.divider()
    try:
        status = client.history_status()
        if not status.enabled:
            st.info("History recording is disabled. Investigations are not automatically retained.")
        else:
            st.info("History is enabled on the backend. Dashboard recording remains opt-in per investigation.")
            page = client.history(limit=1)
            st.metric("Locally stored investigations", page.total)
    except DataError as error:
        st.warning("History status/count unavailable. No count inferred.")
        st.caption(str(error))


def url_investigator(client):
    st.header("URL Investigator")
    st.caption("Deterministic URL inspection · URLs are parsed, not visited")
    with st.form("url_form", clear_on_submit=True):
        record = recording_option(client, "url_record")
        url = st.text_input("HTTP or HTTPS URL", placeholder="https://example.com")
        submitted = st.form_submit_button("Analyze URL", type="primary")
    if submitted:
        if not url.strip():
            st.warning("Enter an HTTP or HTTPS URL.")
            return
        try:
            with st.spinner("Inspecting URL locally…"):
                result = client.analyze_url(url)
            a, b = st.columns(2)
            a.metric("SUS Score", f"{result.sus_score}/100")
            with b:
                risk_label(result.risk_level)
            st.subheader("Detected indicators")
            findings(result.indicators)
            st.text(result.message)
            # Keep the heuristic result visible if policy evaluation is unavailable.
            try:
                decision = client.evaluate_url(url, record=record)
                st.subheader("Deterministic recommendation")
                st.text(decision.recommended_action.replace("_", " ").title())
                st.text(decision.explanation)
                st.caption(f"Decision Policy v{decision.policy_version}")
            except DataError as error:
                st.warning("Policy recommendation unavailable.")
                st.caption(str(error))
        except DataError as error:
            st.error(str(error))
        st.caption("If recording was requested, check History to confirm persistence; analysis success does not guarantee a saved record.")


def text_investigator(client):
    st.header("AI Text Investigator")
    st.info("Analysis uses local Qwen through Ollama. AI findings are not proof of fraud and may be wrong or incomplete.")
    st.caption("Text is not retained by default. History stores only minimized metadata, never submitted text or model prose.")
    with st.form("text_form", clear_on_submit=True):
        record = recording_option(client, "text_record")
        text = st.text_area("Message to investigate", height=200, max_chars=5000)
        submitted = st.form_submit_button("Analyze text", type="primary")
    if submitted:
        if not text.strip():
            st.warning("Enter a nonblank message (up to 5,000 characters).")
            return
        try:
            with st.spinner("Investigating with local Qwen…"):
                result = client.analyze_text(text, record=record)
            st.subheader("Indicators")
            findings(result.indicators)
            for label, value in (("Explanation", result.explanation),
                                 ("Recommendation", result.recommendation),
                                 ("Uncertainty", result.uncertainty)):
                st.subheader(label)
                # Plain text: untrusted model output never becomes active HTML/links.
                st.text(value)
            st.caption("If recording was requested, check History to confirm persistence.")
        except DataError as error:
            st.error(str(error))


def history(client):
    st.header("Investigation History")
    st.caption("Locally stored, privacy-minimized metadata only · newest first")
    try:
        if not client.history_status().enabled:
            st.info("History recording is disabled. Enable it explicitly on the backend to review stored metadata.")
            return
        size = st.selectbox("Records per page", [10, 20, 50, 100], index=1)
        page_number = st.number_input("Page", min_value=1, value=1, step=1)
        page = client.history(limit=size, offset=(page_number - 1) * size)
        st.caption(f"{page.total} stored investigations · page {page_number} of {max(1, (page.total + size - 1) // size)}")
        if not page.items:
            st.info("No investigations on this page." if page.total else "History is empty. No investigations have been saved.")
            return
        st.dataframe(history_rows(page), hide_index=True, width="stretch")
        identifier = st.selectbox("Investigation details", [str(item.investigation_id) for item in page.items])
        if st.button("Load details"):
            record = client.investigation(identifier)
            st.json(record.model_dump(mode="json"))
        st.caption("Text indicators are presence markers, not retained AI findings. Source evidence is omitted; exact replay is not possible.")
    except DataError as error:
        st.error(str(error))


def benchmarks():
    st.header("Benchmarks")
    st.warning("Synthetic cases only. These results do not establish real-world fraud accuracy.")
    try:
        benchmark = load_benchmark()
    except DataError as error:
        st.error(str(error))
        return
    left, right = st.columns(2)
    left.metric("Dataset size", benchmark.dataset_size)
    right.metric("Warning threshold (SUS Score ≥)", benchmark.warning_threshold)
    metrics = benchmark.metrics
    for columns, names in ((st.columns(4), ["true_positives", "true_negatives", "false_positives", "false_negatives"]),
                           (st.columns(4), ["precision", "recall", "f1_score", "accuracy"])):
        for column, name in zip(columns, names):
            value = getattr(metrics, name)
            column.metric(name.replace("_", " ").title(), f"{value:.2%}" if isinstance(value, float) else value)
    st.subheader("Confusion matrix")
    st.table(confusion_matrix(benchmark))
    st.caption("Positive class: suspicious. Rows = actual; columns = predicted. Saved artifact, not a live evaluation.")
    st.text(f"Evaluation version: {benchmark.evaluation_version}\nDataset SHA-256: {benchmark.dataset_sha256}")
    st.code(".venv/bin/python -m benchmarks.evaluate_urls", language="bash")


def evidence():
    st.header("Project Evidence")
    st.caption("Repository artifacts, not live integration or test claims")
    references = [
        ("MCP server", "docs/mcp-server.md"),
        ("Decision Policy v1", "docs/decision-policy.md"),
        ("Evaluation methodology", "docs/url-evaluation.md"),
        ("Local text investigator", "docs/text-investigator.md"),
        ("History privacy and schema", "docs/investigation-history.md"),
        ("Dashboard architecture and verification", "docs/dashboard.md"),
    ]
    if (ROOT / "backend/mcp_server.py").is_file():
        st.info("MCP implementation present: backend/mcp_server.py (stdio). Runtime status is not checked here.")
    else:
        st.warning("MCP implementation not found in this checkout.")
    for title, relative in references:
        path = ROOT / relative
        if path.is_file():
            with st.expander(f"{title} · {relative}"):
                st.code(path.read_text(encoding="utf-8"), language="markdown")
        else:
            st.caption(f"{title}: {relative} not available")
    evidence_path = ROOT / "EVIDENCE.md"
    if evidence_path.is_file() and evidence_path.stat().st_size:
        with st.expander("Existing evidence · EVIDENCE.md"):
            st.code(evidence_path.read_text(encoding="utf-8"), language="markdown")
    else:
        st.caption("EVIDENCE.md has no recorded evidence. Historical verification is documented in the task-specific docs; counts describe those runs only.")
    st.subheader("Reproduce locally")
    st.code(".venv/bin/python -m pytest -q\nnode --test tests/*.test.cjs\n.venv/bin/python -m benchmarks.evaluate_urls\n.venv/bin/python -m backend.mcp_server", language="bash")
    st.caption("Commands are references only. The dashboard does not execute tests or launch MCP.")


def main():
    st.title("SUS.NOT")
    st.write("Sus? Not on our watch.")
    with st.sidebar:
        st.subheader("Safety Guardian")
        section = st.radio("Workspace", ["Overview", "URL Investigator", "AI Text Investigator",
                                         "Investigation History", "Benchmarks", "Project Evidence"])
        st.caption("Local services only · no automatic collection")
        if st.button("Clear investigation session", help="Clears dashboard widget state and current results; not SQLite history."):
            st.session_state.clear()
            st.rerun()
    with DashboardClient() as client:
        if section == "Overview":
            overview(client)
        elif section == "URL Investigator":
            url_investigator(client)
        elif section == "AI Text Investigator":
            text_investigator(client)
        elif section == "Investigation History":
            history(client)
        elif section == "Benchmarks":
            benchmarks()
        else:
            evidence()
    st.divider()
    st.caption("Experimental safety assistance, not proof of fraud or a guarantee of safety.")


if __name__ == "__main__":
    main()
