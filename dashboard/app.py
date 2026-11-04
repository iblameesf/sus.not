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
    history_rows, load_benchmark, load_benchmark_version, threshold_sweep, qwen_available,
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
    st.header("Benchmarks · Offline URL heuristic")
    st.warning("Synthetic, constructed scenarios only. Not verified fraud, live detection, or real-world accuracy. The URL scorer is unchanged across V1–V3.")
    st.caption("These are three datasets, not three model releases. V2 is deliberately easier and repetitive; V3 probes single-indicator and context-dependent blind spots.")

    titles = {"V1": "Original baseline · 32 cases", "V2": "Repetitive-pattern stress test · 100 cases", "V3": "Challenge set · 100 cases"}
    loaded = {}
    for version in titles:
        try:
            loaded[version] = load_benchmark_version(version)
        except DataError as error:
            st.error(str(error))
    if not loaded:
        return

    st.subheader("Side-by-side comparison")
    summary = []
    for version, (report, rows) in loaded.items():
        m = report.metrics
        summary.append({"Version": version, "Purpose": titles[version], "Cases": report.dataset_size,
                        "Accuracy": f"{m.accuracy:.2%}", "Precision": f"{m.precision:.2%}",
                        "Recall": f"{m.recall:.2%}", "F1": f"{m.f1_score:.2%}",
                        "TP": m.true_positives, "TN": m.true_negatives,
                        "FP": m.false_positives, "FN": m.false_negatives})
    st.dataframe(summary, hide_index=True, width="stretch")
    st.info("V2's 86% accuracy reflects its constructed pattern distribution, not a detector improvement. V3 includes suspicious scenarios requiring message context absent from URL-only scoring. Results are not directly comparable as performance progression.")

    version = st.selectbox("Inspect benchmark", list(loaded), format_func=lambda key: f"{key} — {titles[key]}")
    report, rows = loaded[version]
    st.subheader(f"{version} · Saved evaluation")
    st.caption("Read-only saved artifact · no network requests, model calls, or live evaluation")
    c1, c2, c3, c4 = st.columns(4)
    for column, label, value in zip((c1, c2, c3, c4),
                                    ("Cases", "Warning threshold", "False positives", "False negatives"),
                                    (report.dataset_size, report.warning_threshold,
                                     report.metrics.false_positives, report.metrics.false_negatives)):
        column.metric(label, value)
    st.subheader("Confusion matrix")
    st.table(confusion_matrix(report))
    st.caption("Positive class = suspicious. Rows are actual labels; columns are predictions. Review-band scores below 60 count as benign in this binary benchmark, not as permission to proceed.")
    st.subheader("Case-level evidence")
    outcome = st.selectbox("Filter cases", ["All", "FP", "FN", "TP", "TN"], key=f"outcome_{version}")
    filtered = [row for row in rows if outcome == "All" or row["outcome"].upper() == outcome]
    st.dataframe([{"ID": row["id"], "Actual": row["expected_label"],
                   "Predicted": row["predicted_label"], "Outcome": row["outcome"].upper(),
                   "Score": row["sus_score"], "URL": row["url"], "Rationale": row["rationale"],
                   "Indicators": "; ".join(row["indicators"])} for row in filtered],
                 hide_index=True, width="stretch")
    st.caption(f"Showing {len(filtered)} of {len(rows)} cases. Rationales describe constructed scenarios, not verified website behavior.")

    if version == "V3":
        st.subheader("Exploratory threshold analysis · V3")
        sweep = threshold_sweep(rows)
        st.dataframe([{**row, **{name: f"{row[name]:.2%}" for name in ("Accuracy", "Precision", "Recall", "F1")}} for row in sweep],
                     hide_index=True, width="stretch")
        st.caption("Thresholds are applied to the same saved V3 scores. This is exploratory tuning on V3, not an independent validation or a change to the deployed policy. Lower thresholds increase false alarms.")

    st.subheader("Reproduce and audit")
    st.code(f".venv/bin/python -m benchmarks.evaluate_urls --version {version[1:]}", language="bash")
    st.code(f"Dataset: benchmarks/url_cases_v{version[1:]}.json\nResult: benchmarks/results/url_evaluation_v{version[1:]}.json\nDataset SHA-256 (canonical validated JSON): {report.dataset_sha256}", language="text")
    st.caption("V1 remains compatible with the original default command: .venv/bin/python -m benchmarks.evaluate_urls. Documentation: docs/url-evaluation.md")


def evidence():
    from dashboard.evidence_page import evidence_page
    evidence_page()


def main():
    st.title("SUS.NOT")
    st.write("Sus? Not on our watch.")
    with st.sidebar:
        st.subheader("Safety Guardian")
        section = st.radio("Workspace", ["Overview", "URL Investigator", "AI Text Investigator",
                                         "Investigation History", "Benchmarks", "Project Evidence",
                                         "Gmail Security"])
        st.caption("Local services only · no automatic collection")
        if st.button("Clear investigation session", help="Clears dashboard widget state and current results; not SQLite history."):
            gmail_bridge = st.session_state.get("gmail_bridge")

            if gmail_bridge is not None:
                try:
                    gmail_bridge.close()
                except Exception:
                    st.error(
                        "Gmail session cleanup failed. "
                        "Restart the local dashboard before reconnecting."
                    )
                    st.stop()

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
        elif section == "Gmail Security":
            from dashboard.gmail_page import gmail_security
            gmail_security()
        else:
            evidence()
    st.divider()
    st.caption("Experimental safety assistance, not proof of fraud or a guarantee of safety.")


if __name__ == "__main__":
    main()
