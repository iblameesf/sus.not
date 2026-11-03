"""Readable, advisory-only Gmail investigation reports."""

import streamlit as st


def render_reports(result, selected_messages):
    """Display reports using the original submitted selection order.

    references: tuple of opaque reference strings parallel to selected_messages.
    """

    if not isinstance(result, dict):
        st.error("Unexpected investigation response.")
        return

    reports = result.get("results", [])

    if not isinstance(reports, list):
        st.error("Investigation results are unavailable.")
        return

    st.subheader("Security Investigation Report")

    st.caption(
        "Experimental security assistance. Findings are advisory, "
        "not proof that an email is fraudulent or safe."
    )

    for position, item in enumerate(reports):
        if not isinstance(item, dict):
            continue

        # Backend selection_index is zero-based within the submitted
        # selection, not the original Gmail inbox index.
        selection_index = item.get("selection_index")

        if type(selection_index) is not int:
            st.warning("A result has no valid selection index.")
            continue

        if not 0 <= selection_index < len(selected_messages):
            st.warning("A result could not be matched to a selected email.")
            continue

        message = selected_messages[selection_index]

        if not isinstance(message, dict):
            message = {}

        subject = str(message.get("subject") or "(No subject)")
        sender = str(message.get("sender") or "Unknown sender")
        inbox_index = message.get("index", "?")

        status = str(item.get("status") or "unknown").lower()

        with st.container(border=True):
            st.markdown(f"### Email {inbox_index}: {subject}")
            st.text(f"From: {sender}")
            display_status = "UNVERIFIED" if status == "failed" else status.upper()
            st.markdown(f"**Investigation status:** {display_status}")

            if status == "partial":
                st.warning(
                    "Partial investigation: some email content or security "
                    "checks could not be analyzed. This result does not "
                    "establish that the email is safe."
                )

            if status == "failed":
                error = item.get("error", "unknown_error")

                explanations = {
                    "malformed_email":
                        "The email could not be parsed reliably.",
                    "body_limit":
                        "The email exceeded the permitted analysis size.",
                }

                st.error(
                    "Unable to verify this email. "
                    + explanations.get(
                        error,
                        "The investigation could not be completed."
                    )
                    + " This does not establish that the email is safe or malicious."
                )
                st.warning(
                    "Verify important requests independently through the "
                    "organization's official website or application. "
                    "Do not rely on links or contact details in an "
                    "unverified email."
                )

                st.caption(
                    f"Technical error: {error}. "
                    "No security conclusion was reached."
                )
                continue

            report = item.get("report")

            if not isinstance(report, dict):
                st.warning("No detailed investigation report available.")
                continue

            advisory = report.get("recommended_advisory_action") or {}

            if isinstance(advisory, dict):
                action = advisory.get(
                    "action",
                    "review_before_proceeding",
                )

                st.markdown("#### Recommended action")
                st.info(str(action).replace("_", " ").capitalize())

                explanation = advisory.get("explanation")

                if explanation:
                    st.write(str(explanation))

            ai = report.get("ai_text_assessment") or {}

            if isinstance(ai, dict) and ai:
                st.markdown("#### AI content assessment")
                st.warning(
                    "AI-generated claims are withheld because they have not "
                    "been independently verified. An AI model may incorrectly "
                    "identify legitimate notifications as phishing attempts."
                )
                st.info(
                    "Insufficient verified evidence to establish malicious "
                    "intent or impersonation from AI-generated text alone. "
                    "Review the independent security evidence and URL "
                    "assessments below."
                )

            evidence = report.get("evidence") or []

            st.markdown("#### Evidence")
            st.write(f"{len(evidence)} evidence item(s) reported.")

            for entry in evidence:
                if not isinstance(entry, dict):
                    continue

                finding = entry.get("finding", "Unspecified finding")
                severity = entry.get("severity", "unknown")

                with st.expander(
                    f"{str(severity).upper()} — {finding}"
                ):
                    st.write(
                        "Source:",
                        entry.get("source_component", "unknown"),
                    )

                    for limitation in entry.get("limitations") or []:
                        st.caption(str(limitation))

            urls = report.get("url_assessments") or []

            if urls:
                st.markdown("#### URL assessments")

                for entry in urls:
                    if not isinstance(entry, dict):
                        continue

                    assessment = entry.get("assessment") or {}

                    st.write(
                        "Risk level:",
                        assessment.get("risk_level", "unknown"),
                    )

                    if assessment.get("explanation"):
                        st.caption(str(assessment["explanation"]))

            uncertainties = report.get("uncertainty") or []

            if uncertainties:
                with st.expander("Limitations and uncertainty"):
                    for uncertainty in uncertainties:
                        st.write(f"• {uncertainty}")
