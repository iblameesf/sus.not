"""Gmail Security page for the local SUS.NOT dashboard."""

import streamlit as st

from dashboard.gmail_bridge import GmailBridge
from dashboard.gmail_report import render_reports


def gmail_security():
    st.header("Gmail Security")
    st.caption("Read-only Gmail investigation · Explicit consent · Local AI analysis")

    st.info(
        "Google grants read-only mailbox access. SUS.NOT does not "
        "automatically scan your inbox. You choose which messages to investigate."
    )

    if "gmail_bridge" not in st.session_state:
        st.session_state.gmail_bridge = None

    bridge = st.session_state.gmail_bridge

    if bridge is None:
        consent = st.checkbox(
            "I understand that Google grants read-only mailbox access."
        )

        if st.button("Connect Gmail", disabled=not consent):
            from pathlib import Path

            config = Path.home() / ".config/sus-not/gmail-desktop.json"

            try:
                bridge = GmailBridge(str(config))
                st.session_state.gmail_bridge = bridge
                bridge.authorize(remember=False)
                st.success("Google authorization opened. Complete sign-in in your browser.")
            except Exception:
                st.error("Gmail connection could not be started.")
                if bridge is not None:
                    bridge.close()
                    st.session_state.gmail_bridge = None

        return

    try:
        status = bridge.status()
    except Exception:
        st.error("Gmail session unavailable. Disconnect and reconnect.")
        return

    st.subheader("Connection status")
    st.json(status)

    if st.button("Refresh Gmail status"):
        st.rerun()

    st.divider()

    st.subheader("Inbox")

    if st.button("Load messages"):
        try:
            messages_result = bridge.list_messages()
            st.session_state.gmail_messages = messages_result
            # Store references parallel to messages for Move to Spam.
            # References are stored inside the TrustedLauncher and will be available
            # until the next list_messages() or disconnect() call.
        except Exception:
            st.error("Unable to load Gmail messages.")

    messages = st.session_state.get("gmail_messages", [])

    if messages:
        options = list(range(1, len(messages) + 1))

        selected = st.multiselect(
            "Select up to five emails",
            options=options,
            max_selections=5,
        )

        for index, message in enumerate(messages, 1):
            if not isinstance(message, dict):
                continue

            sender = str(message.get("sender") or "Unknown sender")
            subject = str(message.get("subject") or "(No subject)")
            received = str(message.get("date") or "Unknown date")

            with st.container(border=True):
                st.markdown(f"**{index}. {subject}**")
                st.text(f"From: {sender}")
                st.text(f"Received: {received}")

        investigation_consent = st.checkbox(
            "I explicitly authorize SUS.NOT to fetch and locally "
            "analyze only the selected emails.",
            value=False,
            key="gmail_investigation_consent",
        )

        if st.button(
            "Investigate selected emails",
            disabled=not selected or not investigation_consent,
        ):
            try:
                # Capture references before investigate() clears them in the launcher.
                result = bridge.investigate(
                    selected,
                    record_history=False,
                )
                selected_messages = [
                    messages[index - 1]
                    for index in selected
                ]

                st.session_state.gmail_selected_messages = selected_messages
                st.session_state.gmail_results = result

                st.success(
                    "Investigation finished. Review the individual "
                    "results below, including any partial or failed analyses."
                )
            except Exception as exc:
                st.session_state.pop("gmail_results", None)
                st.error(
                    "Investigation could not be completed. "
                    "No safety conclusion should be inferred."
                )
                st.caption(
                    "Diagnostic exception type: "
                    + type(exc).__name__
                )
                if isinstance(exc, TimeoutError):
                    st.warning(
                        "The Gmail investigation timed out. "
                        "Try investigating one email."
                    )
                elif (
                    isinstance(exc, RuntimeError)
                    and "closed" in str(exc).lower()
                ):
                    st.warning(
                        "The Gmail bridge session expired. "
                        "Restart Streamlit and reconnect Gmail."
                    )
                else:
                    st.info(
                        "A Gmail investigation runtime error occurred. "
                        "No security conclusion was reached."
                    )

    results = st.session_state.get("gmail_results")

    if results:
        st.divider()

        selected_messages = st.session_state.get(
            "gmail_selected_messages",
            [],
        )

        render_reports(results, selected_messages)

    st.divider()

    if st.button("Disconnect Gmail"):
        try:
            bridge.disconnect()
            bridge.close()
            for key in (
                "gmail_bridge",
                "gmail_messages",
                "gmail_results",
                "gmail_selected_messages",
                "gmail_investigation_consent",
            ):
                st.session_state.pop(key, None)
            st.success("Gmail disconnected.")
            st.rerun()
        except Exception:
            st.error("Disconnect failed. Check the connection before retrying.")
