"""Regression tests for bounded Gmail MIME fallback."""

from email.message import EmailMessage

import pytest

from backend.email_parser import EmailParseError, MAX_BODY_CHARS, parse_email


def make_email(text=None, html=None):
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.com"
    message["Subject"] = "Test notification"

    if text is not None:
        message.set_content(text)

    if html is not None:
        if text is None:
            message.set_content(html, subtype="html")
        else:
            message.add_alternative(html, subtype="html")

    return message.as_bytes()


def test_large_html_with_complete_plain_text_is_partial():
    raw = make_email(
        text="Complete notification text.",
        html="<html><body>" + "X" * (MAX_BODY_CHARS + 1) + "</body></html>",
    )

    parsed = parse_email(raw)

    assert "Complete notification text." in parsed.text
    assert ("html_omitted_body_limit", "body.html") in parsed.errors


def test_large_html_without_plain_text_fails_closed():
    raw = make_email(
        html="<html><body>" + "X" * (MAX_BODY_CHARS + 1) + "</body></html>",
    )

    with pytest.raises(EmailParseError) as error:
        parse_email(raw)

    assert error.value.code == "body_limit"


def test_oversized_plain_text_fails_closed():
    raw = make_email(text="A" * (MAX_BODY_CHARS + 1))

    with pytest.raises(EmailParseError) as error:
        parse_email(raw)

    assert error.value.code == "body_limit"
