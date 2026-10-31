"""Bounded, network-free email/HTML parsing. Parsed source stays local and ephemeral."""

from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.errors import MessageError
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_EMAIL_BYTES = 128 * 1024
MAX_BODY_CHARS = 20000
MAX_PARTS = 30
MAX_DEPTH = 8
MAX_URLS = 10
MAX_CANDIDATES = 100
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.I)
URL_CANDIDATE_PATTERN = re.compile(r"\bhttps?:[^\s<>\"']*", re.I)
EMAIL_PATTERN = re.compile(r"[\w.+-]+@([\w.-]+\.[a-zA-Z]{2,})")


class EmailParseError(ValueError):
    def __init__(self, code="malformed_email", status=422):
        self.code, self.status = code, status
        super().__init__("Email is malformed or exceeds supported parsing limits.")


class StructuredEmail(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sender: str | None = Field(default=None, max_length=2048)
    reply_to: str | None = Field(default=None, max_length=2048)
    subject: str | None = Field(default=None, max_length=2048)
    date: str | None = Field(default=None, max_length=2048)
    message_id: str | None = Field(default=None, max_length=2048)
    text_body: str | None = Field(default=None, max_length=MAX_BODY_CHARS)
    html_body: str | None = Field(default=None, max_length=MAX_BODY_CHARS)

    @field_validator("sender", "reply_to", "subject", "date", "message_id")
    @classmethod
    def header_controls(cls, value):
        if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Header control characters are not permitted")
        return value


class EmailInvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    raw_email: str | None = Field(default=None, min_length=1, max_length=MAX_EMAIL_BYTES)
    email: StructuredEmail | None = None

    @model_validator(mode="after")
    def exactly_one(self):
        if (self.raw_email is None) == (self.email is None):
            raise ValueError("Provide either raw_email or email")
        return self


@dataclass
class ParsedURL:
    url_id: str
    value: str
    references: list[str] = field(default_factory=list)


@dataclass
class ParsedEmail:
    headers: dict[str, str]
    sender_domain: str | None
    reply_domain: str | None
    text: str
    urls: list[ParsedURL]
    # Fixed codes + structural references only, not raw submitted text.
    indicators: list[tuple[str, str]]
    errors: list[tuple[str, str]]
    metadata: dict


def host(value: str) -> str | None:
    try:
        name = urlsplit(value).hostname
        return name.encode("idna").decode("ascii").lower().rstrip(".") if name else None
    except (ValueError, UnicodeError):
        return None


class TextHTML(HTMLParser):
    """Collect text and HTTP candidates only; never render, resolve, or load assets."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.anchor = None
        self.suppressed = []
        self.elements = 0

    def handle_starttag(self, tag, attrs):
        self.elements += 1
        if self.elements > 2000:
            raise EmailParseError("html_limit", 413)
        if tag in {"script", "style", "head", "template", "noscript"}:
            self.suppressed.append(tag)
        if self.suppressed:
            return
        values = dict(attrs)
        if tag == "a":
            self.finish_anchor()
            self.anchor = [values.get("href", ""), []]
        for name in ("href", "src", "action"):
            value = values.get(name) or ""
            if value.lower().startswith(("http:", "https:")):
                if len(self.links) >= MAX_CANDIDATES:
                    raise EmailParseError("html_link_limit", 413)
                self.links.append((value, "", f"html.attribute[{len(self.links)}]"))
        self.text.append(" ")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.suppressed:
            if tag == self.suppressed[-1]:
                self.suppressed.pop()
            return
        if tag == "a":
            self.finish_anchor()
        self.text.append(" ")

    def handle_data(self, data):
        if not self.suppressed:
            self.text.append(data)
            if self.anchor is not None:
                self.anchor[1].append(data)

    def finish_anchor(self):
        if self.anchor is not None:
            destination, visible = self.anchor
            if destination.lower().startswith(("http:", "https:")):
                if len(self.links) >= MAX_CANDIDATES:
                    raise EmailParseError("html_link_limit", 413)
                self.links.append((destination, "".join(visible).strip(), f"html.anchor[{len(self.links)}]"))
            self.anchor = None


def address_domain(value: str | None, header: str) -> str | None:
    if not value:
        return None
    try:
        parsed = policy.default.header_factory(header, value)
        if parsed.defects or len(parsed.addresses) != 1:
            raise ValueError()
        address = parsed.addresses[0]
        if not address.username or not address.domain:
            raise ValueError()
        return address.domain.encode("idna").decode("ascii").lower().rstrip(".")
    except (ValueError, AttributeError, UnicodeError, IndexError, MessageError):
        raise EmailParseError("invalid_address_header") from None


def read_raw(raw: str | bytes) -> tuple[dict, list[str], list[str]]:
    raw_bytes = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    # Probe syntax without losing original MIME octets or guessing body charsets.
    probe = raw.decode("ascii", errors="surrogateescape") if isinstance(raw, bytes) else raw
    if len(raw_bytes) > MAX_EMAIL_BYTES:
        raise EmailParseError("email_size_limit", 413)
    if not probe.strip() or "\x00" in probe:
        raise EmailParseError()
    # Conservative preflight bounds MIME tree construction, before the stdlib parser.
    if len(re.findall(r"(?im)^content-type:", probe)) > MAX_PARTS:
        raise EmailParseError("mime_part_limit", 413)
    first = probe.splitlines()[0]
    looks_rfc = bool(re.match(r"^[!-9;-~]+:", first)) and not first.lower().startswith(("http:", "https:"))
    if not looks_rfc:
        # Header-looking malformed input must not silently become benign plain text.
        if re.match(r"(?i)^(from|reply-to|subject|date|message-id)\b", first):
            raise EmailParseError("invalid_headers")
        try:
            return {}, [raw.decode("utf-8") if isinstance(raw, bytes) else raw], []
        except UnicodeError:
            raise EmailParseError() from None
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        headers = {}
        for key in ("From", "Reply-To", "Subject", "Date", "Message-ID"):
            values = message.get_all(key, [])
            if len(values) > 1:
                raise EmailParseError("duplicate_headers")
            if values:
                headers[key] = str(values[0])
        texts, htmls = [], []
        count = 0

        def visit(part, depth):
            nonlocal count
            count += 1
            if count > MAX_PARTS or depth > MAX_DEPTH:
                raise EmailParseError("mime_limit", 413)
            items = list(part.raw_items())
            if len(items) > 50 or sum(len(k) + len(v) for k, v in items) > 16384:
                raise EmailParseError("header_limit", 413)
            if any(len(v) > 2048 for _, v in items):
                raise EmailParseError("header_limit", 413)
            for key, value in items:
                if any((ord(c) < 32 and c not in "\r\n\t") or ord(c) == 127 for c in value):
                    raise EmailParseError("invalid_headers")
                # Date/Message-ID are reported as partial metadata failures below.
                if key.lower() not in {"date", "message-id"}:
                    if any(header.defects for header in part.get_all(key, [])):
                        raise EmailParseError("invalid_headers")
            if part.defects:
                raise EmailParseError("mime_defect")
            if part.get_content_disposition() == "attachment" or part.get_filename():
                return
            if part.get_content_type() == "message/rfc822":
                return
            if part.is_multipart():
                for child in part.iter_parts():
                    visit(child, depth + 1)
            elif part.get_content_type() in {"text/plain", "text/html"}:
                content = part.get_content(errors="strict")
                if part.defects:
                    raise EmailParseError("mime_decode_error")
                (htmls if part.get_content_type() == "text/html" else texts).append(content)
        visit(message, 0)
        return headers, texts, htmls
    except EmailParseError:
        raise
    except (ValueError, LookupError, UnicodeError, RecursionError, TypeError, MessageError):
        raise EmailParseError() from None


def parse_email(request: EmailInvestigationRequest | bytes) -> ParsedEmail:
    if isinstance(request, bytes):
        headers, texts, htmls = read_raw(request)
    elif request.raw_email is not None:
        headers, texts, htmls = read_raw(request.raw_email)
    else:
        fields = request.email
        headers = {key: value for key, value in {
            "From": fields.sender, "Reply-To": fields.reply_to, "Subject": fields.subject,
            "Date": fields.date, "Message-ID": fields.message_id,
        }.items() if value}
        texts, htmls = [fields.text_body or ""], [fields.html_body or ""]
        if len(request.model_dump_json().encode()) > MAX_EMAIL_BYTES:
            raise EmailParseError("email_size_limit", 413)
    if sum(map(len, texts + htmls)) > MAX_BODY_CHARS:
        raise EmailParseError("body_limit", 413)
    sender = address_domain(headers.get("From"), "From")
    reply = address_domain(headers.get("Reply-To"), "Reply-To")
    indicators, errors = [], []
    if sender is None:
        indicators.append(("missing_sender", "metadata.sender"))
    if sender and reply and sender != reply:
        indicators.append(("reply_domain_mismatch", "metadata.reply_to"))
    if sender:
        name = policy.default.header_factory("From", headers["From"]).addresses[0].display_name
        domains = [match.group(1).lower().rstrip(".") for match in EMAIL_PATTERN.finditer(name)]
        if any(domain != sender for domain in domains):
            indicators.append(("display_address_mismatch", "metadata.sender.display_name"))
    date_valid = None
    if headers.get("Date"):
        try:
            parsedate_to_datetime(headers["Date"])
            date_valid = True
        except (ValueError, TypeError, OverflowError):
            date_valid = False
            errors.append(("invalid_date", "metadata.date"))
    if headers.get("Message-ID") and not re.fullmatch(r"<[^<>\s@]+@[^<>\s@]+>", headers["Message-ID"]):
        errors.append(("invalid_message_id", "metadata.message_id"))
    candidates = []
    for index, html in enumerate(htmls):
        converter = TextHTML()
        converter.feed(html)
        converter.close()
        converter.finish_anchor()
        texts.append(" ".join(converter.text))
        candidates.extend((value, visible, f"body.html[{index}].{ref}") for value, visible, ref in converter.links)
    text = "\n".join(dict.fromkeys(value.strip() for value in texts if value.strip()))
    if len(text) > MAX_BODY_CHARS:
        raise EmailParseError("body_limit", 413)
    if not text and not headers:
        raise EmailParseError("empty_email")
    # Subject links are evidence too; sender/header addresses are never URL destinations.
    content = headers.get("Subject", "") + "\n" + text
    for index, match in enumerate(URL_CANDIDATE_PATTERN.finditer(content)):
        if len(candidates) >= MAX_CANDIDATES:
            errors.append(("url_candidate_limit", "body.urls"))
            break
        candidates.append((match.group().rstrip(".,;!?)"), "", f"content.url[{index}]"))
    urls, seen = [], {}
    for value, visible, reference in candidates:
        try:
            from backend.main import AnalyzeURLRequest
            if len(value) > 2048:
                raise ValueError()
            AnalyzeURLRequest(url=value)
        except ValueError:
            if ("malformed_url", "body.urls") not in errors:
                errors.append(("malformed_url", "body.urls"))
            continue
        if value not in seen:
            if len(urls) >= MAX_URLS:
                if ("url_limit", "body.urls") not in errors:
                    errors.append(("url_limit", "body.urls"))
                continue
            item = ParsedURL(f"url-{len(urls) + 1}", value)
            urls.append(item)
            seen[value] = item
        item = seen[value]
        if reference not in item.references:
            item.references.append(reference)
        destination = urlsplit(value)
        if destination.username is not None:
            indicator = ("url_userinfo", item.url_id)
            if indicator not in indicators:
                indicators.append(indicator)
        visible_url = visible.strip()
        if re.fullmatch(r"[\w.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?", visible_url):
            visible_url = "https://" + visible_url
        if visible_url.lower().startswith(("http://", "https://")):
            presented = host(visible_url)
            if presented and presented != host(value):
                indicator = ("link_destination_mismatch", item.url_id)
                if indicator not in indicators:
                    indicators.append(indicator)
    metadata = {
        "sender_present": sender is not None, "reply_to_present": reply is not None,
        "sender_address": "[redacted]" if sender else None,
        "reply_to_address": "[redacted]" if reply else None,
        "display_name_present": bool(sender and policy.default.header_factory("From", headers["From"]).addresses[0].display_name),
        "subject_present": bool(headers.get("Subject")), "date_present": bool(headers.get("Date")),
        "date_valid": date_valid, "message_id_present": bool(headers.get("Message-ID")),
        "text_body_present": bool(text), "html_body_present": any(htmls),
    }
    return ParsedEmail(headers, sender, reply, text, urls, indicators, errors, metadata)
