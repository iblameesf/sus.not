"""Conservative redaction for the new email API; never a general secret detector."""

import re
from urllib.parse import unquote, urlsplit, parse_qsl

from backend.email_parser import URL_PATTERN, ParsedEmail

SECRET = re.compile(
    r"(?i)\b(?:password|passwd|pwd|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"token|secret|otp|verification[ -]?code|one[ -]?time[ -]?(?:code|password)|authorization)"
    r"\b(?:\s*[:=]\s*|\s+(?:is\s+)?)[\"']?([^\s\"'<>;&,]+)"
)
EMAIL = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]+@[\w.-]+")
TOKEN = re.compile(r"\b(?:eyJ[\w-]+\.[\w-]+\.[\w-]+|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{12,})\b")
PEM = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S)


class EmailRedactor:
    def __init__(self, parsed: ParsedEmail):
        source = "\n".join([*parsed.headers.values(), parsed.text, *(item.value for item in parsed.urls)])
        self.secrets = {match.group(1) for match in SECRET.finditer(source)}
        self.secrets.update(re.findall(r"(?i)\bBearer\s+(\S+)", source))
        self.secrets.update(re.findall(r"\b\d{4,}\b", source))
        # High-entropy-looking source tokens are withheld even without a known label.
        self.secrets.update(word for word in re.findall(r"[\w+/=-]{8,}", source)
                            if any(c.isdigit() for c in word) and any(c.isalpha() for c in word))
        for item in parsed.urls:
            parts = urlsplit(item.value)
            self.secrets.update(value for value in (parts.username, parts.password, parts.fragment) if value)
            self.secrets.update(value for _, value in parse_qsl(parts.query, keep_blank_values=False))
            self.secrets.update(value for value in parts.path.split("/") if len(value) >= 8)
        self.secrets |= {unquote(value) for value in self.secrets}
        self.secrets.discard("")
        self.literal_pattern = re.compile(
            "|".join(re.escape(value) for value in sorted(self.secrets, key=lambda value: (-len(value), value))), re.I,
        ) if self.secrets else None

    def scrub(self, text: str) -> str:
        text = PEM.sub("[private key redacted]", text)
        text = URL_PATTERN.sub("[URL redacted]", text)
        text = EMAIL.sub("[address redacted]", text)
        text = TOKEN.sub("[credential redacted]", text)
        text = SECRET.sub(lambda match: match.group().replace(match.group(1), "[redacted]"), text)
        text = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [redacted]", text)
        # A single pass avoids repeatedly expanding markers containing short secrets.
        # Longest alternatives first also catch values echoed without their labels.
        return self.literal_pattern.sub("[redacted]", text) if self.literal_pattern else text
