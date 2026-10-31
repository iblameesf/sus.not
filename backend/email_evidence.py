"""Email evidence provenance and advisory policy v1; no IO or model instructions."""

from typing import Literal

from pydantic import BaseModel

from backend.email_parser import ParsedEmail

EMAIL_POLICY_VERSION = "email-1"


class Evidence(BaseModel):
    evidence_id: str
    evidence_type: str
    source_component: Literal["email_metadata", "email_parser", "inspect_url", "inspect_text"]
    finding: str
    severity: Literal["info", "low", "medium", "high"]
    supporting_reference: str
    limitations: list[str]


class Correlation(BaseModel):
    rule_id: str
    evidence_ids: list[str]
    finding: str
    limitations: str = "Co-occurrence is not proof of fraud or common ownership."


class EmailAdvisory(BaseModel):
    policy_version: Literal["email-1"] = EMAIL_POLICY_VERSION
    action: Literal["continue_with_caution", "review_before_proceeding", "show_warning"]
    reasons: list[str]
    evidence_ids: list[str]
    advisory: bool = True
    dismissible: bool = True
    explanation: str = (
        "Advisory only: independently verify via known official channels. "
        "No email is deleted, blocked, reported, or modified. No email fraud score is computed."
    )


METADATA_FINDINGS = {
    "missing_sender": "Sender address is missing; attribution is limited.",
    "reply_domain_mismatch": "Sender and Reply-To use different full domain names.",
    "display_address_mismatch": "An email address in the display name uses a different domain from the sender address.",
    "link_destination_mismatch": "A link displays a different HTTP(S) hostname from its actual destination.",
    "url_userinfo": "A URL contains user information before its destination host, which can obscure presentation.",
}
METADATA_LIMITATION = (
    "Headers and link labels are untrusted claims. Domain differences can be legitimate; "
    "they do not establish spoofing. SPF, DKIM, and DMARC were not verified."
)


def add_evidence(records: list[Evidence], *, evidence_type: str, source_component: str,
                 finding: str, severity: str, supporting_reference: str,
                 limitations: list[str]) -> Evidence:
    record = Evidence(
        evidence_id=f"ev-{len(records) + 1:03d}", evidence_type=evidence_type,
        source_component=source_component, finding=finding, severity=severity,
        supporting_reference=supporting_reference, limitations=limitations,
    )
    records.append(record)
    return record


def metadata_evidence(parsed: ParsedEmail) -> list[Evidence]:
    records = []
    for code, reference in parsed.indicators:
        add_evidence(
            records, evidence_type=code,
            source_component="email_parser" if code in {"link_destination_mismatch", "url_userinfo"} else "email_metadata",
            finding=METADATA_FINDINGS[code], severity="medium" if code != "missing_sender" else "low",
            supporting_reference=reference, limitations=[METADATA_LIMITATION],
        )
    return records


def url_evidence(records: list[Evidence], assessment, reference: str) -> None:
    """Shared production/benchmark evidence projection of an existing URL assessment."""
    for index, indicator in enumerate(assessment.indicators):
        add_evidence(records, evidence_type="url_indicator", source_component="inspect_url",
                     finding=indicator, severity="medium",
                     supporting_reference=f"{reference}.indicators[{index}]",
                     limitations=["Experimental URL heuristics are not fraud probabilities; the URL was not visited."])
    if assessment.decision.risk_level in {"high", "critical"}:
        add_evidence(records, evidence_type="url_high_risk", source_component="inspect_url",
                     finding="Existing URL Decision Policy v1 recommends a warning for this URL.",
                     severity="high", supporting_reference=f"{reference}.decision",
                     limitations=["This is a URL-level heuristic, not an email score or proof of fraud."])


def correlate(records: list[Evidence]) -> list[Correlation]:
    """Only typed source evidence participates; finding prose is never interpreted."""
    correlations = []
    groups = (
        ("sender_and_link_mismatch", {"reply_domain_mismatch", "display_address_mismatch"},
         {"link_destination_mismatch"}, "Sender identity discrepancy co-occurs with misleading link presentation."),
        ("url_and_content_concern", {"url_indicator"}, {"ai_content_indicator"},
         "URL heuristic indicators co-occur with unverified model content findings."),
    )
    for rule, left, right, finding in groups:
        a = [e.evidence_id for e in records if e.evidence_type in left]
        b = [e.evidence_id for e in records if e.evidence_type in right]
        if a and b:
            correlations.append(Correlation(rule_id=rule, evidence_ids=a + b, finding=finding))
    return correlations


def email_advisory(records: list[Evidence], correlations: list[Correlation], *, incomplete: bool) -> EmailAdvisory:
    """Explicit priority rules; AI cannot lower or dictate deterministic decisions."""
    high_urls = [e.evidence_id for e in records if e.evidence_type == "url_high_risk"]
    mismatches = [c for c in correlations if c.rule_id == "sender_and_link_mismatch"]
    if high_urls or mismatches:
        reasons = (["url_policy_warning"] if high_urls else []) + (["sender_and_link_mismatch"] if mismatches else [])
        return EmailAdvisory(action="show_warning", reasons=reasons,
                             evidence_ids=list(dict.fromkeys(high_urls + [ref for c in mismatches for ref in c.evidence_ids])))
    if records or incomplete:
        return EmailAdvisory(action="review_before_proceeding",
                             reasons=(["investigation_incomplete"] if incomplete else []) + (["evidence_requires_review"] if records else []),
                             evidence_ids=[e.evidence_id for e in records])
    return EmailAdvisory(action="continue_with_caution", reasons=["no_indicators_in_completed_checks"], evidence_ids=[])
