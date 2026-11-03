"""Offline comparison against explicitly protected registered domains."""

from urllib.parse import urlsplit

import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=())


def compare_domain(hostname: str, protected_domain: str) -> str:
    """Return trusted, potential_impersonation, or unrelated.

    'trusted' means domain ownership matches, not that a website is safe.
    """
    hostname = hostname.lower().rstrip(".")
    protected_domain = protected_domain.lower().rstrip(".")

    if not hostname or not protected_domain:
        return "unrelated"

    actual = _extractor(hostname).top_domain_under_public_suffix
    protected = _extractor(protected_domain).top_domain_under_public_suffix

    if not actual or not protected:
        return "unrelated"

    if actual == protected:
        return "trusted"

    # Only compare domain-label boundaries, never arbitrary substring matches.
    # E.g. login-university.ac.uk.example.com can be a misleading prefix.
    prefix = hostname[:-(len(actual) + 1)] if hostname.endswith("." + actual) else ""
    protected_labels = protected_domain.split(".")
    candidate_labels = prefix.split(".") if prefix else []
    for i in range(len(candidate_labels) - len(protected_labels) + 1):
        segment = candidate_labels[i:i + len(protected_labels)]
        if segment == protected_labels:
            return "potential_impersonation"
        # Allow an explicit login- prefix on the first protected label only.
        if (len(segment) == len(protected_labels)
                and segment[0] == "login-" + protected_labels[0]
                and segment[1:] == protected_labels[1:]):
            return "potential_impersonation"
    return "unrelated"
