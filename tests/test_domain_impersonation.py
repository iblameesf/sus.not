import pytest

from backend.domain_impersonation import compare_domain


@pytest.mark.parametrize(
    "hostname, protected, expected",
    [
        ("university.ac.uk", "university.ac.uk", "trusted"),
        ("portal.university.ac.uk", "university.ac.uk", "trusted"),
        ("university.ac.uk.example.com", "university.ac.uk", "potential_impersonation"),
        ("login-university.ac.uk.example.com", "university.ac.uk", "potential_impersonation"),
        ("example.com", "university.ac.uk", "unrelated"),
        ("student-login.example.com", "university.ac.uk", "unrelated"),
        ("UNIVERSITY.AC.UK.", "university.ac.uk", "trusted"),
    ],
)
def test_domain_comparison(hostname, protected, expected):
    assert compare_domain(hostname, protected) == expected
