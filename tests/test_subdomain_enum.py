"""Tests for passive subdomain enumeration (Phase 2)."""
from phantomsignal.scrapers.subdomain_enum import (
    normalize_host,
    merge_hosts,
    generate_permutations,
    parse_crtsh,
    parse_hackertarget,
    parse_alienvault,
    parse_anubis,
    is_wildcard_false_positive,
)


def test_normalize_host():
    assert normalize_host("API.Example.COM.") == "api.example.com"
    assert normalize_host("*.example.com") == "example.com"
    assert normalize_host("https://x.example.com/path") == "x.example.com"
    assert normalize_host("x.example.com:8443") == "x.example.com"
    assert normalize_host("not a host") is None
    assert normalize_host("") is None


def test_merge_hosts_scopes_to_domain():
    hosts = merge_hosts(
        "example.com",
        ["api.example.com", "EVIL.com", "*.cdn.example.com", "example.com", "junk"],
    )
    assert hosts == {"api.example.com", "cdn.example.com", "example.com"}
    # out-of-scope apex is dropped
    assert "evil.com" not in hosts


def test_generate_permutations():
    perms = generate_permutations("example.com", ["api.example.com"], words=["dev", "staging"])
    # base label 'api' permuted with words, plus the words themselves as bases
    assert "dev-api.example.com" in perms
    assert "api-staging.example.com" in perms
    assert "api1.example.com" in perms
    assert "dev.example.com" in perms          # wordlist itself becomes a base
    # everything is in-scope and validly formed
    assert all(h.endswith(".example.com") for h in perms)
    assert all(normalize_host(h) for h in perms)


def test_parse_crtsh_handles_multiline_san():
    payload = [
        {"name_value": "a.example.com\n*.b.example.com"},
        {"name_value": "c.example.com"},
    ]
    hosts = parse_crtsh(payload)
    assert hosts == {"a.example.com", "b.example.com", "c.example.com"}
    # also accepts a raw JSON string
    assert parse_crtsh('[{"name_value": "d.example.com"}]') == {"d.example.com"}


def test_parse_hackertarget_and_error():
    text = "a.example.com,1.2.3.4\nb.example.com,5.6.7.8"
    assert parse_hackertarget(text) == {"a.example.com", "b.example.com"}
    assert parse_hackertarget("error check your api") == set()


def test_parse_alienvault_and_anubis():
    av = {"passive_dns": [{"hostname": "a.example.com"}, {"hostname": "bad host"}]}
    assert parse_alienvault(av) == {"a.example.com"}
    assert parse_anubis(["x.example.com", "y.example.com"]) == {"x.example.com", "y.example.com"}


def test_wildcard_false_positive_logic():
    wc = {"1.2.3.4", "1.2.3.5"}
    # resolves only to wildcard IPs, no CNAME → false positive
    assert is_wildcard_false_positive(["1.2.3.4"], [], wc) is True
    # has a CNAME → real record, keep (takeover-relevant)
    assert is_wildcard_false_positive(["1.2.3.4"], ["x.herokuapp.com"], wc) is False
    # resolves to an IP outside the wildcard set → real
    assert is_wildcard_false_positive(["9.9.9.9"], [], wc) is False
    # no wildcard on the domain → never a false positive
    assert is_wildcard_false_positive(["1.2.3.4"], [], set()) is False
