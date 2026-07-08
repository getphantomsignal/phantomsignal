"""Tests for archive URL mining (Phase 2)."""
from phantomsignal.scrapers.archive_miner import (
    parse_wayback_cdx,
    parse_otx_urllist,
    parse_urlscan,
    host_of,
    in_scope,
    subdomains_from_urls,
    extract_params,
    classify_url,
    is_interesting,
)


def test_parse_wayback_cdx():
    payload = [
        ["original"],
        ["https://acme.com/a"],
        ["https://api.acme.com/b?x=1"],
    ]
    urls = parse_wayback_cdx(payload)
    assert urls == {"https://acme.com/a", "https://api.acme.com/b?x=1"}
    # header-only or malformed → empty
    assert parse_wayback_cdx([["original"]]) == set()
    assert parse_wayback_cdx("not json") == set()


def test_parse_otx_and_urlscan():
    otx = {"url_list": [{"url": "https://acme.com/x"}, {"url": "https://acme.com/y"}]}
    assert parse_otx_urllist(otx) == {"https://acme.com/x", "https://acme.com/y"}
    us = {"results": [{"page": {"url": "https://acme.com/z"}}, {"page": {}}]}
    assert parse_urlscan(us) == {"https://acme.com/z"}


def test_host_and_scope():
    assert host_of("https://api.acme.com:8443/x") == "api.acme.com"
    assert in_scope("https://api.acme.com/x", "acme.com") is True
    assert in_scope("https://acme.com/x", "acme.com") is True
    assert in_scope("https://evil.com/x", "acme.com") is False
    assert in_scope("https://notacme.com/x", "acme.com") is False   # suffix trap


def test_subdomains_from_urls():
    urls = ["https://acme.com/", "https://api.acme.com/x",
            "https://cdn.acme.com/y", "https://evil.com/z"]
    subs = subdomains_from_urls(urls, "acme.com")
    assert subs == {"acme.com", "api.acme.com", "cdn.acme.com"}
    assert "evil.com" not in subs


def test_extract_params():
    assert extract_params("https://acme.com/x?a=1&b=2&a=3") == {"a", "b"}
    assert extract_params("https://acme.com/x") == set()


def test_classify_url():
    assert "sensitive-file" in classify_url("https://acme.com/backup.sql")
    assert "sensitive-file" in classify_url("https://acme.com/.env")
    assert "sensitive-path" in classify_url("https://acme.com/admin/login")
    assert "parameterised" in classify_url("https://acme.com/search?q=x")
    assert classify_url("https://acme.com/about.html") == []
    assert is_interesting("https://acme.com/wp-config.php.bak") is True
    assert is_interesting("https://acme.com/index.html") is False
