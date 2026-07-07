"""Tests for subdomain-takeover detection (Phase 2)."""
from phantomsignal.scrapers.takeover import (
    match_service,
    body_indicates_takeover,
    classify,
    FINGERPRINT_DB,
)


def test_match_service_by_cname():
    gh = match_service("myproject.github.io")
    assert gh and gh["service"] == "GitHub Pages"
    heroku = match_service("old-app.herokudns.com.")
    assert heroku and heroku["service"] == "Heroku"
    azure = match_service("gone.trafficmanager.net")
    assert azure and azure["service"] == "Azure"
    assert match_service("www.example.com") is None
    assert match_service("") is None


def test_body_indicates_takeover():
    s3 = match_service("bucket.s3.amazonaws.com")
    assert body_indicates_takeover("<html>...NoSuchBucket...</html>", s3) is True
    assert body_indicates_takeover("normal site content", s3) is False
    # a provider with no body fingerprints (nxdomain-type) never matches on body
    azure = match_service("x.azurewebsites.net")
    assert body_indicates_takeover("anything", azure) is False


def test_classify_body_match_is_vulnerable():
    gh = match_service("x.github.io")
    v = classify(gh, body_match=True, target_nxdomain=False)
    assert v["verdict"] == "vulnerable" and v["severity"] == "high"


def test_classify_nxdomain_provider():
    azure = match_service("x.azurewebsites.net")
    # NXDOMAIN on an nxdomain-type provider → vulnerable
    v = classify(azure, body_match=False, target_nxdomain=True)
    assert v["verdict"] == "vulnerable"
    # target still resolves → no signal at all for a body-less provider
    assert classify(azure, body_match=False, target_nxdomain=False) is None


def test_classify_unconfirmed_candidate():
    gh = match_service("x.github.io")  # status vulnerable, no confirmation
    v = classify(gh, body_match=False, target_nxdomain=False)
    assert v["verdict"] == "candidate" and v["severity"] == "medium"


def test_classify_edge_service_no_false_positive():
    # Shopify is "edge": a bare CNAME with no confirmation should NOT be flagged
    shopify = match_service("shop.myshopify.com")
    assert shopify["status"] == "edge"
    assert classify(shopify, body_match=False, target_nxdomain=False) is None
    # but a real fingerprint still flags it
    assert classify(shopify, body_match=True, target_nxdomain=False)["verdict"] == "vulnerable"


def test_fingerprint_db_integrity():
    for entry in FINGERPRINT_DB:
        assert entry["cname"] and entry["service"]
        assert entry["status"] in ("vulnerable", "edge")
        # nxdomain-only providers may have empty fingerprints; others should have some
        if not entry.get("nxdomain"):
            assert entry["fingerprints"], f"{entry['service']} needs body fingerprints"
