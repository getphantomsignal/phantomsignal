"""Tests for dark-web leak-exposure monitoring (Phase 4, darkweb).

Parsing, target-scoping, and secret masking are pure and tested against a real
ransomware.live v2 record shape. run() is driven over an httpx MockTransport.
"""
from functools import partial

import httpx
import pytest

from phantomsignal.scrapers import darkweb as dw
from phantomsignal.scrapers.darkweb import (
    mask_secret, extract_domain, registered_name,
    parse_ransomware_victims, victim_matches_target, DarkWebMonitor,
)


class _Cfg:
    def get(self, *a, **k):
        return k.get("default")


# ── guardrail: secret masking ───────────────────────────────────────────────

def test_mask_secret_never_leaks_plaintext():
    assert mask_secret("hunter2") == "[redacted:7]"
    assert "hunter" not in mask_secret("hunter2")
    assert mask_secret("") == ""


# ── domain helpers ──────────────────────────────────────────────────────────

def test_extract_domain_and_registered_name():
    assert extract_domain("https://mail.acme.co.uk/x") == "mail.acme.co.uk"
    assert extract_domain("not a domain") is None
    assert registered_name("mail.acme.com") == "acme"


# ── parsing + scoping ───────────────────────────────────────────────────────

_PAYLOAD = [
    {"victim": "Acme Corporation", "group": "LockBit", "domain": "acme.com",
     "attackdate": "2026-05-01T00:00:00+00:00", "discovered": "2026-05-02T00:00:00+00:00",
     "country": "US", "activity": "Manufacturing",
     "claim_url": "http://abc.onion/acme", "url": "https://www.ransomware.live/id/xyz",
     "infostealer": "yes"},
    {"victim": "Globex Inc", "group": "BlackCat", "domain": "globex.com",
     "attackdate": "2026-04-01T00:00:00+00:00", "discovered": "2026-04-02T00:00:00+00:00",
     "country": "DE", "activity": "Finance", "claim_url": "", "url": "", "infostealer": ""},
]


def test_parse_ransomware_victims():
    recs = parse_ransomware_victims(_PAYLOAD)
    assert len(recs) == 2
    assert recs[0]["victim"] == "Acme Corporation"
    assert recs[0]["infostealer"] is True
    assert recs[1]["infostealer"] is False
    assert parse_ransomware_victims({"not": "a list"}) == []


def test_victim_matches_target_scopes_to_domain():
    recs = parse_ransomware_victims(_PAYLOAD)
    # exact domain match → strong
    assert victim_matches_target(recs[0], "acme.com") == "domain"
    # a fuzzy hit that is NOT this target must be rejected
    assert victim_matches_target(recs[1], "acme.com") is None
    # name-only match when domain field empty
    name_rec = {"victim": "Acme Corporation", "domain": ""}
    assert victim_matches_target(name_rec, "acme.com") == "name"


def test_victim_matches_target_rejects_junk_html_names():
    # scraped-HTML fragment must not name-match even if it contains the brand
    junk = {"victim": "aria-label=Acme>", "domain": ""}
    assert victim_matches_target(junk, "acme.com") is None


# ── end-to-end (mocked) ─────────────────────────────────────────────────────

def _handler(request: httpx.Request) -> httpx.Response:
    # searchvictims/acme → both records; scoping must drop Globex
    return httpx.Response(200, json=_PAYLOAD)


def _monitor(monkeypatch):
    transport = httpx.MockTransport(_handler)
    monkeypatch.setattr(dw.httpx, "AsyncClient",
                        partial(httpx.AsyncClient, transport=transport))
    return DarkWebMonitor(_Cfg())


@pytest.mark.asyncio
async def test_run_reports_only_scoped_ransomware_hits(monkeypatch):
    mon = _monitor(monkeypatch)
    results = await mon.run("acme.com")
    hits = [r for r in results if r["type"] == "ransomware_exposure"]
    assert len(hits) == 1
    assert hits[0]["data"]["victim"] == "Acme Corporation"
    assert hits[0]["data"]["group"] == "LockBit"
    assert hits[0]["data"]["has_infostealer_data"] is True
    assert hits[0]["confidence"] == 0.95
    summary = next(r for r in results if r["type"] == "darkweb_summary")
    assert summary["data"]["ransomware_hits"] == 1
    assert summary["data"]["groups"] == ["LockBit"]
    assert summary["is_anomaly"] is True


@pytest.mark.asyncio
async def test_run_rejects_non_domain_target(monkeypatch):
    mon = _monitor(monkeypatch)
    assert await mon.run("just-a-handle") == []
