"""Tests for keyless username enumeration (Phase 4, username_enum).

The rule evaluator and URL templating are pure and tested directly. The class
`run()` is driven end-to-end over an httpx MockTransport (no network), including
the false-positive guard that must drop a catch-all site.
"""
from functools import partial

import httpx
import pytest

from phantomsignal.scrapers import username_enum as ue
from phantomsignal.scrapers.username_enum import (
    clean_username, is_valid_username, build_check_url, evaluate_site,
    UsernameEnumerator,
)


class _Cfg:
    def get(self, *a, **k):
        return k.get("default")


# ── pure helpers ────────────────────────────────────────────────────────────

def test_clean_username():
    assert clean_username("@alice") == "alice"
    assert clean_username("https://twitter.com/alice") == "alice"
    assert clean_username("u/bob") == "bob"
    assert clean_username("  carol/  ") == "carol"


def test_is_valid_username():
    assert is_valid_username("alice_01")
    assert is_valid_username("a.b-c")
    assert not is_valid_username("has space")
    assert not is_valid_username("with/slash")
    assert not is_valid_username("")


def test_build_check_url():
    rule = {"uri_check": "https://x.test/user/{account}/profile"}
    assert build_check_url(rule, "alice") == "https://x.test/user/alice/profile"


def test_evaluate_site_hit_and_miss():
    rule = {"e_code": 200, "e_string": "FOUND", "m_string": ""}
    assert evaluate_site(rule, 200, "... FOUND ...") is True
    assert evaluate_site(rule, 404, "... FOUND ...") is False      # wrong status
    assert evaluate_site(rule, 200, "... nope ...") is False       # marker absent


def test_evaluate_site_miss_string_overrides():
    rule = {"e_code": 200, "e_string": "profile", "m_string": "not found"}
    assert evaluate_site(rule, 200, "profile of alice") is True
    # e_string present but so is the miss marker → treated as a miss
    assert evaluate_site(rule, 200, "profile not found") is False


def test_evaluate_site_bad_rule():
    assert evaluate_site({"e_code": None}, 200, "x") is False


# ── end-to-end over a mock transport ────────────────────────────────────────

_SITES = [
    {"name": "SiteA", "cat": "social", "uri_check": "https://a.test/{account}",
     "e_code": 200, "e_string": "FOUND", "m_string": ""},
    {"name": "SiteB", "cat": "coding", "uri_check": "https://b.test/{account}",
     "e_code": 200, "e_string": "PROFILE", "m_string": ""},
    {"name": "CatchAll", "cat": "misc", "uri_check": "https://c.test/{account}",
     "e_code": 200, "e_string": "FOUND", "m_string": ""},
    {"name": "Miss", "cat": "misc", "uri_check": "https://d.test/{account}",
     "e_code": 200, "e_string": "NOPE", "m_string": ""},
]


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    has_alice = "alice" in request.url.path
    if host == "a.test":
        return httpx.Response(200, text="...FOUND...") if has_alice else httpx.Response(404)
    if host == "b.test":
        return httpx.Response(200, text="...PROFILE...") if has_alice else httpx.Response(404)
    if host == "c.test":                       # catch-all: matches ANY handle
        return httpx.Response(200, text="...FOUND...")
    return httpx.Response(200, text="...unrelated...")     # d.test: never the marker


def _enum_with_mock(monkeypatch, fp_check=True):
    transport = httpx.MockTransport(_handler)
    monkeypatch.setattr(ue.httpx, "AsyncClient",
                        partial(httpx.AsyncClient, transport=transport))
    enum = UsernameEnumerator(_Cfg())
    enum._sites = _SITES
    enum.fp_check = fp_check
    return enum


@pytest.mark.asyncio
async def test_run_finds_real_accounts_and_drops_catch_all(monkeypatch):
    enum = _enum_with_mock(monkeypatch, fp_check=True)
    results = await enum.run("alice")
    found = {r["data"]["site"] for r in results if r["type"] == "username_account"}
    assert found == {"SiteA", "SiteB"}                 # CatchAll dropped, Miss never hit
    summary = next(r for r in results if r["type"] == "username_enum_summary")
    assert summary["data"]["accounts_found"] == 2
    assert summary["data"]["by_category"] == {"social": 1, "coding": 1}
    assert summary["is_anomaly"] is False           # 2 hits is below the broad-exposure threshold


@pytest.mark.asyncio
async def test_run_without_fp_guard_keeps_catch_all(monkeypatch):
    enum = _enum_with_mock(monkeypatch, fp_check=False)
    results = await enum.run("alice")
    found = {r["data"]["site"] for r in results if r["type"] == "username_account"}
    assert found == {"SiteA", "SiteB", "CatchAll"}     # FP guard off → catch-all survives


@pytest.mark.asyncio
async def test_run_rejects_invalid_username(monkeypatch):
    enum = _enum_with_mock(monkeypatch)
    assert await enum.run("has space") == []


@pytest.mark.asyncio
async def test_run_skips_domain_and_email_targets(monkeypatch):
    # dotted/@-bearing targets are domains/emails, not handles → no probing
    enum = _enum_with_mock(monkeypatch)
    assert await enum.run("example.com") == []
    assert await enum.run("alice@example.com") == []
