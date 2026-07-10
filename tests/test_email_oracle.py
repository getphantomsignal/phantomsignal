"""Tests for email-account discovery (Phase 4, email_oracle).

Hashing, validation, response classification, and Gravatar profile parsing are
pure and tested directly. run() is driven over an httpx MockTransport (no network)
against Gravatar's real avatar-existence + profile-JSON behaviour.
"""
import hashlib
from functools import partial

import httpx
import pytest

from phantomsignal.scrapers import email_oracle as eo
from phantomsignal.scrapers.email_oracle import (
    is_valid_email, email_md5, classify_oracle_response, parse_gravatar_profile,
    EmailOracle,
)


class _Cfg:
    def get(self, *a, **k):
        return k.get("default")


# ── pure helpers ────────────────────────────────────────────────────────────

def test_is_valid_email():
    assert is_valid_email("Jane.Doe@Example.com")
    assert not is_valid_email("nope")
    assert not is_valid_email("a@b")


def test_email_md5_normalises():
    assert email_md5(" Test@Example.COM ") == hashlib.md5(b"test@example.com").hexdigest()


def test_classify_oracle_response():
    rule = {"exists_status": 200, "not_exists_status": 404}
    assert classify_oracle_response(rule, 200, "") == "exists"
    assert classify_oracle_response(rule, 404, "") == "not_exists"
    assert classify_oracle_response(rule, 500, "") == "unknown"
    # marker-gated exists
    rule2 = {"exists_status": 200, "exists_string": "profile"}
    assert classify_oracle_response(rule2, 200, "has profile") == "exists"
    assert classify_oracle_response(rule2, 200, "nope") == "unknown"


_PROFILE = {"entry": [{
    "displayName": "Beau Lebens", "preferredUsername": "beau",
    "company": "Automattic", "job_title": "Engineer", "currentLocation": "US",
    "accounts": [
        {"shortname": "twitter", "username": "beau"},
        {"shortname": "github", "username": "beaulebens"},
        {"name": "NoHandle"},                       # dropped: no username
    ],
}]}


def test_parse_gravatar_profile():
    p = parse_gravatar_profile(_PROFILE)
    assert p["display_name"] == "Beau Lebens"
    assert p["username"] == "beau"
    assert p["company"] == "Automattic"
    assert ("twitter", "beau") in p["accounts"]
    assert ("github", "beaulebens") in p["accounts"]
    assert len(p["accounts"]) == 2                   # NoHandle dropped
    assert parse_gravatar_profile({}) == {}


# ── end-to-end over a mock transport ────────────────────────────────────────

_EMAIL = "beau@dentedreality.com.au"
_MD5 = email_md5(_EMAIL)


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if "/avatar/" in path:
        # gravatar exists → 200 (d=404 would 404 for a miss)
        return httpx.Response(200, content=b"\x89PNG")
    if path.endswith(".json"):
        return httpx.Response(200, json=_PROFILE)
    return httpx.Response(404)


def _oracle(monkeypatch):
    transport = httpx.MockTransport(_handler)
    monkeypatch.setattr(eo.httpx, "AsyncClient",
                        partial(httpx.AsyncClient, transport=transport))
    return EmailOracle(_Cfg())


@pytest.mark.asyncio
async def test_run_finds_gravatar_and_linked_accounts(monkeypatch):
    oracle = _oracle(monkeypatch)
    results = await oracle.run(_EMAIL)
    assert any(r["type"] == "email_account" and r["data"]["service"] == "gravatar"
               for r in results)
    prof = next(r for r in results if r["type"] == "email_profile")
    assert prof["data"]["display_name"] == "Beau Lebens"
    linked = {(r["data"]["service"], r["data"]["handle"])
              for r in results if r["type"] == "email_linked_account"}
    assert ("twitter", "beau") in linked and ("github", "beaulebens") in linked
    summary = next(r for r in results if r["type"] == "email_oracle_summary")
    assert summary["data"]["registered_on"] == ["gravatar"]
    assert summary["data"]["linked_accounts"] == 2
    assert summary["is_anomaly"] is True


@pytest.mark.asyncio
async def test_run_rejects_non_email(monkeypatch):
    oracle = _oracle(monkeypatch)
    assert await oracle.run("not-an-email") == []
    assert await oracle.run("example.com") == []
