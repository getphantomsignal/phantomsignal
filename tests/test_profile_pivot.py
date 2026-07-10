"""Tests for recursive profile pivoting (Phase 4, profile_pivot).

The identifier extractor is pure and tested directly. The engine is driven
end-to-end with a fake username enumerator + an httpx MockTransport (no network).
"""
from functools import partial

import httpx
import pytest

from phantomsignal.intel.people import profile_pivot as pp
from phantomsignal.intel.people.profile_pivot import (
    extract_profile_identifiers, ProfilePivotEngine,
)


class _Cfg:
    def get(self, *a, **k):
        return k.get("default")


# ── pure extractor ──────────────────────────────────────────────────────────

_PROFILE_HTML = """
<html><body>
  <p>Reach me at Jane.Doe@example.com — more at https://janedoe.dev/blog</p>
  <a href="https://github.com/janedoe">gh</a>
  <a href="https://twitter.com/jane_d">tw</a>
  <a href="https://twitter.com/home">nav</a>
  <a href="https://linkedin.com/in/jane-doe-123">li</a>
  <img src="https://gravatar.com/avatar/0123456789abcdef0123456789abcdef?s=80">
</body></html>
"""


def test_extract_handles_emails_domains_gravatar():
    ids = extract_profile_identifiers(_PROFILE_HTML, base_url="https://site.test/janedoe")
    assert ("github", "janedoe") in ids["handles"]
    assert ("twitter", "jane_d") in ids["handles"]
    assert ("linkedin", "jane-doe-123") in ids["handles"]
    # reserved nav path must not be taken as a handle
    assert ("twitter", "home") not in ids["handles"]
    assert "jane.doe@example.com" in ids["emails"]
    assert "janedoe.dev" in ids["domains"]
    assert "0123456789abcdef0123456789abcdef" in ids["gravatar_hashes"]


def test_extract_excludes_infra_and_self_domain():
    html = ('<a href="https://google.com/x">g</a>'
            '<a href="https://janedoe.dev/other">self</a>')
    ids = extract_profile_identifiers(html, base_url="https://janedoe.dev/profile")
    assert "google.com" not in ids["domains"]      # infra
    assert "janedoe.dev" not in ids["domains"]      # self domain excluded


def test_extract_empty():
    ids = extract_profile_identifiers("<html>nothing here</html>", "https://x.test/u")
    assert ids["handles"] == set() and ids["emails"] == set()


# ── engine end-to-end (mocked) ──────────────────────────────────────────────

class _FakeEnumerator:
    """Returns a fixed profile URL for the seed handle only."""
    def __init__(self, mapping):
        self.mapping = mapping

    async def run(self, handle):
        url = self.mapping.get(handle)
        if not url:
            return []
        return [{"type": "username_account",
                 "data": {"username": handle, "site": "Seed", "url": url}}]


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.host == "seed.test":
        return httpx.Response(200, text=_PROFILE_HTML)
    return httpx.Response(404)


def _engine(monkeypatch, max_depth=1):
    transport = httpx.MockTransport(_handler)
    monkeypatch.setattr(pp.httpx, "AsyncClient",
                        partial(httpx.AsyncClient, transport=transport))
    enum = _FakeEnumerator({"janedoe": "https://seed.test/janedoe"})
    eng = ProfilePivotEngine(_Cfg(), enumerator=enum)
    eng.max_depth = max_depth
    return eng


@pytest.mark.asyncio
async def test_run_discovers_linked_identities(monkeypatch):
    eng = _engine(monkeypatch, max_depth=1)
    results = await eng.run("janedoe")
    linked = {(r["data"].get("platform"), r["data"]["value"])
              for r in results if r["type"] == "linked_identity" and r["data"]["kind"] == "handle"}
    assert ("twitter", "jane_d") in linked
    assert ("linkedin", "jane-doe-123") in linked
    emails = {r["data"]["value"] for r in results
              if r["type"] == "linked_identity" and r["data"]["kind"] == "email"}
    assert "jane.doe@example.com" in emails
    summary = next(r for r in results if r["type"] == "profile_pivot_summary")
    assert summary["data"]["profiles_parsed"] == 1
    assert summary["data"]["linked_emails"] == 1


@pytest.mark.asyncio
async def test_run_skips_domain_and_invalid_targets(monkeypatch):
    eng = _engine(monkeypatch)
    assert await eng.run("example.com") == []
    assert await eng.run("has space") == []
    assert await eng.run("a@b.com") == []
