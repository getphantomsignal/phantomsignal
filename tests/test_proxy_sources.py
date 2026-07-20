"""Tests for proxy-pool seeding — parser, normalizer, merge, and fetch."""
import httpx
import pytest

from phantomsignal.core import proxy_sources as P


# ── normalize ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,scheme,expected", [
    ("192.0.2.4:8080", "http", "http://192.0.2.4:8080"),
    ("192.0.2.4:1080", "socks5", "socks5://192.0.2.4:1080"),
    ("socks5://203.0.113.9:1080", "http", "socks5://203.0.113.9:1080"),   # explicit scheme wins
    ("user:pass@192.0.2.4:3128", "http", "http://user:pass@192.0.2.4:3128"),
    ("192.0.2.4:3128:user:pass", "http", "http://user:pass@192.0.2.4:3128"),
    ("  http://192.0.2.4:80  ", "http", "http://192.0.2.4:80"),
])
def test_normalize_valid(raw, scheme, expected):
    assert P.normalize_proxy(raw, scheme) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "# comment", "// note", "notaproxy", "192.0.2.4",
    "192.0.2.4:99999",            # port out of range
    "gopher://192.0.2.4:70",      # disallowed scheme
])
def test_normalize_invalid(raw):
    assert P.normalize_proxy(raw) is None


def test_parse_lines_dedups_and_limits():
    text = "\n".join(["192.0.2.4:8080", "192.0.2.4:8080", "# skip",
                      "198.51.100.8:3128", "bad line", "203.0.113.9:1080"])
    out = P.parse_proxy_lines(text, "http")
    assert out == ["http://192.0.2.4:8080", "http://198.51.100.8:3128", "http://203.0.113.9:1080"]
    assert P.parse_proxy_lines(text, "http", limit=1) == ["http://192.0.2.4:8080"]


def test_merge_pool_dedups_preserves_and_caps():
    existing = ["http://192.0.2.1:80"]
    additions = ["http://192.0.2.1:80", "http://198.51.100.2:80", "http://203.0.113.3:80"]
    assert P.merge_pool(existing, additions) == [
        "http://192.0.2.1:80", "http://198.51.100.2:80", "http://203.0.113.3:80"]
    assert P.merge_pool(existing, additions, cap=2) == [
        "http://192.0.2.1:80", "http://198.51.100.2:80"]


def test_is_fetchable_url():
    assert P.is_fetchable_url("https://x/y.txt")
    assert P.is_fetchable_url("http://x/y.txt")
    assert not P.is_fetchable_url("file:///etc/passwd")
    assert not P.is_fetchable_url("ftp://x/y")


def test_baked_in_sources_wellformed():
    assert P.PROXY_SOURCES
    for key, src in P.PROXY_SOURCES.items():
        assert P.is_fetchable_url(src["url"]), key
        assert src["scheme"] in ("http", "https", "socks4", "socks5")
        assert src["name"] and src["description"]


# ── fetch ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_parses_feed(monkeypatch):
    body = "192.0.2.4:8080\n198.51.100.8:3128\ngarbage\n"

    def handler(request):
        return httpx.Response(200, text=body)

    real_cls = httpx.AsyncClient

    def fake_client(*a, **k):
        return real_cls(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(P.httpx, "AsyncClient", fake_client)
    out = await P.fetch_proxy_source("https://feed/list.txt", "socks5")
    assert out == ["socks5://192.0.2.4:8080", "socks5://198.51.100.8:3128"]


@pytest.mark.asyncio
async def test_fetch_rejects_non_http():
    with pytest.raises(ValueError):
        await P.fetch_proxy_source("file:///etc/passwd", "http")
