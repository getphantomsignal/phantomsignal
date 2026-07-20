"""Tests for the OPSEC-native foundation (v1.25).

Covers the scraper module registry (F1), the per-scan attribution ledger and
its contextvar scope, the honest posture grading, and the StealthClient wiring
that records every egress into the active ledger.
"""
import asyncio

import httpx

from phantomsignal.core.http import (
    AttributionLedger, PROFILES, StealthClient, attribution_scope,
    _current_ledger,
)
from phantomsignal.intel.opsec import (
    OpsecLevel, build_attribution_result, worst_level,
)
from phantomsignal.scrapers.registry import get_registered_modules


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── F1: scraper module registry ─────────────────────────────────────────────

def test_registry_populated_and_opsec_tagged():
    mods = get_registered_modules()
    assert {"dns_recon", "intel", "web_crawl", "port_scan"} <= set(mods)
    # tags reflect real behaviour: stealth-routed vs raw-socket
    assert mods["takeover"].opsec is OpsecLevel.STEALTH_GUARANTEED
    assert mods["port_scan"].opsec is OpsecLevel.ATTRIBUTABLE
    for spec in mods.values():
        assert callable(spec.factory) and spec.label


# ── attribution ledger ──────────────────────────────────────────────────────

def test_ledger_summary_counts():
    led = AttributionLedger()
    led.record_request("a.com", "http://p:8080", "chrome124")
    led.record_request("b.com", None, None)
    led.record_block("cloudflare")
    led.record_backoff()
    s = led.summary()
    assert s["total_requests"] == 2
    assert s["proxied"] == 1 and s["direct"] == 1
    assert s["proxied_pct"] == 50.0
    assert s["impersonated"] == 1
    assert s["ja3_profiles"] == {"chrome124": 1}
    assert s["block_names"] == {"cloudflare": 1}
    assert s["backoffs"] == 1
    assert s["hosts_touched"] == 2


def test_attribution_scope_sets_and_resets():
    assert _current_ledger.get() is None
    with attribution_scope() as led:
        assert _current_ledger.get() is led
    assert _current_ledger.get() is None


def test_worst_level():
    assert worst_level(
        [OpsecLevel.STEALTH_GUARANTEED, OpsecLevel.ATTRIBUTABLE]
    ) is OpsecLevel.ATTRIBUTABLE
    assert worst_level([]) is None


# ── honest posture grading ──────────────────────────────────────────────────

def test_grade_exposed_when_any_attributable_module():
    r = build_attribution_result(
        AttributionLedger().summary(), {"dns_recon": "attributable"}
    )
    assert r["type"] == "attribution_surface"
    assert r["data"]["grade"] == "exposed"


def test_grade_masked_when_all_proxied_and_impersonated():
    led = AttributionLedger()
    for _ in range(5):
        led.record_request("x.com", "http://p", "chrome124")
    r = build_attribution_result(led.summary(), {"takeover": "stealth_guaranteed"})
    assert r["data"]["grade"] == "masked"


def test_grade_partial_when_half_proxied_no_impersonation():
    led = AttributionLedger()
    led.record_request("x.com", "http://p", None)
    led.record_request("x.com", None, None)
    r = build_attribution_result(led.summary(), {"js_mine": "stealth_guaranteed"})
    assert r["data"]["grade"] == "partial"


def test_attribution_result_carries_no_exposure_weight():
    r = build_attribution_result(AttributionLedger().summary(), {})
    assert r["relevance_score"] == 0.0


# ── StealthClient records egress into the active ledger ──────────────────────

def _client_with_mock(handler):
    client = StealthClient(profile=PROFILES["off"])
    # Inject a mock transport as the "direct" (proxy=None) egress client.
    client._clients[None] = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def test_stealth_client_records_direct_egress():
    client = _client_with_mock(lambda req: httpx.Response(200, text="ok"))

    async def go():
        with attribution_scope() as led:
            await client.get("http://target.test/")
            await client.get("http://target.test/2")
        await client.aclose()
        return led

    led = _run(go())
    s = led.summary()
    assert s["total_requests"] == 2
    assert s["direct"] == 2 and s["proxied"] == 0
    assert "target.test" in led.hosts


def test_stealth_client_records_waf_block():
    client = _client_with_mock(
        lambda req: httpx.Response(503, text="just a moment")
    )

    async def go():
        with attribution_scope() as led:
            await client.get("http://t.test/")
        await client.aclose()
        return led

    led = _run(go())
    s = led.summary()
    assert s["waf_blocks"] >= 1
    assert s["block_names"]


def test_stealth_client_without_scope_is_noop():
    client = _client_with_mock(lambda req: httpx.Response(200, text="ok"))

    async def go():
        # No attribution_scope active — must not raise.
        r = await client.get("http://target.test/")
        await client.aclose()
        return r

    assert _run(go()).status_code == 200


def test_stealth_stream_reads_body_and_records_egress():
    payload = b"PK\x03\x04 doc bytes"
    client = _client_with_mock(lambda req: httpx.Response(200, content=payload))

    async def go():
        with attribution_scope() as led:
            async with client.stream("GET", "http://target.test/x.docx") as resp:
                buf = b""
                async for chunk in resp.aiter_bytes():
                    buf += chunk
        await client.aclose()
        return led, buf

    led, buf = _run(go())
    assert buf == payload
    s = led.summary()
    # streamed download egressed, and is honestly recorded as non-impersonated
    assert s["total_requests"] == 1 and s["direct"] == 1
    assert s["impersonated"] == 0


def test_doc_metadata_download_routes_through_stealth():
    """The document-download phase must egress via StealthClient's stream path
    (proxy/identity/pacing) and record into the active scan ledger — not a raw
    scanner UA on a raw httpx client."""
    from phantomsignal.scrapers.doc_metadata import DocMetadataExtractor

    class _Cfg:
        def get(self, *a, **k):
            return k.get("default")

    doc_bytes = b"PK\x03\x04 pretend-docx bytes"
    ext = DocMetadataExtractor(_Cfg())
    ext.max_bytes = 10 * 1024 * 1024

    client = _client_with_mock(lambda req: httpx.Response(200, content=doc_bytes))

    async def go():
        with attribution_scope() as led:
            raw = await ext._fetch_capped(client, "http://target.test/a.docx")
        await client.aclose()
        return led, raw

    led, raw = _run(go())
    assert raw == doc_bytes                      # streamed body reassembled
    assert led.summary()["total_requests"] == 1  # egress recorded in the scan


def test_doc_metadata_download_respects_size_cap():
    """The zip-bomb guard still fires on the stealth stream path."""
    from phantomsignal.scrapers.doc_metadata import DocMetadataExtractor

    class _Cfg:
        def get(self, *a, **k):
            return k.get("default")

    ext = DocMetadataExtractor(_Cfg())
    ext.max_bytes = 8
    client = _client_with_mock(lambda req: httpx.Response(200, content=b"x" * 64))

    async def go():
        raw = await ext._fetch_capped(client, "http://target.test/big.pdf")
        await client.aclose()
        return raw

    assert _run(go()) is None    # oversized → skipped, not truncated
