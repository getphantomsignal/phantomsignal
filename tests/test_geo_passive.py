"""Free / passive Geo Recon tests (InternetDB + RIPEstat + geoIP), no network."""
import asyncio

from phantomsignal.intel.geo import geo_recon, passive


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_parse_asn():
    assert passive.parse_asn("AS13335") == 13335
    assert passive.parse_asn("13335") == 13335
    assert passive.parse_asn("as 42 ") is None or passive.parse_asn("as42") == 42
    assert passive.parse_asn("notanasn") is None


def test_cpe_product():
    assert passive.cpe_product(["cpe:/a:nginx:nginx:1.2"]) == "nginx"
    assert passive.cpe_product([]) == ""


def test_sample_ips_from_prefixes():
    ips = passive.sample_ips_from_prefixes(["104.18.0.0/24", "1.1.1.0/30", "bad", "2001:db8::/32"])
    assert "104.18.0.1" in ips           # first usable host
    assert "1.1.1.1" in ips
    assert all(":" not in ip for ip in ips)   # IPv6 skipped


def test_assets_from_expands_ports():
    idb = {"ports": [80, 443], "cpes": ["cpe:/a:nginx:nginx"], "vulns": ["CVE-1"],
           "hostnames": ["a.example.com"]}
    geo = {"city": "Denver", "country": "United States", "lat": 39.7, "lon": -104.9, "org": "Acme"}
    rows = passive.assets_from("1.2.3.4", idb, geo)
    assert {r["port"] for r in rows} == {80, 443}
    assert rows[0]["product"] == "nginx" and rows[0]["city"] == "Denver"
    assert rows[0]["vulns"] == ["CVE-1"] and rows[0]["lat"] == 39.7


def test_place_matches():
    g = {"city": "South Brisbane", "country": "Australia", "cc": "AU"}
    assert passive.place_matches(g, "brisbane", None)
    assert passive.place_matches(g, None, "AU")
    assert passive.place_matches(g, None, "australia")
    assert not passive.place_matches(g, "denver", None)
    assert not passive.place_matches(None, "x", None)


def test_recon_passive_end_to_end(monkeypatch):
    # Stub the three network primitives; drive the full orchestration.
    async def _prefixes(client, asn):
        return ["104.18.0.0/24", "203.0.113.0/24"]

    async def _geoip(client, ips):
        return {
            "104.18.0.1": {"city": "Denver", "country": "United States", "cc": "US",
                           "lat": 39.7, "lon": -104.9, "org": "Acme"},
            "203.0.113.1": {"city": "Reno", "country": "United States", "cc": "US",
                            "lat": 39.5, "lon": -119.8, "org": "Beta"},
        }

    async def _idb(client, ip):
        if ip == "104.18.0.1":
            return {"ports": [443], "cpes": ["cpe:/a:nginx:nginx"], "vulns": ["CVE-9"], "hostnames": []}
        return {"ports": [22], "cpes": [], "vulns": [], "hostnames": []}

    monkeypatch.setattr(passive, "asn_prefixes", _prefixes)
    monkeypatch.setattr(passive, "geoip_batch", _geoip)
    monkeypatch.setattr(passive, "internetdb", _idb)

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    import phantomsignal.core.http as http_mod
    monkeypatch.setattr(http_mod, "stealth_client", lambda *a, **k: _Client())

    # No filter → both hosts.
    res = _run(geo_recon.GeoReconEngine(None).recon_passive(asn=13335))
    assert res["mode"] == "free" and res["configured"] is True
    assert res["summary"]["hosts"] == 2
    assert res["assets"][0]["ip"] == "104.18.0.1"          # vulnerable first

    # City filter → only Denver.
    res2 = _run(geo_recon.GeoReconEngine(None).recon_passive(asn=13335, city="Denver"))
    assert res2["summary"]["hosts"] == 1
    assert res2["assets"][0]["city"] == "Denver"
