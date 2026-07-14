"""Geo Recon (place → assets) tests — spec §1 / §13."""
import asyncio

from phantomsignal.intel.geo import geo_recon


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_build_query_variants():
    assert geo_recon.build_query(city="Denver", country="US") == 'city:"Denver" country:US'
    assert geo_recon.build_query(lat=39.7, lon=-104.9, radius_km=30) == 'geo:"39.7,-104.9,30"'
    # radius is capped at Shodan's 100 km limit
    assert '100' in geo_recon.build_query(lat=1, lon=2, radius_km=500)
    # coordinates win over city; org/domain scope appended
    q = geo_recon.build_query(city="Denver", org="Acme", domain="ex.com")
    assert 'city:"Denver"' in q and 'org:"Acme"' in q and 'hostname:"ex.com"' in q


def test_parse_latlon():
    assert geo_recon.parse_latlon("39.7392,-104.9903") == (39.7392, -104.9903)
    assert geo_recon.parse_latlon("not coords") is None
    assert geo_recon.parse_latlon(None) is None


def test_dedupe_and_sort_vulnerable_first():
    matches = [
        {"ip": "1.1.1.1", "port": 80, "vulns": []},
        {"ip": "1.1.1.1", "port": 80, "vulns": []},          # dup (ip, port)
        {"ip": "2.2.2.2", "port": 443, "vulns": ["CVE-2021-1"]},
    ]
    out = geo_recon.dedupe(matches)
    assert len(out) == 2                                      # dup removed
    assert out[0]["ip"] == "2.2.2.2"                          # vulnerable first


def test_summarize_counts():
    assets = [
        {"ip": "1.1.1.1", "port": 80, "org": "Acme", "product": "nginx", "country": "US", "vulns": []},
        {"ip": "1.1.1.1", "port": 22, "org": "Acme", "product": "OpenSSH", "country": "US", "vulns": ["CVE-1"]},
        {"ip": "2.2.2.2", "port": 80, "org": "Beta", "product": "nginx", "country": "US", "vulns": []},
    ]
    s = geo_recon.summarize(assets)
    assert s["assets"] == 3 and s["hosts"] == 2
    assert s["vuln_hosts"] == 1 and s["vulns"] == ["CVE-1"]
    assert ("nginx", 2) in s["products"]


def test_recon_without_key_degrades(monkeypatch):
    # ShodanAPI.geo_search reports not-configured; recon returns empty + configured=False.
    class _Shodan:
        def __init__(self, cfg):
            pass

        async def geo_search(self, q, **k):
            return {"total": 0, "matches": [], "configured": False}

    import phantomsignal.intel.apis.shodan_api as shodan_mod
    monkeypatch.setattr(shodan_mod, "ShodanAPI", _Shodan)
    res = _run(geo_recon.GeoReconEngine(None).recon(country="US", lat=39.7, lon=-104.9))
    assert res["configured"] is False and res["assets"] == []
    assert res["query"] == 'geo:"39.7,-104.9,25"'


def test_recon_maps_and_summarizes_matches(monkeypatch):
    class _Shodan:
        def __init__(self, cfg):
            pass

        async def geo_search(self, q, **k):
            return {"total": 2, "configured": True, "matches": [
                {"ip": "1.1.1.1", "port": 443, "product": "nginx", "org": "Acme",
                 "lat": 39.7, "lon": -104.9, "vulns": ["CVE-1"], "country": "US"},
                {"ip": "2.2.2.2", "port": 22, "product": "OpenSSH", "org": "Beta",
                 "lat": 39.8, "lon": -105.0, "vulns": [], "country": "US"},
            ]}

    import phantomsignal.intel.apis.shodan_api as shodan_mod
    monkeypatch.setattr(shodan_mod, "ShodanAPI", _Shodan)
    res = _run(geo_recon.GeoReconEngine(None).recon(lat=39.7, lon=-104.9, radius_km=20))
    assert res["configured"] and res["total"] == 2
    assert res["summary"]["hosts"] == 2 and res["summary"]["vuln_hosts"] == 1
    assert res["assets"][0]["ip"] == "1.1.1.1"               # vulnerable first
