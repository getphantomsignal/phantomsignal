"""EXIF GPS capture + reverse-geocode tests (spec §8 / §12)."""
import asyncio

import pytest

from phantomsignal.core.database import get_db, init_db
from phantomsignal.core.models import GeoReverseCache
from phantomsignal.intel.geo import exif, places


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_iso_dt_parses_exif_datetime():
    assert exif._iso_dt("2026:06:01 14:30:00") == "2026-06-01T14:30:00"
    assert exif._iso_dt("garbage") is None
    assert exif._iso_dt(None) is None


def test_image_geo_reads_gps_and_datetime(monkeypatch):
    monkeypatch.setattr(exif, "parse_exif_metadata",
                        lambda raw: {"gps": {"lat": 39.7392, "lon": -104.9903},
                                     "datetime": "2026:06:01 10:00:00"})
    geo = exif.image_geo(b"fakejpegbytes")
    assert geo == {"lat": 39.7392, "lon": -104.9903, "observed_at": "2026-06-01T10:00:00"}
    # No GPS => no signal.
    monkeypatch.setattr(exif, "parse_exif_metadata", lambda raw: {"exif_make": "Apple"})
    assert exif.image_geo(b"x") is None


def test_mine_image_exif_emits_reverse_geocoded_hard_fix(monkeypatch):
    profile = {
        "confidence": 0.8,
        "search_params": {"username": "axm"},
        "images": ["https://cdn.example.com/photo1.jpg", "https://cdn.example.com/photo2.jpg"],
    }

    class _Resp:
        content = b"jpegbytes"

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, *a, **k):
            return _Resp()

    import phantomsignal.core.http as http_mod
    monkeypatch.setattr(http_mod, "stealth_client", lambda *a, **k: _Client())
    # Only the first photo carries GPS.
    seen = {"n": 0}

    def _fake_parse(raw):
        seen["n"] += 1
        return ({"gps": {"lat": 39.7392, "lon": -104.9903}, "datetime": "2026:06:01 10:00:00"}
                if seen["n"] == 1 else {})

    monkeypatch.setattr(exif, "parse_exif_metadata", _fake_parse)

    async def _fake_reverse(config, lat, lon):
        return {"city": "Denver", "region": "CO", "country": "US"}

    monkeypatch.setattr(places, "reverse_geocode", _fake_reverse)

    sigs = _run(exif.mine_image_exif(None, profile))
    assert len(sigs) == 1
    s = sigs[0]
    assert s.kind == "exif_gps"
    assert s.place == {"city": "Denver", "region": "CO", "country": "US"}
    assert s.lat == 39.7392 and s.observed_at == "2026-06-01T10:00:00"
    assert s.source_url == "https://cdn.example.com/photo1.jpg"
    # exif_gps is a hard fix: high effective confidence on a well-matched profile.
    assert s.effective_confidence > 0.7


@pytest.fixture
def _db():
    init_db()
    places._REV_CACHE.clear()
    with get_db() as db:
        db.query(GeoReverseCache).delete()
    yield
    with get_db() as db:
        db.query(GeoReverseCache).delete()


def test_reverse_geocode_caches_across_processes(_db, monkeypatch):
    calls = {"n": 0}

    class _Resp:
        def json(self):
            return {"address": {"city": "Denver", "state": "Colorado", "country_code": "us"}}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **k):
            calls["n"] += 1
            return _Resp()

    import phantomsignal.core.http as http_mod
    monkeypatch.setattr(http_mod, "stealth_client", lambda *a, **k: _Client())

    place = _run(places.reverse_geocode(None, 39.7392, -104.9903))
    assert place == {"city": "Denver", "region": "Colorado", "country": "US"}
    assert calls["n"] == 1

    places._REV_CACHE.clear()                     # simulate a fresh process
    place2 = _run(places.reverse_geocode(None, 39.7392, -104.9903))
    assert place2["city"] == "Denver"
    assert calls["n"] == 1                          # served from the DB cache
