"""Persistent geocode cache tests (spec §12)."""
import asyncio

import pytest

from phantomsignal.core.database import get_db, init_db
from phantomsignal.core.models import GeoCache
from phantomsignal.intel.geo import places


@pytest.fixture(autouse=True)
def _db_and_clear_mem():
    init_db()
    places._GEO_CACHE.clear()
    with get_db() as db:
        db.query(GeoCache).delete()
    yield
    with get_db() as db:
        db.query(GeoCache).delete()


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_geocode_persists_and_reuses_without_second_network_hit(monkeypatch):
    calls = {"n": 0}

    class _Resp:
        def json(self):
            return [{"lat": "39.7392", "lon": "-104.9903"}]

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **k):
            calls["n"] += 1
            return _Resp()

    monkeypatch.setattr(places, "stealth_client", lambda *a, **k: _Client(), raising=False)
    import phantomsignal.core.http as http_mod
    monkeypatch.setattr(http_mod, "stealth_client", lambda *a, **k: _Client())

    place = {"city": "Denver", "region": "CO", "country": "US"}
    coords = _run(places.geocode(None, place))
    assert coords == (39.7392, -104.9903)
    assert calls["n"] == 1

    # Persisted to the DB cache.
    with get_db() as db:
        row = db.query(GeoCache).filter(GeoCache.query == "Denver, CO, US").first()
        assert row is not None and row.hit and row.lat == pytest.approx(39.7392)

    # A fresh process (clear the in-memory layer) reuses the DB cache — no 2nd call.
    places._GEO_CACHE.clear()
    coords2 = _run(places.geocode(None, place))
    assert coords2 == (39.7392, -104.9903)
    assert calls["n"] == 1


def test_negative_result_is_cached(monkeypatch):
    calls = {"n": 0}

    class _Resp:
        def json(self):
            return []                       # no geocode result

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

    place = {"city": "Nowheresville", "country": "XX"}
    assert _run(places.geocode(None, place)) is None
    assert calls["n"] == 1
    with get_db() as db:
        row = db.query(GeoCache).filter(GeoCache.query == "Nowheresville, XX").first()
        assert row is not None and row.hit is False

    places._GEO_CACHE.clear()
    assert _run(places.geocode(None, place)) is None
    assert calls["n"] == 1                  # negative cache prevents a re-hit
