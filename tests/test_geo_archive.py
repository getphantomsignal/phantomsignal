"""Archived / scrubbed location capture tests (spec §8)."""
import asyncio

from phantomsignal.intel.geo import archive


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_extract_locations_from_text():
    html = '''<script>{"name":"Alex","location":"Denver, CO","x":1}</script>
              <p>Currently based in Portland, Oregon and loving it.</p>
              <span>location: not-a-place-just-words-without-comma</span>'''
    locs = archive.extract_locations_from_text(html)
    assert "Denver, CO" in locs
    assert any("Portland" in v for v in locs)
    # a bare wordy string with no comma / city,region shape is rejected
    assert not any("not-a-place" in v for v in locs)


def test_parse_cdx_snapshots_skips_header_and_builds_urls():
    payload = [
        ["timestamp", "original"],
        ["20180101000000", "https://twitter.com/axm"],
        ["20200601120000", "https://twitter.com/axm"],
    ]
    snaps = archive.parse_cdx_snapshots(payload)
    assert len(snaps) == 2
    ts, url = snaps[0]
    assert ts == "20180101000000"
    assert "web.archive.org/web/20180101000000id_/" in url


def test_current_place_keys_and_scrubbed_detection():
    profile = {
        "locations": [{"value": "Austin, TX", "source": "twitter"}],
        "addresses": [{"city": "Austin", "state": "TX", "country": "US"}],
    }
    keys = archive.current_place_keys(profile)
    # Austin normalises to one key regardless of how it was written.
    assert archive.canonical_key({"city": "Austin", "region": "TX"}, None, None) in keys
    # A different archived place is "scrubbed" (not among current keys).
    denver = archive.canonical_key({"city": "Denver", "region": "CO"}, None, None)
    assert denver not in keys


def test_mine_flags_scrubbed_vs_retained(monkeypatch):
    # Current profile knows Austin; the archive also shows a since-removed Denver.
    profile = {
        "confidence": 0.7,
        "search_params": {"username": "axm"},
        "social_profiles": {"twitter": "https://twitter.com/axm"},
        "locations": [{"value": "Austin, TX", "source": "twitter"}],
    }

    archived_html = '{"location":"Denver, CO"} ... {"location":"Austin, TX"}'

    class _Resp:
        def __init__(self, *, js=None, text=""):
            self._js, self.text = js, text

        def json(self):
            return self._js

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, *a, **k):
            if "cdx" in url:
                return _Resp(js=[["timestamp", "original"],
                                 ["20190101000000", "https://twitter.com/axm"]])
            return _Resp(text=archived_html)

    import phantomsignal.core.http as http_mod
    monkeypatch.setattr(http_mod, "stealth_client", lambda *a, **k: _Client())

    sigs = _run(archive.mine_archived_locations(None, profile))
    by_city = {s.place.get("city"): s for s in sigs}
    assert set(by_city) == {"Denver", "Austin"}
    assert by_city["Denver"].raw["scrubbed"] is True        # gone from current profile
    assert by_city["Austin"].raw["scrubbed"] is False       # still present
    assert by_city["Denver"].observed_at == "2019-01-01"
    assert all(s.kind == "archived_location" for s in sigs)
