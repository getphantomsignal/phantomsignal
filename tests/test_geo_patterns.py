"""Pattern-of-life + prioritized search grid tests (spec §7 / §9, Phase 2)."""
from phantomsignal.intel.geo import aggregate, patterns
from phantomsignal.intel.geo.signals import GeoSignal


def _footprint(signals):
    clusters = aggregate.cluster(signals)
    sig_dicts = [s.to_dict() for s in signals]
    patterns.classify_places(clusters, sig_dicts)
    grid = patterns.search_grid(clusters, sig_dicts)
    return clusters, grid


def _by_label(items, label):
    return next(i for i in items if i["label"].startswith(label))


def test_night_and_weekend_fixes_classify_as_home():
    sigs = [
        GeoSignal("checkin", {"city": "Denver", "region": "CO", "country": "US"},
                  source="foursquare", lat=39.7, lon=-104.9, attribution_confidence=0.9,
                  observed_at="2026-01-05T23:10:00"),   # Monday night
        GeoSignal("checkin", {"city": "Denver", "region": "CO", "country": "US"},
                  source="swarm", lat=39.7, lon=-104.9, attribution_confidence=0.9,
                  observed_at="2026-01-10T09:30:00"),   # Saturday morning (weekend)
    ]
    clusters, _ = _footprint(sigs)
    assert clusters[0]["pol"] == "home"


def test_weekday_daytime_fixes_classify_as_work():
    sigs = [
        GeoSignal("checkin", {"city": "Boulder", "region": "CO", "country": "US"},
                  source="foursquare", lat=40.0, lon=-105.2, attribution_confidence=0.9,
                  observed_at="2026-01-06T10:00:00"),   # Tuesday 10am
        GeoSignal("checkin", {"city": "Boulder", "region": "CO", "country": "US"},
                  source="swarm", lat=40.0, lon=-105.2, attribution_confidence=0.9,
                  observed_at="2026-01-07T14:00:00"),   # Wednesday 2pm
    ]
    clusters, _ = _footprint(sigs)
    assert clusters[0]["pol"] == "work"


def test_residential_record_without_clock_leans_home():
    sigs = [GeoSignal("address_record", {"city": "Reno", "region": "NV", "country": "US"},
                      source="spokeo", lat=39.5, lon=-119.8, attribution_confidence=0.7,
                      observed_at="2025-06-01")]        # date only, no clock
    clusters, _ = _footprint(sigs)
    assert clusters[0]["pol"] == "home"
    assert "residential" in clusters[0]["pol_reason"]


def test_search_grid_ranks_home_over_stale_oneoff_and_drops_eliminated():
    sigs = [
        # Home: corroborated night check-ins, recent.
        GeoSignal("checkin", {"city": "Denver", "region": "CO", "country": "US"},
                  source="foursquare", lat=39.7, lon=-104.9, attribution_confidence=0.9,
                  observed_at="2026-06-01T23:00:00"),
        GeoSignal("checkin", {"city": "Denver", "region": "CO", "country": "US"},
                  source="swarm", lat=39.7, lon=-104.9, attribution_confidence=0.9,
                  observed_at="2026-06-02T22:00:00"),
        # A stale, weak, one-off inferred sighting elsewhere.
        GeoSignal("area_code", {"country": "US", "city": "Miami", "region": "FL"},
                  source="phone", lat=25.7, lon=-80.1, attribution_confidence=0.4,
                  observed_at="2019-01-01"),
        # An eliminated place (negative only) — must not appear in the grid.
        GeoSignal("checkin", {"city": "Reno", "region": "NV", "country": "US"},
                  source="manual", polarity="negative", attribution_confidence=0.9),
    ]
    clusters, grid = _footprint(sigs)
    labels = [g["label"] for g in grid]
    assert labels and labels[0].startswith("Denver")      # home ranks first
    assert grid[0]["score"] > grid[-1]["score"]
    assert not any(g["label"].startswith("Reno") for g in grid)   # eliminated dropped
    assert _by_label(grid, "Denver")["pol"] == "home"
