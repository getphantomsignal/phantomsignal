"""Tests for the Geo/Locate compute core (Phase 1a). See specs/geo-locate.md."""
import asyncio
import json

from phantomsignal.intel.geo import aggregate
from phantomsignal.intel.geo.engine import GeoEngine
from phantomsignal.intel.geo.export import to_geojson, to_kml, to_report
from phantomsignal.intel.geo.extract import extract_signals, parse_address
from phantomsignal.intel.geo.signals import GeoSignal, combine_confidence, round_to_confidence


def _sig(kind, place=None, attr=1.0, **kw):
    return GeoSignal(kind=kind, place=place or {"city": "Denver", "region": "CO", "country": "US"},
                     source=kw.pop("source", "test"), attribution_confidence=attr, **kw)


def test_compound_confidence_discounts_attribution():
    # A perfect EXIF fix on a weakly-matched profile is NOT a strong location.
    strong = _sig("exif_gps", attr=1.0)
    weak = _sig("exif_gps", attr=0.4)
    assert strong.effective_confidence > 0.9
    assert abs(weak.effective_confidence - 0.95 * 0.4) < 1e-6
    assert weak.effective_confidence < strong.effective_confidence


def test_corroboration_combines():
    # Two independent 0.6 signals agreeing beat either alone.
    assert abs(combine_confidence([0.6, 0.6]) - 0.84) < 1e-6
    assert combine_confidence([0.95]) == 0.95
    assert combine_confidence([0.3, 0.3, 0.3]) < 0.66


def test_precision_rounding_matches_tier():
    assert round_to_confidence("exif_gps", 39.123456) == 39.1235   # hard: 4dp
    assert round_to_confidence("address_record", 39.123456) == 39.12  # stated: 2dp
    assert round_to_confidence("timezone", 39.123456) == 39.1        # inferred: 1dp


def test_parse_address_variants():
    d = parse_address({"city": "Denver", "state": "CO", "postal_code": "80202"})
    assert d["city"] == "Denver" and d["region"] == "CO" and d["zip"] == "80202"
    s = parse_address("123 Main St, Denver, CO 80202")
    assert s["city"] == "Denver" and s["region"] == "CO" and s["zip"] == "80202"


def test_extract_from_profile():
    profile = {
        "confidence": 0.8,
        "addresses": [{"city": "Denver", "state": "CO", "zip": "80202", "source": "spokeo"}],
        "images": [{"lat": 39.7392, "lon": -104.9903, "source": "exif", "taken_at": "2026-06-01T10:00:00Z"}],
        "breach_data": [{"country": "US", "city": "Denver"}],
        "phones": [{"value": "+13035551234", "country": "United States"}],
        "associates": [{"name": "Jane Roe", "city": "Boulder", "state": "CO"}],
    }
    sigs = extract_signals(profile)
    kinds = {s.kind for s in sigs}
    assert {"address_record", "exif_gps", "breach_field", "area_code", "associate"} <= kinds
    # associate is discounted twice (low kind + attr*0.5)
    assoc = next(s for s in sigs if s.kind == "associate")
    addr = next(s for s in sigs if s.kind == "address_record")
    assert assoc.effective_confidence < addr.effective_confidence


def test_cluster_and_last_known_prefers_corroborated_hard_fix():
    signals = [
        _sig("exif_gps", place={"city": "Denver", "region": "CO", "country": "US"},
             lat=39.7392, lon=-104.9903, observed_at="2026-06-01T00:00:00Z"),
        _sig("checkin", place={"city": "Denver", "region": "CO", "country": "US"},
             lat=39.7392, lon=-104.9903, observed_at="2026-06-02T00:00:00Z"),
        _sig("stated_location", place={"city": "Miami", "region": "FL", "country": "US"}, attr=0.6),
    ]
    clusters = aggregate.cluster(signals)
    lk = aggregate.last_known(clusters, signals)
    assert lk is not None
    assert "Denver" in lk["label"]
    assert lk["corroboration"] == 2 and lk["radius_km"] <= 2.0


def test_conflict_competing_and_travel_infeasible():
    signals = [
        _sig("geotag", place={"city": "Denver", "region": "CO", "country": "US"},
             lat=39.7, lon=-104.9, observed_at="2026-06-01T10:00:00Z"),
        _sig("geotag", place={"city": "Tokyo", "country": "JP"},
             lat=35.6, lon=139.6, observed_at="2026-06-01T12:00:00Z"),
    ]
    clusters = aggregate.cluster(signals)
    conf = aggregate.conflicts(clusters, signals)
    types = {c["type"] for c in conf}
    assert "competing_locations" in types   # two strong disagreeing places
    assert "travel_infeasible" in types      # Denver->Tokyo in 2h


def test_negative_signal_eliminates_area():
    signals = [_sig("checkin", place={"city": "Reno", "region": "NV", "country": "US"},
                    lat=39.5, lon=-119.8, polarity="negative")]
    clusters = aggregate.cluster(signals)
    assert clusters[0]["eliminated"] is True
    assert aggregate.last_known(clusters, signals) is None


def test_engine_locate_and_exports():
    profile = {
        "search_params": {"first_name": "John", "last_name": "Doe"},
        "confidence": 0.75,
        "addresses": [
            {"city": "Denver", "state": "CO", "zip": "80202", "lat": 39.7392, "lon": -104.9903, "source": "spokeo"},
            {"city": "Denver", "state": "CO", "zip": "80202", "lat": 39.7392, "lon": -104.9903, "source": "whitepages"},
        ],
    }
    fp = asyncio.run(GeoEngine(None).locate(profile, geocode=False))
    assert fp["subject"] == "John Doe"
    assert fp["last_known"] and "Denver" in fp["last_known"]["label"]
    # two independent sources on the same place → corroborated above either alone
    assert fp["last_known"]["confidence"] > 0.65 * 0.75

    gj = json.loads(to_geojson(fp))
    assert gj["type"] == "FeatureCollection" and gj["features"]
    kml = to_kml(fp)
    assert "<kml" in kml and "Denver" in kml
    report = to_report(fp)
    assert "Last-known" in report and "spokeo" in report and "whitepages" in report
