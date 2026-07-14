"""Per-record attribution contract tests (spec §6 / §15.5)."""
from phantomsignal.intel.geo.attribution import explicit_match, record_attribution
from phantomsignal.intel.geo.extract import extract_signals


def test_explicit_match_normalises_percent_and_fraction():
    assert explicit_match({"match_confidence": 0.82}) == 0.82
    assert explicit_match({"match": 74}) == 0.74          # percentage form
    assert explicit_match({"score": "0.5"}) == 0.5
    assert explicit_match({"nope": 1}) is None


def test_explicit_match_wins_over_prior():
    # A source-declared match overrides the blanket profile prior.
    attr = record_attribution({"match_confidence": 0.9}, source="pipl", base=0.3,
                              kind="address_record")
    assert attr == 0.9


def test_kind_and_pivot_directness_discount():
    # Associate location ties weakly; a pivot source risks a namesake.
    assoc = record_attribution({}, source="relatives", base=0.8, kind="associate")
    assert abs(assoc - 0.4) < 1e-6                          # 0.8 * 0.5
    pivot = record_attribution({}, source="username_enum", base=0.8, kind="stated_location")
    assert abs(pivot - 0.68) < 1e-6                         # 0.8 * 0.85


def test_self_corroboration_bonus_on_identifier_echo():
    params = {"email": "alex@example.com", "username": "axm"}
    base = record_attribution({"city": "Denver"}, source="spokeo", base=0.6,
                              kind="address_record", search_params=params)
    echo = record_attribution({"city": "Denver", "email": "alex@example.com"},
                              source="spokeo", base=0.6, kind="address_record",
                              search_params=params)
    assert echo > base
    assert abs(echo - 0.8) < 1e-6                           # 1 - (1-0.6)*0.5
    # A name-only echo is NOT enough (namesakes share names).
    name_only = record_attribution({"name": "Alex Morgan"}, source="spokeo", base=0.6,
                                   kind="address_record", search_params={"first_name": "Alex"})
    assert abs(name_only - 0.6) < 1e-6


def test_extract_uses_per_record_attribution():
    profile = {
        "confidence": 0.5,
        "search_params": {"email": "alex@example.com"},
        "addresses": [
            {"city": "Denver", "state": "CO", "country": "US", "source": "spokeo",
             "match_confidence": 0.95},                     # explicit high match
            {"city": "Reno", "state": "NV", "country": "US", "source": "spokeo"},
        ],
        "relatives": [
            {"name": "Sam", "city": "Aspen", "state": "CO", "country": "US"},
        ],
    }
    sigs = {s.place.get("city"): s for s in extract_signals(profile)}
    assert sigs["Denver"].attribution_confidence == 0.95   # explicit wins
    assert abs(sigs["Reno"].attribution_confidence - 0.5) < 1e-6   # prior
    assert abs(sigs["Aspen"].attribution_confidence - 0.25) < 1e-6  # associate 0.5*0.5
