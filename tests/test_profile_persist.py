"""Tests for Profiler persistence — flattening a shadow profile into a
people_intel Scan + ScanResults so it lands in the Scans store.

The flattener is pure and tested directly. The DB writer is exercised against
an in-memory SQLite database.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from phantomsignal.core.models import Base, Scan, ScanResult, ShadowProfile
from phantomsignal.intel.people import persist as P


_PROFILE = {
    "search_params": {"username": "janedoe"},
    "names": ["Jane Doe"],
    "emails": [{"value": "jane@example.com", "source": "gravatar"}],
    "phones": [{"value": "+15551234567", "source": "abstract"}],
    "addresses": [],
    "social_profiles": {
        "github": "https://github.com/janedoe",
        "emailrep": "[found via emailrep on twitter]",
    },
    "usernames": [{"value": "janedoe", "platform": "github"}],
    "employers": ["Acme Corp"],
    "locations": [{"value": "Denver, CO", "source": "github"}],
    "breach_data": [{"name": "BigBreach", "breach_date": "2019"}],
    "images": ["https://img/1.png"],
    "sources": ["github", "gravatar"],
    "confidence": 0.5,
    "shadow_score": 42.0,
    "raw_results": [{"type": "x"}],
}


# ── pure flattener ────────────────────────────────────────────────────────────

def test_flatten_covers_all_sections():
    rows = P.profile_to_results(_PROFILE)
    types = {r["type"] for r in rows}
    assert {"identity_name", "email", "phone", "social_profile", "username",
            "employer", "stated_location", "breach_data", "profile_image",
            "people_profile_summary"} <= types
    # every row carries the people tag and a data dict
    assert all("people" in r["tags"] for r in rows)
    assert all(isinstance(r["data"], dict) for r in rows)


def test_flatten_social_dict_becomes_rows():
    rows = P.profile_to_results(_PROFILE)
    socials = [r for r in rows if r["type"] == "social_profile"]
    assert {r["source"] for r in socials} == {"github", "emailrep"}
    gh = next(r for r in socials if r["source"] == "github")
    assert gh["data"] == {"platform": "github", "url": "https://github.com/janedoe"}


def test_flatten_breach_is_anomaly():
    rows = P.profile_to_results(_PROFILE)
    breach = next(r for r in rows if r["type"] == "breach_data")
    assert breach["is_anomaly"] is True


def test_flatten_summary_counts():
    summary = next(r for r in P.profile_to_results(_PROFILE)
                   if r["type"] == "people_profile_summary")
    assert summary["data"]["emails"] == 1
    assert summary["data"]["social_profiles"] == 2
    assert summary["data"]["breaches"] == 1
    assert summary["data"]["shadow_score"] == 42.0


def test_flatten_empty_profile():
    assert P.profile_to_results({}) == []


def test_query_label_prefers_name():
    assert P.query_label({"first_name": "Jane", "last_name": "Doe"}) == "Jane Doe"
    assert P.query_label({"email": "x@y.z"}) == "x@y.z"
    assert P.query_label({"username": "j"}) == "j"
    assert P.query_label({}) == "unknown subject"


def test_threat_level_thresholds():
    assert P._threat_level(90, False).value == "critical"
    assert P._threat_level(65, False).value == "malicious"
    assert P._threat_level(40, False).value == "suspicious"
    assert P._threat_level(5, True).value == "suspicious"  # breach floors it
    assert P._threat_level(5, False).value == "clean"
    assert P._threat_level(0, False).value == "unknown"


# ── DB writer ─────────────────────────────────────────────────────────────────

@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Factory = sessionmaker(bind=engine, expire_on_commit=False)

    from contextlib import contextmanager

    @contextmanager
    def _get_db():
        s = Factory()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    monkeypatch.setattr(P, "get_db", _get_db)
    return Factory


def test_persist_creates_scan_and_results(db):
    scan_id = P.persist_profile_scan(_PROFILE, {"username": "janedoe"})
    assert scan_id
    s = db()
    scan = s.query(Scan).filter(Scan.id == scan_id).first()
    assert scan.scan_type.value == "people_intel"
    assert scan.status.value == "complete"
    assert scan.shadow_score == 42.0
    assert scan.progress == 100
    assert s.query(ScanResult).filter(ScanResult.scan_id == scan_id).count() >= 9
    sp = s.query(ShadowProfile).filter(ShadowProfile.scan_id == scan_id).first()
    assert sp.full_name == "Jane Doe"
    assert sp.social_profiles["github"] == "https://github.com/janedoe"
    s.close()


def test_persist_empty_profile_returns_none(db):
    assert P.persist_profile_scan({}, {"username": "x"}) is None
