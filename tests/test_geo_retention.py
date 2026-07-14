"""Retention + minor-subject governance tests (spec §10)."""
from datetime import datetime, timedelta, timezone

import pytest

from phantomsignal.core.database import get_db, init_db
from phantomsignal.core.models import AuditEvent, LocateCase, LocateSignal
from phantomsignal.intel.geo import retention, store
from phantomsignal.intel.geo.export import to_report


def _iso(days_from_now):
    return (datetime.now(timezone.utc).date() + timedelta(days=days_from_now)).isoformat()


def test_until_iso_and_status():
    assert retention.until_iso(None) is None
    assert retention.until_iso(0) is None
    assert retention.until_iso("30")[:4].isdigit()        # accepts stringy input
    future = retention.status(_iso(10))
    assert future["set"] and not future["expired"] and future["days_left"] == 10
    past = retention.status(_iso(-3))
    assert past["set"] and past["expired"] and past["days_left"] == -3
    none = retention.status(None)
    assert none == {"set": False, "until": None, "expired": False, "days_left": None}


@pytest.fixture(autouse=True)
def _db():
    init_db()
    with get_db() as db:
        db.query(AuditEvent).delete()
        db.query(LocateSignal).delete()
        db.query(LocateCase).delete()
    yield


def test_open_case_stores_retention_and_audits():
    until = _iso(90)
    with get_db() as db:
        cid = store.open_case(db, subject="R", identifiers={}, purpose="", opened_by="op",
                              retention_until=until)
    with get_db() as db:
        case = db.query(LocateCase).filter(LocateCase.id == cid).first()
        assert case.retention_until == until
        assert any("retention_until" in (e["detail"] or "") for e in store.list_audit(db, cid))
        # list surfaces the computed status
        d = next(c for c in store.list_cases(db) if c["id"] == cid)
        assert d["retention"]["set"] and not d["retention"]["expired"]


def test_purge_expired_only_removes_past_cases():
    with get_db() as db:
        keep = store.open_case(db, subject="Keep", identifiers={}, purpose="", opened_by="op",
                               retention_until=_iso(30))
        gone = store.open_case(db, subject="Gone", identifiers={}, purpose="", opened_by="op",
                               retention_until=_iso(-1))
        forever = store.open_case(db, subject="Forever", identifiers={}, purpose="", opened_by="op")
    with get_db() as db:
        assert store.purge_expired(db) == 1
    with get_db() as db:
        ids = {c["id"] for c in store.list_cases(db)}
        assert keep in ids and forever in ids and gone not in ids


def test_minor_and_retention_notices_in_report():
    fp = {"subject": "Kid", "sensitivity": "minor",
          "retention": {"set": True, "until": _iso(-2), "expired": True, "days_left": -2},
          "clusters": [], "signals": [], "conflicts": [], "search_grid": []}
    report = to_report(fp)
    assert "MINOR SUBJECT" in report
    assert "Past retention" in report
