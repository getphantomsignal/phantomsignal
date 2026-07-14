"""Persistence + chain-of-custody tests for Locate (Phase 1b)."""
import pytest

from phantomsignal.core.database import get_db, init_db
from phantomsignal.core.models import LocateCase, LocateSignal, AuditEvent
from phantomsignal.intel.geo import store
from phantomsignal.intel.geo.signals import GeoSignal


@pytest.fixture(autouse=True)
def _db():
    init_db()
    yield


def _cleanup(db, case_id):
    db.query(AuditEvent).filter(AuditEvent.case_id == case_id).delete()
    db.query(LocateSignal).filter(LocateSignal.case_id == case_id).delete()
    db.query(LocateCase).filter(LocateCase.id == case_id).delete()


def test_open_case_logs_audit():
    with get_db() as db:
        cid = store.open_case(db, subject="Alex Morgan", identifiers={"first_name": "Alex"},
                              purpose="test case", opened_by="analyst", sensitivity="minor")
    with get_db() as db:
        case = db.query(LocateCase).filter(LocateCase.id == cid).first()
        assert case and case.subject == "Alex Morgan" and case.sensitivity == "minor"
        events = store.list_audit(db, cid)
        assert any(e["action"] == "case_opened" for e in events)
        _cleanup(db, cid)


def test_persist_is_idempotent_and_recomputes_footprint():
    sigs = [
        GeoSignal("address_record", {"city": "Denver", "region": "CO", "country": "US"},
                  source="spokeo", lat=39.7392, lon=-104.9903, attribution_confidence=0.8),
        GeoSignal("address_record", {"city": "Denver", "region": "CO", "country": "US"},
                  source="whitepages", lat=39.7392, lon=-104.9903, attribution_confidence=0.8),
    ]
    with get_db() as db:
        cid = store.open_case(db, subject="Test", identifiers={}, purpose="", opened_by="op")
        n1 = store.persist_signals(db, cid, sigs, actor="op")
    assert n1 == 2
    with get_db() as db:
        # re-persisting the same signals adds nothing (idempotent)
        n2 = store.persist_signals(db, cid, [
            GeoSignal("address_record", {"city": "Denver", "region": "CO", "country": "US"},
                      source="spokeo", lat=39.7392, lon=-104.9903, attribution_confidence=0.8),
        ], actor="op")
        assert n2 == 0
        fp = store.footprint_for_case(db, cid, subject="Test")
        assert fp["last_known"] and "Denver" in fp["last_known"]["label"]
        # two independent sources corroborate above either alone
        assert fp["last_known"]["confidence"] > 0.65 * 0.8
        _cleanup(db, cid)


def test_manual_negative_signal_eliminates_and_audits():
    with get_db() as db:
        cid = store.open_case(db, subject="Test2", identifiers={}, purpose="", opened_by="op")
        store.add_manual_signal(db, cid, kind="checkin", place={"city": "Reno", "region": "NV", "country": "US"},
                                polarity="negative", source="manual", actor="op")
    with get_db() as db:
        fp = store.footprint_for_case(db, cid, subject="Test2")
        assert fp["clusters"][0]["eliminated"] is True
        assert fp["last_known"] is None
        events = store.list_audit(db, cid)
        assert any(e["action"] == "manual_signal_added" for e in events)
        _cleanup(db, cid)


def test_delete_case_purges_signals_and_audit():
    sigs = [GeoSignal("address_record", {"city": "Denver", "region": "CO", "country": "US"},
                      source="spokeo", lat=39.7, lon=-104.9, attribution_confidence=0.8)]
    with get_db() as db:
        cid = store.open_case(db, subject="Purge Me", identifiers={}, purpose="", opened_by="op")
        store.persist_signals(db, cid, sigs, actor="op")
    with get_db() as db:
        assert store.delete_case(db, cid) is True
    with get_db() as db:
        assert db.query(LocateCase).filter(LocateCase.id == cid).first() is None
        # cascade removed children — nothing left to stack up
        assert db.query(LocateSignal).filter(LocateSignal.case_id == cid).count() == 0
        assert db.query(AuditEvent).filter(AuditEvent.case_id == cid).count() == 0
        # deleting a missing case is a no-op, not an error
        assert store.delete_case(db, "does-not-exist") is False


def test_delete_signal_keeps_case_and_logs():
    with get_db() as db:
        cid = store.open_case(db, subject="Keep", identifiers={}, purpose="", opened_by="op")
        store.add_manual_signal(db, cid, kind="checkin", place={"city": "Reno", "region": "NV", "country": "US"},
                                polarity="positive", source="manual", actor="op")
    with get_db() as db:
        sig_id = db.query(LocateSignal).filter(LocateSignal.case_id == cid).first().id
    with get_db() as db:
        assert store.delete_signal(db, cid, sig_id, actor="op") is True
    with get_db() as db:
        assert db.query(LocateSignal).filter(LocateSignal.id == sig_id).first() is None
        assert db.query(LocateCase).filter(LocateCase.id == cid).first() is not None
        events = store.list_audit(db, cid)
        assert any(e["action"] == "signal_deleted" for e in events)
        assert store.delete_signal(db, cid, "missing", actor="op") is False
        _cleanup(db, cid)
