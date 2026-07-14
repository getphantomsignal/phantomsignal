"""
Persistence + chain-of-custody for Locate cases (spec §5/§10).

Bridges the compute-layer ``GeoSignal`` dataclass to the ``LocateSignal`` ORM
row, and records an ``AuditEvent`` for every ingest / edit / export so the output
is defensible for handoff.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from phantomsignal.core.models import AuditEvent, LocateCase, LocateSignal
from phantomsignal.intel.geo import aggregate
from phantomsignal.intel.geo.places import canonical_key
from phantomsignal.intel.geo.signals import GeoSignal


def _to_record(sig: GeoSignal, case_id: str) -> LocateSignal:
    return LocateSignal(
        id=sig.id, case_id=case_id, kind=sig.kind, polarity=sig.polarity,
        entry=sig.entry, place=sig.place or {}, place_key=sig.place_key,
        lat=sig.lat, lon=sig.lon, observed_at=sig.observed_at,
        source=sig.source, source_url=sig.source_url,
        attribution_confidence=sig.attribution_confidence, raw=sig.raw or {},
    )


def _from_record(rec: LocateSignal) -> GeoSignal:
    return GeoSignal(
        kind=rec.kind, place=rec.place or {}, source=rec.source or "unknown",
        source_url=rec.source_url, lat=rec.lat, lon=rec.lon,
        observed_at=rec.observed_at, attribution_confidence=rec.attribution_confidence or 1.0,
        polarity=rec.polarity or "positive", entry=rec.entry or "auto",
        raw=rec.raw or {}, id=rec.id,
    )


def audit(db, case_id: str, actor: Optional[str], action: str,
          source: Optional[str] = None, detail: Optional[str] = None) -> None:
    db.add(AuditEvent(case_id=case_id, actor=actor, action=action,
                      source=source, detail=detail))


def open_case(db, *, subject: str, identifiers: Dict, purpose: str,
              opened_by: str, sensitivity: str = "normal",
              profile_id: Optional[str] = None) -> str:
    case = LocateCase(
        subject=subject, identifiers=identifiers or {}, purpose=purpose,
        opened_by=opened_by, sensitivity=sensitivity, profile_id=profile_id,
    )
    db.add(case)
    db.flush()
    audit(db, case.id, opened_by, "case_opened",
          detail=f"subject={subject!r} purpose={purpose!r} sensitivity={sensitivity}")
    return case.id


def persist_signals(db, case_id: str, signals: List[GeoSignal], *,
                    actor: Optional[str], source_label: str = "profiler") -> int:
    """Idempotent ingest: skip a signal already present for this case by
    (kind, place_key, source, polarity)."""
    existing = db.query(LocateSignal).filter(LocateSignal.case_id == case_id).all()
    seen = {(r.kind, r.place_key, r.source, r.polarity) for r in existing}
    added = 0
    for s in signals:
        s.place_key = canonical_key(s.place, s.lat, s.lon)
        key = (s.kind, s.place_key, s.source, s.polarity)
        if key in seen:
            continue
        seen.add(key)
        db.add(_to_record(s, case_id))
        added += 1
    if added:
        audit(db, case_id, actor, "signals_ingested", source=source_label,
              detail=f"{added} signal(s)")
    return added


def load_signals(db, case_id: str) -> List[GeoSignal]:
    rows = db.query(LocateSignal).filter(LocateSignal.case_id == case_id).all()
    return [_from_record(r) for r in rows]


def add_manual_signal(db, case_id: str, *, kind: str, place: Dict, polarity: str,
                      source: str, actor: str, attribution_confidence: float = 0.9,
                      observed_at: Optional[str] = None) -> None:
    sig = GeoSignal(kind=kind, place=place, source=source, polarity=polarity,
                    entry="manual", attribution_confidence=attribution_confidence,
                    observed_at=observed_at)
    sig.place_key = canonical_key(sig.place, sig.lat, sig.lon)
    db.add(_to_record(sig, case_id))
    audit(db, case_id, actor, "manual_signal_added", source=source,
          detail=f"{polarity} {kind} @ {place}")


def footprint_for_case(db, case_id: str, *, subject: str = "subject") -> Dict:
    """Recompute the footprint from persisted signals (so manual/negative
    additions are always reflected), and cache last-known on the case."""
    signals = load_signals(db, case_id)
    clusters = aggregate.cluster(signals)
    lk = aggregate.last_known(clusters, signals)
    conf = aggregate.conflicts(clusters, signals)

    case = db.query(LocateCase).filter(LocateCase.id == case_id).first()
    if case is not None:
        case.last_known = lk
        if not subject or subject == "subject":
            subject = case.subject or "subject"

    return {
        "subject": subject,
        "signals": [s.to_dict() for s in signals],
        "clusters": clusters,
        "last_known": lk,
        "conflicts": conf,
        "counts": {
            "signals": len(signals), "clusters": len(clusters),
            "hard": sum(1 for s in signals if s.tier == "hard"),
            "conflicts": len(conf),
        },
        "sources": sorted({s.source for s in signals}),
    }


def delete_case(db, case_id: str) -> bool:
    """Purge a case and everything under it (signals + chain-of-custody). The
    audit trail goes with the case — a purged case leaves nothing behind."""
    case = db.query(LocateCase).filter(LocateCase.id == case_id).first()
    if case is None:
        return False
    db.delete(case)   # cascade removes LocateSignal + AuditEvent rows
    return True


def delete_signal(db, case_id: str, signal_id: str, *, actor: Optional[str] = None) -> bool:
    """Remove a single signal from a case, keeping the audit trail and logging
    the removal (the case itself is retained)."""
    rec = (db.query(LocateSignal)
           .filter(LocateSignal.id == signal_id, LocateSignal.case_id == case_id)
           .first())
    if rec is None:
        return False
    detail = f"{rec.polarity} {rec.kind} @ {rec.place}"
    db.delete(rec)
    audit(db, case_id, actor, "signal_deleted", source=rec.source, detail=detail)
    return True


def list_cases(db) -> List[Dict]:
    rows = db.query(LocateCase).order_by(LocateCase.created_at.desc()).limit(100).all()
    return [c.to_dict() for c in rows]


def list_audit(db, case_id: str) -> List[Dict]:
    rows = (db.query(AuditEvent).filter(AuditEvent.case_id == case_id)
            .order_by(AuditEvent.at.asc()).all())
    return [a.to_dict() for a in rows]
