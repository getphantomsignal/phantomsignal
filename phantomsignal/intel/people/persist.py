"""
PhantomSignal — Profiler persistence.

The Profiler (``ShadowProfileBuilder``) historically returned an ephemeral dict
that was rendered once and then lost: it never appeared under Scans and had no
history, export, or diff. This module flattens a built profile into the same
``Scan`` / ``ScanResult`` shape the recon engine produces, so a Profiler run is
a first-class scan (type ``people_intel``) alongside every other scan.

The flattener is pure and unit-tested; ``persist_profile_scan`` composes the DB
write around it.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional

from phantomsignal.core.database import get_db
from phantomsignal.core.models import (
    Scan, ScanResult, ScanStatus, ScanType, ShadowProfile, ThreatLevel,
)

logger = logging.getLogger("phantomsignal.people.persist")

MODULE = "profiler"


def query_label(query: Optional[Dict]) -> str:
    """Human label for the scan target, derived from whatever identifiers the
    Profiler was run with."""
    query = query or {}
    first = (query.get("first_name") or "").strip()
    last = (query.get("last_name") or "").strip()
    name = " ".join(x for x in (first, last) if x).strip()
    return (name or query.get("email") or query.get("username")
            or query.get("phone") or "unknown subject")


def _value(item, key="value"):
    return item.get(key) if isinstance(item, dict) else item


def _source(item, default=MODULE):
    if isinstance(item, dict) and item.get("source"):
        return item["source"]
    return default


def profile_to_results(profile: Dict) -> List[Dict]:
    """Flatten a shadow profile dict into engine-style result records
    (``{type, source, data, confidence, relevance_score, is_anomaly, tags}``).
    Pure — no DB, no network."""
    if not profile:
        return []

    results: List[Dict] = []

    def add(rtype, source, data, *, confidence=0.7, relevance=0.6,
            anomaly=False, tags=None):
        results.append({
            "type": rtype, "source": source,
            "data": data if isinstance(data, dict) else {"value": data},
            "confidence": confidence, "relevance_score": relevance,
            "is_anomaly": anomaly, "tags": ["people", *(tags or [])],
        })

    for name in profile.get("names", []):
        add("identity_name", MODULE, {"value": name}, relevance=0.75,
            tags=["identity"])

    for email in profile.get("emails", []):
        add("email", _source(email), email if isinstance(email, dict)
            else {"value": email}, confidence=0.8, relevance=0.8, tags=["email"])

    for phone in profile.get("phones", []):
        add("phone", _source(phone), phone if isinstance(phone, dict)
            else {"value": phone}, confidence=0.8, relevance=0.8, tags=["phone"])

    for addr in profile.get("addresses", []):
        add("address", _source(addr), addr if isinstance(addr, dict)
            else {"value": addr}, relevance=0.7, tags=["address"])

    for platform, url in (profile.get("social_profiles") or {}).items():
        add("social_profile", platform, {"platform": platform, "url": url},
            relevance=0.6, tags=["social", platform])

    for uname in profile.get("usernames", []):
        data = uname if isinstance(uname, dict) else {"value": uname}
        add("username", data.get("platform") or MODULE, data,
            relevance=0.55, tags=["username"])

    for emp in profile.get("employers", []):
        add("employer", _source(emp), emp if isinstance(emp, dict)
            else {"name": emp}, relevance=0.6, tags=["employer"])

    for loc in profile.get("locations", []):
        add("stated_location", _source(loc), loc if isinstance(loc, dict)
            else {"value": loc}, relevance=0.65, tags=["location"])

    for breach in profile.get("breach_data", []):
        add("breach_data", _source(breach, "breach"),
            breach if isinstance(breach, dict) else {"name": breach},
            confidence=0.9, relevance=0.9, anomaly=True, tags=["breach"])

    for img in profile.get("images", []):
        add("profile_image", MODULE, {"url": _value(img, "url")},
            relevance=0.4, tags=["image"])

    results.append({
        "type": "people_profile_summary", "source": MODULE,
        "data": {
            "search_params": profile.get("search_params", {}),
            "sources": profile.get("sources", []),
            "names": len(profile.get("names", [])),
            "emails": len(profile.get("emails", [])),
            "phones": len(profile.get("phones", [])),
            "addresses": len(profile.get("addresses", [])),
            "social_profiles": len(profile.get("social_profiles", {})),
            "usernames": len(profile.get("usernames", [])),
            "breaches": len(profile.get("breach_data", [])),
            "confidence": profile.get("confidence", 0.0),
            "shadow_score": profile.get("shadow_score", 0.0),
        },
        "confidence": 1.0, "relevance_score": 0.85,
        "is_anomaly": False, "tags": ["people", "summary"],
    })
    return results


def _threat_level(score: float, has_breach: bool) -> ThreatLevel:
    """Mirror the engine's score thresholds; a breach is never below suspicious."""
    if score >= 80:
        return ThreatLevel.CRITICAL
    if score >= 60:
        return ThreatLevel.MALICIOUS
    if score >= 35 or has_breach:
        return ThreatLevel.SUSPICIOUS
    if score > 0:
        return ThreatLevel.CLEAN
    return ThreatLevel.UNKNOWN


def persist_profile_scan(profile: Dict, query: Optional[Dict] = None,
                         name: Optional[str] = None) -> Optional[str]:
    """Persist a built profile as a completed ``people_intel`` Scan plus its
    ScanResults and a linked ShadowProfile. Returns the new scan id, or ``None``
    if the profile is empty. Best-effort: logs and returns ``None`` on failure so
    it never breaks the Profiler response."""
    if not profile:
        return None

    query = query or profile.get("search_params") or {}
    target = query_label(query)
    results = profile_to_results(profile)
    score = float(profile.get("shadow_score") or 0.0)
    has_breach = bool(profile.get("breach_data"))
    now = datetime.utcnow()

    try:
        with get_db() as db:
            scan = Scan(
                name=name or f"Profiler — {target[:40]}",
                target=target,
                scan_type=ScanType.PEOPLE_INTEL,
                status=ScanStatus.COMPLETE,
                profile="people",
                modules_enabled=[MODULE],
                options={},
                started_at=now,
                completed_at=now,
                duration_seconds=0.0,
                progress=100,
                shadow_score=score,
                threat_level=_threat_level(score, has_breach),
                tags=["people", "profiler"],
            )
            db.add(scan)
            db.flush()
            scan_id = scan.id

            for item in results:
                db.add(ScanResult(
                    scan_id=scan_id,
                    module=MODULE,
                    result_type=item["type"],
                    source=item.get("source"),
                    data=item.get("data", {}),
                    confidence=item.get("confidence", 1.0),
                    relevance_score=item.get("relevance_score", 0.5),
                    tags=item.get("tags", []),
                    is_anomaly=item.get("is_anomaly", False),
                ))

            db.add(ShadowProfile(
                full_name=(profile.get("names") or [None])[0],
                first_name=query.get("first_name"),
                last_name=query.get("last_name"),
                emails=profile.get("emails", []),
                phones=profile.get("phones", []),
                addresses=profile.get("addresses", []),
                usernames=profile.get("usernames", []),
                social_profiles=profile.get("social_profiles", {}),
                employers=profile.get("employers", []),
                education=profile.get("education", []),
                breach_data=profile.get("breach_data", []),
                images=profile.get("images", []),
                sources=profile.get("sources", []),
                shadow_score=score,
                confidence=float(profile.get("confidence") or 0.0),
                raw_intel=profile.get("raw_results", []),
                scan_id=scan_id,
            ))
        return scan_id
    except Exception:
        logger.exception("Failed to persist profiler scan for %s", target)
        return None
