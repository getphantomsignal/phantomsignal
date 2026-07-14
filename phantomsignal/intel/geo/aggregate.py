"""
Aggregate GeoSignals into a footprint: canonicalise + cluster by place, apply
corroboration, pick a last-known location, and surface conflicts rather than
hiding them (spec §6/§7).
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Dict, List, Optional

from phantomsignal.intel.geo.places import canonical_key, display_place
from phantomsignal.intel.geo.signals import GeoSignal, combine_confidence

# Above this combined effective confidence, two clusters in different places are
# a genuine conflict worth showing (not just noise).
_CONFLICT_FLOOR = 0.6
# Recency half-life for weighting the last-known choice (days).
_HALF_LIFE_DAYS = 365.0


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _recency_weight(observed_at: Optional[str], now: datetime) -> float:
    dt = _parse_dt(observed_at)
    if dt is None:
        return 0.5   # unknown time — neither fresh nor stale
    age_days = max(0.0, (now - dt).total_seconds() / 86400.0)
    return 0.5 ** (age_days / _HALF_LIFE_DAYS)


def cluster(signals: List[GeoSignal]) -> List[Dict]:
    """Group by canonical place; combine confidence within each positive cluster."""
    for s in signals:
        s.place_key = canonical_key(s.place, s.lat, s.lon)

    groups: Dict[str, List[GeoSignal]] = {}
    for s in signals:
        groups.setdefault(s.place_key, []).append(s)

    # Corroboration: within a cluster, positive signals corroborate each other.
    clusters = []
    for key, members in groups.items():
        positives = [m for m in members if m.polarity == "positive"]
        negatives = [m for m in members if m.polarity == "negative"]
        for m in positives:
            m.corroborated_by = [o.id for o in positives if o.id != m.id]
        combined = combine_confidence([m.effective_confidence for m in positives])
        # Distinct independent sources strengthen corroboration signal quality.
        sources = sorted({m.source for m in positives})
        place = next((m.place for m in members if any(m.place.values())), members[0].place)
        clusters.append({
            "place_key": key,
            "place": place,
            "label": display_place(place),
            "lat": next((m.lat for m in positives if m.lat is not None), None),
            "lon": next((m.lon for m in positives if m.lon is not None), None),
            "combined_confidence": combined,
            "signal_count": len(positives),
            "eliminated": bool(negatives) and not positives,
            "negated_by": [n.id for n in negatives],
            "sources": sources,
            "signal_ids": [m.id for m in members],
            "kinds": sorted({m.kind for m in positives}),
        })
    clusters.sort(key=lambda c: c["combined_confidence"], reverse=True)
    return clusters


def last_known(clusters: List[Dict], signals: List[GeoSignal]) -> Optional[Dict]:
    """Best current estimate = cluster maximising combined_confidence × recency."""
    now = datetime.now(timezone.utc)
    by_id = {s.id: s for s in signals}
    best, best_score = None, -1.0
    for c in clusters:
        if c.get("eliminated") or c["combined_confidence"] <= 0:
            continue
        recency = max((_recency_weight(by_id[i].observed_at, now)
                       for i in c["signal_ids"] if i in by_id), default=0.5)
        score = c["combined_confidence"] * recency
        if score > best_score:
            best, best_score = c, score
    if not best:
        return None
    # Radius: tight when we have a corroborated hard fix, wide for lone/coarse.
    hard = any(k in ("exif_gps", "geotag", "checkin", "bssid") for k in best["kinds"])
    if hard and best["signal_count"] > 1:
        radius = 2.0
    elif hard:
        radius = 10.0
    elif best["combined_confidence"] >= 0.6:
        radius = 25.0
    else:
        radius = 75.0
    as_of = max((by_id[i].observed_at for i in best["signal_ids"]
                 if i in by_id and by_id[i].observed_at), default=None)
    return {
        "place": best["place"],
        "label": best["label"],
        "lat": best["lat"], "lon": best["lon"],
        "radius_km": radius,
        "confidence": best["combined_confidence"],
        "corroboration": best["signal_count"],
        "sources": best["sources"],
        "as_of": as_of,
    }


def _haversine_km(a, b) -> float:
    (lat1, lon1), (lat2, lon2) = a, b
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


def conflicts(clusters: List[Dict], signals: List[GeoSignal]) -> List[Dict]:
    """Surface disagreement: (a) two strong clusters in different places, and
    (b) travel-infeasible pairs of timed+located hard fixes."""
    out: List[Dict] = []

    strong = [c for c in clusters if c["combined_confidence"] >= _CONFLICT_FLOOR and not c.get("eliminated")]
    for i in range(len(strong)):
        for j in range(i + 1, len(strong)):
            out.append({
                "type": "competing_locations",
                "places": [strong[i]["label"], strong[j]["label"]],
                "confidence": [strong[i]["combined_confidence"], strong[j]["combined_confidence"]],
                "detail": "two high-confidence locations disagree — verify before acting",
            })

    # Travel feasibility on timed, located positive signals.
    timed = [s for s in signals
             if s.polarity == "positive" and s.lat is not None and s.lon is not None
             and _parse_dt(s.observed_at) is not None]
    timed.sort(key=lambda s: _parse_dt(s.observed_at))
    for a, b in zip(timed, timed[1:]):
        dt_h = abs((_parse_dt(b.observed_at) - _parse_dt(a.observed_at)).total_seconds()) / 3600.0
        dist = _haversine_km((a.lat, a.lon), (b.lat, b.lon))
        if dt_h < 24 and dist > 50:
            speed = dist / dt_h if dt_h else float("inf")
            if speed > 900:   # faster than a commercial flight — implausible
                out.append({
                    "type": "travel_infeasible",
                    "detail": f"{dist:.0f} km in {dt_h:.1f} h (~{speed:.0f} km/h) — "
                              "one fix is likely wrong, spoofed, or a shared account",
                    "signals": [a.id, b.id],
                })
    return out
