"""
Pattern-of-life + prioritized search grid (spec §7 / §9 — Phase 2).

Temporal clustering separates **home** (nights/weekends), **work** (weekday
daytime), and **frequented** places from the signals' timestamps — usually the
real payoff, and what a prioritized "where to look next" grid is built from.

Timestamps are heterogeneous: many signals are date-only. We use time-of-day /
day-of-week when present and fall back to frequency + kind evidence otherwise,
and we say which evidence drove each label rather than over-claiming.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from phantomsignal.intel.geo.aggregate import _parse_dt, _recency_weight

# Residential vs workplace lean by signal kind, when the clock can't decide.
_HOME_KINDS = frozenset({"address_record", "breach_field"})
# Priority weight per pattern-of-life label — drives the search grid ranking.
_POL_WEIGHT = {"home": 1.0, "work": 0.8, "frequented": 0.65, "seen": 0.45}


def _is_night(dt: datetime) -> bool:
    return dt.hour >= 20 or dt.hour < 7                    # any day, evening/overnight


def _is_work_hours(dt: datetime) -> bool:
    return dt.weekday() < 5 and 9 <= dt.hour < 18          # weekday daytime


def _is_leisure(dt: datetime) -> bool:
    return dt.weekday() >= 5 and not _is_night(dt)         # weekend daytime


def _has_clock(dt_str: Optional[str]) -> bool:
    """True when a timestamp carries a real time-of-day (not just a date)."""
    return bool(dt_str) and ("T" in str(dt_str) or ":" in str(dt_str))


def classify_places(clusters: List[Dict], signals: List[Dict]) -> None:
    """Annotate each positive cluster in place with ``pol`` + ``pol_reason``.

    ``signals`` are signal dicts (``to_dict()`` shape) carrying ``place_key``,
    ``observed_at`` and ``kind``.
    """
    by_key: Dict[str, List[Dict]] = {}
    for s in signals:
        if s.get("polarity") == "negative":
            continue
        by_key.setdefault(s.get("place_key"), []).append(s)

    for c in clusters:
        if c.get("eliminated"):
            c["pol"], c["pol_reason"] = None, "eliminated"
            continue
        members = by_key.get(c["place_key"], [])
        visits = len(members)
        residential = any(s.get("kind") in _HOME_KINDS for s in members)
        clock = [dt for dt, s in ((_parse_dt(s.get("observed_at")), s) for s in members)
                 if dt and _has_clock(s.get("observed_at"))]
        night = sum(1 for dt in clock if _is_night(dt))
        work = sum(1 for dt in clock if _is_work_hours(dt))
        leisure = sum(1 for dt in clock if _is_leisure(dt))

        # A residential record or repeated night presence => home. Repeated
        # weekday-daytime => work. Repeat visits without a clear signature =>
        # frequented. A lone sighting stays "seen" — we don't over-claim.
        if residential:
            label, reason = "home", "residential record"
        elif night >= 2 and night >= work:
            label, reason = "home", f"{night} night fixes"
        elif work >= 2 or (work >= 1 and work > night and work >= leisure):
            label, reason = "work", f"{work} weekday-daytime fix(es)"
        elif night >= 1 and night >= work and night >= leisure and visits >= 2:
            label, reason = "home", f"{night} night fix(es)"
        elif visits >= 2:
            label, reason = "frequented", f"{visits} sightings"
        else:
            label, reason = "seen", "single sighting"
        c["pol"], c["pol_reason"] = label, reason


def search_grid(clusters: List[Dict], signals: List[Dict]) -> List[Dict]:
    """Ranked 'where to look next' list: priority = confidence × recency ×
    pattern weight. Home/work outrank a stale one-off; eliminated areas drop."""
    now = datetime.now(timezone.utc)
    recency_by_key: Dict[str, float] = {}
    for s in signals:
        if s.get("polarity") == "negative":
            continue
        w = _recency_weight(s.get("observed_at"), now)
        k = s.get("place_key")
        recency_by_key[k] = max(recency_by_key.get(k, 0.0), w)

    grid = []
    for c in clusters:
        if c.get("eliminated") or c["combined_confidence"] <= 0:
            continue
        pol = c.get("pol") or "seen"
        recency = recency_by_key.get(c["place_key"], 0.5)
        score = c["combined_confidence"] * (0.5 + 0.5 * recency) * _POL_WEIGHT.get(pol, 0.45)
        grid.append({
            "label": c["label"],
            "place_key": c["place_key"],
            "lat": c.get("lat"), "lon": c.get("lon"),
            "pol": pol,
            "pol_reason": c.get("pol_reason"),
            "confidence": c["combined_confidence"],
            "radius_km": c.get("radius_km"),
            "score": round(score, 4),
            "why": f"{pol} · {c.get('pol_reason')} · {c['signal_count']} signal(s) "
                   f"[{', '.join(c.get('kinds', []))}]",
        })
    grid.sort(key=lambda g: g["score"], reverse=True)
    return grid
