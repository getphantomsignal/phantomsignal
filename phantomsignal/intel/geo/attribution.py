"""
Per-record attribution (spec §6 core rule + §15.5 contract).

``attribution_confidence`` is the certainty that a located record belongs to the
*subject* (not a namesake or a loose pivot). It is the second half of the
compound confidence: a perfect EXIF fix on a record we're only 40% sure is the
subject is a 0.4-ish location, not a 0.95 one.

Rather than stamping every signal with one blanket profile-level number, we
derive it per record:

1. **Explicit match** — if the source hands up its own per-record match
   (``match_confidence`` / ``attribution_confidence`` / ``match`` / ``confidence``
   / ``score``; 0..1 or 0..100), that is the primary signal.
2. **Prior** — otherwise the profile's overall match confidence.
3. **Kind directness** — an associate's location ties to the subject far more
   weakly than a subject-direct address; a phone-country tie is coarse.
4. **Source directness** — records from username/profile *pivots* can land on a
   namesake, so they are discounted.
5. **Self-corroboration** — a record that independently echoes a searched
   identifier (the case's email / username) verifiably concerns the subject, so
   its remaining doubt is halved.

This is the small contract the clustering depends on; keep it here so
``profile_pivot`` / ``username_enum`` can populate the recognised keys.
"""
from __future__ import annotations

from typing import Dict, Optional

# Per-record match keys a source may declare, in priority order.
_MATCH_KEYS = ("match_confidence", "attribution_confidence", "match", "confidence", "score")

# How directly a *kind* of location ties to the subject (default 1.0).
_KIND_DIRECTNESS = {"associate": 0.5, "area_code": 0.8, "breach_field": 0.9}

# Sources that discover records by pivoting/enumerating handles — a real hit on
# the wrong person (namesake / reused handle) is plausible, so discount them.
_PIVOT_SOURCES = frozenset({"username_enum", "profile_pivot", "sherlock", "maigret"})
_PIVOT_FACTOR = 0.85


def _norm_match(v) -> Optional[float]:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if f > 1.0:                       # looks like a 0..100 percentage
        f /= 100.0
    return max(0.0, min(1.0, f))


def explicit_match(record) -> Optional[float]:
    """The per-record match a source declared, normalised to 0..1, or None."""
    if not isinstance(record, dict):
        return None
    for k in _MATCH_KEYS:
        if record.get(k) is not None:
            m = _norm_match(record[k])
            if m is not None:
                return m
    return None


def _echoes_identifier(record, search_params: Dict) -> bool:
    """True when the record independently contains the searched email or
    username — strong evidence it's the subject, not a namesake. Name-only
    echoes are deliberately ignored (namesakes share names)."""
    if not isinstance(record, dict):
        return False
    idents = [str(search_params.get(k)).lower()
              for k in ("email", "username") if search_params.get(k)]
    if not idents:
        return False
    blob = " ".join(str(v).lower() for v in record.values() if isinstance(v, (str, int, float)))
    return any(i in blob for i in idents)


def record_attribution(record, *, source: str, base: float, kind: str,
                       search_params: Optional[Dict] = None) -> float:
    """Certainty a located record belongs to the subject, in [0, 1]."""
    m = explicit_match(record)
    attr = m if m is not None else max(0.0, min(1.0, float(base)))

    attr *= _KIND_DIRECTNESS.get(kind, 1.0)
    if (source or "").lower() in _PIVOT_SOURCES:
        attr *= _PIVOT_FACTOR
    if search_params and _echoes_identifier(record, search_params):
        attr = 1.0 - (1.0 - attr) * 0.5      # halve the remaining doubt

    return round(max(0.0, min(1.0, attr)), 3)
