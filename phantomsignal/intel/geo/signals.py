"""
GeoSignal — one located observation, with compound (attribution-aware) confidence.

The core correctness rule (spec §6): a location is only as trustworthy as our
certainty that the observation is real (``kind_confidence``) AND that it belongs
to the subject (``attribution_confidence``). Effective confidence is their
product, then raised by independent corroboration.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# kind -> base confidence that the observation itself is a real location fix.
KIND_CONFIDENCE: Dict[str, float] = {
    # hard fixes
    "exif_gps": 0.95, "geotag": 0.90, "checkin": 0.88, "bssid": 0.90,
    # stated / recorded
    "address_record": 0.65, "stated_location": 0.60,
    "archived_location": 0.55, "news_mention": 0.50,
    # inferred
    "area_code": 0.35, "asn_region": 0.30, "breach_field": 0.30,
    "timezone": 0.25, "associate": 0.25,
}

HARD_KINDS = frozenset({"exif_gps", "geotag", "checkin", "bssid"})

# decimals of lat/lon precision we allow to be shown per tier — never imply more
# precision than the signal supports (spec §12).
_PRECISION = {"hard": 4, "stated": 2, "inferred": 1}


def _tier(kind: str) -> str:
    if kind in HARD_KINDS:
        return "hard"
    if KIND_CONFIDENCE.get(kind, 0.2) >= 0.45:
        return "stated"
    return "inferred"


def round_to_confidence(kind: str, value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    return round(value, _PRECISION[_tier(kind)])


@dataclass
class GeoSignal:
    kind: str
    place: Dict                                   # {city, region, country, zip}
    source: str
    source_url: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    observed_at: Optional[str] = None             # ISO8601 when known
    attribution_confidence: float = 1.0           # certainty it's the subject
    polarity: str = "positive"                    # positive | negative
    entry: str = "auto"                           # auto | manual
    raw: Optional[dict] = None
    place_key: Optional[str] = None               # canonical (set by aggregate)
    corroborated_by: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        self.lat = round_to_confidence(self.kind, self.lat)
        self.lon = round_to_confidence(self.kind, self.lon)
        self.attribution_confidence = max(0.0, min(1.0, float(self.attribution_confidence)))

    @property
    def kind_confidence(self) -> float:
        return KIND_CONFIDENCE.get(self.kind, 0.20)

    @property
    def effective_confidence(self) -> float:
        """Real × belongs-to-subject. The load-bearing number."""
        return round(self.kind_confidence * self.attribution_confidence, 4)

    @property
    def tier(self) -> str:
        return _tier(self.kind)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "tier": self.tier,
            "polarity": self.polarity,
            "entry": self.entry,
            "place": self.place,
            "lat": self.lat,
            "lon": self.lon,
            "observed_at": self.observed_at,
            "source": self.source,
            "source_url": self.source_url,
            "kind_confidence": self.kind_confidence,
            "attribution_confidence": round(self.attribution_confidence, 3),
            "effective_confidence": self.effective_confidence,
            "corroborated_by": self.corroborated_by,
            "place_key": self.place_key,
            # A location present in an archive but gone from the current profile
            # (spec §8) — important, not more certain; drives the UI/report flag.
            "scrubbed": bool((self.raw or {}).get("scrubbed")),
        }


def combine_confidence(effectives: List[float]) -> float:
    """Independent corroboration: P(at least one right) = 1 - Π(1 - e_i).

    Two 0.6 signals agreeing => 0.84, stronger than either alone; a lone 0.95
    still beats a pile of weak inferred hints."""
    prod = 1.0
    for e in effectives:
        prod *= (1.0 - max(0.0, min(1.0, e)))
    return round(1.0 - prod, 4)
