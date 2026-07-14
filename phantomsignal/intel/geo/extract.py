"""
Turn a Profiler ``profile`` dict (from ShadowProfileBuilder) into attributed
GeoSignals. Every signal gets an ``attribution_confidence`` so a location fix on
a weakly-matched record is discounted (spec §6). No network here — pure mapping.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from phantomsignal.intel.geo.attribution import record_attribution
from phantomsignal.intel.geo.signals import GeoSignal

# US-ish "…, City, ST 12345" tail; enough to canonicalise, not to over-claim.
_ADDR_TAIL = re.compile(
    r",\s*([A-Za-z .'-]+?),?\s+([A-Z]{2})\s+(\d{5})(?:-\d{4})?\s*(?:,\s*([A-Za-z .]+))?\s*$"
)
# "Denver, CO" / "Austin, Texas" / "London, UK" — city + region/country, one
# comma, no street number (digits excluded from the city part).
_CITY_REGION = re.compile(r"^([A-Za-z][A-Za-z .'\-]+),\s*([A-Za-z][A-Za-z .]{1,31})$")


def _num(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _coords(d: Dict) -> Tuple[Optional[float], Optional[float]]:
    if not isinstance(d, dict):
        return None, None
    lat = _num(d.get("lat") if d.get("lat") is not None else d.get("latitude"))
    lon = _num(d.get("lon") if d.get("lon") is not None else d.get("longitude"))
    if (lat is None or lon is None) and isinstance(d.get("gps"), dict):
        lat = _num(d["gps"].get("lat") or d["gps"].get("latitude"))
        lon = _num(d["gps"].get("lon") or d["gps"].get("longitude"))
    return lat, lon


def parse_address(addr) -> Optional[Dict]:
    """Normalise a heterogeneous address (dict or string) to a place dict."""
    if isinstance(addr, dict):
        return {
            "city": addr.get("city") or addr.get("locality"),
            "region": addr.get("region") or addr.get("state") or addr.get("province"),
            "zip": addr.get("zip") or addr.get("postal_code") or addr.get("postcode"),
            "country": addr.get("country") or addr.get("country_name"),
        }
    if isinstance(addr, str) and addr.strip():
        s = addr.strip()
        m = _ADDR_TAIL.search(s)
        if m:
            return {"city": m.group(1).strip(), "region": m.group(2),
                    "zip": m.group(3), "country": m.group(4) or "US"}
        # "City, Region" / "City, Country" bio form (no street number) — split so
        # it clusters with structured addresses instead of being one opaque city.
        m2 = _CITY_REGION.match(s)
        if m2:
            return {"city": m2.group(1).strip(), "region": m2.group(2).strip(),
                    "zip": None, "country": None}
        # Fall back to a whole-string place we can still geocode/cluster.
        return {"city": s, "region": None, "zip": None, "country": None}
    return None


def _has_place(p: Optional[Dict]) -> bool:
    return bool(p) and any(p.get(k) for k in ("city", "region", "zip", "country"))


def extract_signals(profile: Dict) -> List[GeoSignal]:
    """Extract attributed GeoSignals from a merged profile dict."""
    signals: List[GeoSignal] = []
    # Overall match confidence is the prior; each record refines it (attribution.py).
    base_attr = float(profile.get("confidence") or 0.5)
    params = profile.get("search_params") or {}

    def _src_of(item, default="people-search"):
        return (item.get("source") if isinstance(item, dict) else None) or default

    def _attr(record, source, kind):
        rec = record if isinstance(record, dict) else {"value": record}
        return record_attribution(rec, source=source, base=base_attr, kind=kind,
                                  search_params=params)

    # Address records — subject-direct, attribution = overall match confidence.
    for addr in profile.get("addresses", []) or []:
        place = parse_address(addr)
        if not _has_place(place):
            continue
        lat, lon = _coords(addr) if isinstance(addr, dict) else (None, None)
        signals.append(GeoSignal(
            kind="address_record", place=place, lat=lat, lon=lon,
            source=_src_of(addr), attribution_confidence=_attr(addr, _src_of(addr), "address_record"),
            observed_at=(addr.get("date") if isinstance(addr, dict) else None),
            raw=addr if isinstance(addr, dict) else {"value": addr},
        ))

    # EXIF GPS from images — a hard fix; attribution tied to how sure the image
    # is the subject's (default: overall match confidence).
    for img in profile.get("images", []) or []:
        lat, lon = _coords(img)
        if lat is None or lon is None:
            continue
        signals.append(GeoSignal(
            kind="exif_gps", place={"country": img.get("country") if isinstance(img, dict) else None},
            lat=lat, lon=lon, source=_src_of(img, "exif"),
            source_url=(img.get("url") if isinstance(img, dict) else None),
            attribution_confidence=_attr(img, _src_of(img, "exif"), "exif_gps"),
            observed_at=(img.get("taken_at") or img.get("date")) if isinstance(img, dict) else None,
            raw=img if isinstance(img, dict) else {"value": img},
        ))

    # Stated locations — bio / profile "location" fields from social sources.
    for loc in profile.get("locations", []) or []:
        src = _src_of(loc, "social")
        place = parse_address(loc.get("value") if isinstance(loc, dict) and "value" in loc else loc)
        if not _has_place(place):
            continue
        signals.append(GeoSignal(
            kind="stated_location", place=place, source=src,
            attribution_confidence=_attr(loc, src, "stated_location"),
            raw=loc if isinstance(loc, dict) else {"value": loc},
        ))

    # Timezone — coarse inferred region hint; surfaced even though it rarely
    # maps to a precise point, so it can corroborate a stated location.
    for tz in profile.get("timezones", []) or []:
        value = tz.get("value") if isinstance(tz, dict) else tz
        if not value:
            continue
        src = _src_of(tz, "session")
        signals.append(GeoSignal(
            kind="timezone", place={"region": str(value)}, source=src,
            attribution_confidence=_attr(tz, src, "timezone"),
            raw=tz if isinstance(tz, dict) else {"value": tz},
        ))

    # Breach-data location/country fields — inferred, low confidence.
    for breach in profile.get("breach_data", []) or []:
        if not isinstance(breach, dict):
            continue
        place = {"city": breach.get("city"), "region": breach.get("state") or breach.get("region"),
                 "country": breach.get("country"), "zip": breach.get("zip")}
        if not _has_place(place):
            continue
        signals.append(GeoSignal(
            kind="breach_field", place=place, source=_src_of(breach, "breach"),
            attribution_confidence=_attr(breach, _src_of(breach, "breach"), "breach_field"), raw=breach,
        ))

    # Phone country → coarse inferred region.
    for phone in profile.get("phones", []) or []:
        country = phone.get("country") if isinstance(phone, dict) else None
        if country:
            signals.append(GeoSignal(
                kind="area_code", place={"country": country},
                source=_src_of(phone, "phone"),
                attribution_confidence=_attr(phone, _src_of(phone, "phone"), "area_code"),
                raw=phone if isinstance(phone, dict) else {"value": phone},
            ))

    # Associates/relatives with a location — the associate kind is already
    # discounted, and attribution to the *subject's* location is weaker still.
    for group in ("associates", "relatives"):
        for person in profile.get(group, []) or []:
            if not isinstance(person, dict):
                continue
            place = parse_address(person.get("address")) if person.get("address") else {
                "city": person.get("city"), "region": person.get("state") or person.get("region"),
                "country": person.get("country"),
            }
            if not _has_place(place):
                continue
            signals.append(GeoSignal(
                kind="associate", place=place, source=_src_of(person, group),
                attribution_confidence=_attr(person, _src_of(person, group), "associate"),
                raw={"name": person.get("name"), "relation": group},
            ))

    return signals
