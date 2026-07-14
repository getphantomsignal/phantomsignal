"""
Turn a Profiler ``profile`` dict (from ShadowProfileBuilder) into attributed
GeoSignals. Every signal gets an ``attribution_confidence`` so a location fix on
a weakly-matched record is discounted (spec §6). No network here — pure mapping.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from phantomsignal.intel.geo.signals import GeoSignal

# US-ish "…, City, ST 12345" tail; enough to canonicalise, not to over-claim.
_ADDR_TAIL = re.compile(
    r",\s*([A-Za-z .'-]+?),?\s+([A-Z]{2})\s+(\d{5})(?:-\d{4})?\s*(?:,\s*([A-Za-z .]+))?\s*$"
)


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
        m = _ADDR_TAIL.search(addr)
        if m:
            return {"city": m.group(1).strip(), "region": m.group(2),
                    "zip": m.group(3), "country": m.group(4) or "US"}
        # Fall back to a whole-string place we can still geocode/cluster.
        return {"city": addr.strip(), "region": None, "zip": None, "country": None}
    return None


def _has_place(p: Optional[Dict]) -> bool:
    return bool(p) and any(p.get(k) for k in ("city", "region", "zip", "country"))


def extract_signals(profile: Dict) -> List[GeoSignal]:
    """Extract attributed GeoSignals from a merged profile dict."""
    signals: List[GeoSignal] = []
    # Overall match confidence is the attribution baseline for subject-direct data.
    base_attr = float(profile.get("confidence") or 0.5)

    def _src_of(item, default="people-search"):
        return (item.get("source") if isinstance(item, dict) else None) or default

    # Address records — subject-direct, attribution = overall match confidence.
    for addr in profile.get("addresses", []) or []:
        place = parse_address(addr)
        if not _has_place(place):
            continue
        lat, lon = _coords(addr) if isinstance(addr, dict) else (None, None)
        signals.append(GeoSignal(
            kind="address_record", place=place, lat=lat, lon=lon,
            source=_src_of(addr), attribution_confidence=base_attr,
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
            attribution_confidence=base_attr,
            observed_at=(img.get("taken_at") or img.get("date")) if isinstance(img, dict) else None,
            raw=img if isinstance(img, dict) else {"value": img},
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
            attribution_confidence=base_attr * 0.9, raw=breach,
        ))

    # Phone country → coarse inferred region.
    for phone in profile.get("phones", []) or []:
        country = phone.get("country") if isinstance(phone, dict) else None
        if country:
            signals.append(GeoSignal(
                kind="area_code", place={"country": country},
                source=_src_of(phone, "phone"), attribution_confidence=base_attr * 0.8,
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
                attribution_confidence=base_attr * 0.5,
                raw={"name": person.get("name"), "relation": group},
            ))

    return signals
