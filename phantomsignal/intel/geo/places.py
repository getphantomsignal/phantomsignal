"""
Place canonicalisation + (optional, best-effort) geocoding.

Clustering only works if "NYC", "New York, NY", and a Manhattan lat/lon collapse
to one place (spec §12). We canonicalise to a stable key; when coordinates exist
they win (rounded to a ~city grid), else we use the normalised place tuple.

Geocoding is optional: it enriches string places with coordinates via Nominatim,
routed through the stealth client and cached. It degrades to None on any failure
so the compute path never depends on the network.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

_WS = re.compile(r"\s+")


def _norm(s) -> str:
    return _WS.sub(" ", str(s or "").strip().lower())


def canonical_key(place: Optional[Dict], lat: Optional[float], lon: Optional[float]) -> str:
    """Stable clustering key. Coordinates (rounded to ~city grid) take priority."""
    if lat is not None and lon is not None:
        return f"@{round(lat, 1)},{round(lon, 1)}"
    place = place or {}
    parts = [_norm(place.get(k)) for k in ("city", "region", "country")]
    key = "|".join(p for p in parts if p)
    if key:
        return key
    zp = _norm(place.get("zip"))
    return f"zip:{zp}" if zp else "unknown"


def display_place(place: Optional[Dict]) -> str:
    place = place or {}
    bits = [place.get("city"), place.get("region"), place.get("country")]
    label = ", ".join(str(b) for b in bits if b)
    zp = place.get("zip")
    if zp and str(zp) not in label:
        label = f"{label} {zp}".strip()
    return label or "unknown"


_GEO_CACHE: Dict[str, Optional[Tuple[float, float]]] = {}


async def geocode(config, place: Dict) -> Optional[Tuple[float, float]]:
    """Best-effort forward geocode of a place dict → (lat, lon). Cached; routed
    through the stealth client; returns None on any problem."""
    query = display_place(place)
    if not query or query == "unknown":
        return None
    if query in _GEO_CACHE:
        return _GEO_CACHE[query]

    coords: Optional[Tuple[float, float]] = None
    try:
        from phantomsignal.core.http import stealth_client
        async with stealth_client(config, timeout=8, verify=True) as c:
            r = await c.get(
                "https://nominatim.openstreetmap.org/search",
                params={"q": query, "format": "json", "limit": 1},
            )
            data = r.json()
            if data:
                coords = (float(data[0]["lat"]), float(data[0]["lon"]))
    except Exception:
        coords = None
    _GEO_CACHE[query] = coords
    return coords
