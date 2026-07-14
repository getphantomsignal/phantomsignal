"""
Geo Recon (spec §1 / §4 / §13) — the asset side of Geo: *place → internet-facing
assets*. A geocoding + query layer over Shodan geo filters, correlated with the
enrichment PhantomSignal already does.

This is infrastructure, not people — the inverse (location → who is there) stays
out of scope for the person pipeline by design. Scope a run to an authorized
target/org.

Pure query-building / dedupe / summary here; the async ``recon`` orchestrates
geocoding + the Shodan call.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

from phantomsignal.intel.geo import places

logger = logging.getLogger("phantomsignal.geo.recon")

_LATLON = re.compile(r"^\s*(-?\d{1,3}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*$")


def _q(s: str) -> str:
    return s.replace('"', "").strip()


def build_query(*, country: Optional[str] = None, city: Optional[str] = None,
                lat: Optional[float] = None, lon: Optional[float] = None,
                radius_km: Optional[float] = None, org: Optional[str] = None,
                domain: Optional[str] = None) -> str:
    """Compose a Shodan geo query from the scoped inputs. Coordinates win as a
    radius search; otherwise city/country filters, plus org/domain scope."""
    terms: List[str] = []
    if lat is not None and lon is not None:
        r = radius_km if radius_km and radius_km > 0 else 25
        terms.append(f'geo:"{lat},{lon},{min(r, 100)}"')     # Shodan caps radius at 100 km
    else:
        if city:
            terms.append(f'city:"{_q(city)}"')
        if country:
            terms.append(f"country:{_q(country)[:2].upper()}")
    if org:
        terms.append(f'org:"{_q(org)}"')
    if domain:
        terms.append(f'hostname:"{_q(domain)}"')
    return " ".join(terms)


def parse_latlon(value: Optional[str]) -> Optional[Tuple[float, float]]:
    if not value:
        return None
    m = _LATLON.match(value)
    return (float(m.group(1)), float(m.group(2))) if m else None


def dedupe(matches: List[Dict]) -> List[Dict]:
    """One row per (ip, port); sort vulnerable + well-known assets first."""
    seen = set()
    out = []
    for m in matches:
        key = (m.get("ip"), m.get("port"))
        if key in seen or not m.get("ip"):
            continue
        seen.add(key)
        out.append(m)
    out.sort(key=lambda a: (-len(a.get("vulns") or []), a.get("port") or 0))
    return out


def summarize(assets: List[Dict]) -> Dict:
    def _top(field):
        counts: Dict[str, int] = {}
        for a in assets:
            v = a.get(field)
            if v:
                counts[v] = counts.get(v, 0) + 1
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    vulns = sorted({v for a in assets for v in (a.get("vulns") or [])})
    return {
        "assets": len(assets),
        "hosts": len({a.get("ip") for a in assets if a.get("ip")}),
        "ports": _top("port"),
        "orgs": _top("org"),
        "products": _top("product"),
        "countries": _top("country"),
        "vulns": vulns,
        "vuln_hosts": len({a.get("ip") for a in assets if a.get("vulns")}),
    }


class GeoReconEngine:
    def __init__(self, config):
        self.config = config

    async def recon(self, *, country=None, city=None, lat=None, lon=None,
                    radius_km=None, org=None, domain=None) -> Dict:
        """Geocode the place if needed, run the Shodan geo query, dedupe +
        summarize. Degrades to an empty, ``configured=False`` result without a
        Shodan key."""
        center: Optional[Tuple[float, float]] = None
        if lat is not None and lon is not None:
            center = (lat, lon)
        elif city:
            try:
                center = await places.geocode(self.config, {"city": city, "country": country})
            except Exception:
                center = None

        query = build_query(country=country, city=city, lat=lat, lon=lon,
                            radius_km=radius_km, org=org, domain=domain)
        if not query:
            return {"query": None, "center": center, "configured": True,
                    "total": 0, "assets": [], "summary": summarize([])}

        try:
            from phantomsignal.intel.apis.shodan_api import ShodanAPI
            res = await ShodanAPI(self.config).geo_search(query)
        except Exception as e:  # pragma: no cover
            logger.debug("geo recon shodan call failed: %s", e)
            res = {"total": 0, "matches": [], "configured": False, "error": str(e)}

        assets = dedupe(res.get("matches", []))
        return {
            "query": query,
            "center": center,
            "configured": res.get("configured", False),
            "error": res.get("error"),
            "total": res.get("total", 0),
            "assets": assets,
            "summary": summarize(assets),
        }
