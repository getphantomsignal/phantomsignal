"""
EXIF GPS capture from a subject's images (spec §8 — the strongest hard fix).

The Profiler collects image URLs (avatars, posted photos) but never fetches
them, so the ``exif_gps`` path in extract.py — which expects coordinates already
present — effectively never fired. This module closes that gap: it fetches the
subject's images, parses EXIF GPS (via the same Pillow parser doc_metadata uses),
and reverse-geocodes the point so the hard fix carries a real place label and
clusters with named locations instead of being a coordinate island.

Best-effort and passive: routes through the stealth client (spec §11), caps the
number/size of images, and degrades to nothing on failure.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

from phantomsignal.intel.geo import places
from phantomsignal.intel.geo.attribution import record_attribution
from phantomsignal.intel.geo.signals import GeoSignal
from phantomsignal.scrapers.doc_metadata import parse_exif_metadata

logger = logging.getLogger("phantomsignal.geo.exif")

_MAX_IMAGES = 12
_MAX_BYTES = 20 * 1024 * 1024        # skip absurdly large fetches
_DT_RE = re.compile(r"(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})")


def _iso_dt(value) -> Optional[str]:
    """EXIF 'YYYY:MM:DD HH:MM:SS' → ISO8601, or None."""
    m = _DT_RE.match(str(value or ""))
    return f"{m[1]}-{m[2]}-{m[3]}T{m[4]}:{m[5]}:{m[6]}" if m else None


def image_geo(raw: bytes) -> Optional[Dict]:
    """Pure: EXIF GPS (+ photo datetime) from image bytes, or None. Testable."""
    meta = parse_exif_metadata(raw)
    gps = meta.get("gps") if isinstance(meta, dict) else None
    if not gps or gps.get("lat") is None or gps.get("lon") is None:
        return None
    return {"lat": gps["lat"], "lon": gps["lon"], "observed_at": _iso_dt(meta.get("datetime"))}


def _image_urls(profile: Dict) -> List[str]:
    urls: List[str] = []
    for u in profile.get("images", []) or []:
        val = u.get("url") if isinstance(u, dict) else u
        if isinstance(val, str) and val.startswith("http") and val not in urls:
            urls.append(val)
    return urls[:_MAX_IMAGES]


async def mine_image_exif(config, profile: Dict) -> List[GeoSignal]:
    """Best-effort: fetch the subject's images, emit ``exif_gps`` signals for any
    with GPS EXIF, reverse-geocoded to a place. Never raises."""
    urls = _image_urls(profile)
    if not urls:
        return []
    base = float(profile.get("confidence") or 0.5)
    params = profile.get("search_params") or {}
    signals: List[GeoSignal] = []

    try:
        from phantomsignal.core.http import stealth_client
        async with stealth_client(config, timeout=12, verify=True) as client:
            for url in urls:
                try:
                    r = await client.get(url)
                    raw = r.content
                except Exception:
                    continue
                if not raw or len(raw) > _MAX_BYTES:
                    continue
                geo = image_geo(raw)
                if not geo:
                    continue
                place = await places.reverse_geocode(config, geo["lat"], geo["lon"]) or {}
                signals.append(GeoSignal(
                    kind="exif_gps", place=place, lat=geo["lat"], lon=geo["lon"],
                    source="exif", source_url=url, observed_at=geo.get("observed_at"),
                    attribution_confidence=record_attribution(
                        {"value": url}, source="exif", base=base,
                        kind="exif_gps", search_params=params),
                    raw={"image": url},
                ))
    except Exception as e:  # pragma: no cover
        logger.debug("EXIF mining failed: %s", e)
    return signals
