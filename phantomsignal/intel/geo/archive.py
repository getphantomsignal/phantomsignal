"""
Archived / scrubbed location capture (spec §8 — Wayback).

A location that appeared on a subject's profile in an *old* capture but is gone
now — scrubbed after they went missing — is a strong investigative signal. We
take the subject's social-profile URLs, pull their historical Wayback snapshots,
extract any stated location from the archived page, and mark it ``scrubbed``
when it no longer matches the current profile.

Confidence stays honest (``archived_location`` is a stated-tier kind — being
scrubbed makes it *important*, not more *certain*); the ``scrubbed`` flag in the
signal's provenance is what an investigator acts on. Network is best-effort and
routes through the stealth client (spec §11); it degrades to nothing on failure.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote

from phantomsignal.intel.geo.attribution import record_attribution
from phantomsignal.intel.geo.extract import _CITY_REGION, parse_address
from phantomsignal.intel.geo.places import canonical_key
from phantomsignal.intel.geo.signals import GeoSignal

logger = logging.getLogger("phantomsignal.geo.archive")

CDX = "http://web.archive.org/cdx/search/cdx"
_MAX_URLS = 6            # cap profile URLs we probe per case
_MAX_SNAPS = 2           # oldest N snapshots per URL

# Location as an embedded JSON field ("location":"Denver, CO") — common in
# archived social HTML / JSON-LD — or a labelled bio phrase.
_LOC_JSON = re.compile(r'"location"\s*:\s*"([^"]{2,80})"', re.I)
_LABELLED = re.compile(
    r'(?:based in|lives in|located in|hometown|from)\s+'
    r'([A-Z][A-Za-z .\'-]+,\s*[A-Za-z .]{2,32})', re.I)


def extract_locations_from_text(text: Optional[str]) -> Set[str]:
    """Candidate location strings from archived page text. Pure + testable."""
    out: Set[str] = set()
    for rx in (_LOC_JSON, _LABELLED):
        for m in rx.finditer(text or ""):
            v = " ".join(m.group(1).split()).strip(" .,")
            if 2 < len(v) < 80 and ("," in v or _CITY_REGION.match(v)):
                out.add(v)
    return out


def parse_cdx_snapshots(payload) -> List[Tuple[str, str]]:
    """Wayback CDX rows [timestamp, original] → [(timestamp, snapshot_url)],
    oldest first. First row is the header."""
    rows = payload if isinstance(payload, list) else []
    out: List[Tuple[str, str]] = []
    for row in rows[1:]:
        if isinstance(row, list) and len(row) >= 2 and str(row[0]).isdigit():
            ts, original = row[0], row[1]
            out.append((ts, f"http://web.archive.org/web/{ts}id_/{original}"))
    return out


def _ts_to_date(ts: str) -> Optional[str]:
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else None


def current_place_keys(profile: Dict) -> Set[str]:
    """Canonical keys of the subject's *current* known places — so an archived
    location absent from this set reads as scrubbed/changed."""
    keys: Set[str] = set()
    for loc in profile.get("locations", []) or []:
        val = loc.get("value") if isinstance(loc, dict) and "value" in loc else loc
        place = parse_address(val)
        if place:
            keys.add(canonical_key(place, None, None))
    for addr in profile.get("addresses", []) or []:
        place = parse_address(addr)
        if place:
            keys.add(canonical_key(place, None, None))
    return keys


def _candidate_urls(profile: Dict) -> List[str]:
    urls: List[str] = []
    for u in (profile.get("social_profiles") or {}).values():
        if isinstance(u, str) and u.startswith("http") and u not in urls:
            urls.append(u)
    return urls[:_MAX_URLS]


async def mine_archived_locations(config, profile: Dict) -> List[GeoSignal]:
    """Best-effort: pull archived locations off the subject's profile URLs and
    emit ``archived_location`` signals, flagging those scrubbed since. Never
    raises; returns [] when there's nothing to probe or the network fails."""
    urls = _candidate_urls(profile)
    if not urls:
        return []
    base = float(profile.get("confidence") or 0.5)
    params = profile.get("search_params") or {}
    current = current_place_keys(profile)
    seen: Set[str] = set()
    signals: List[GeoSignal] = []

    try:
        from phantomsignal.core.http import stealth_client
        async with stealth_client(config, timeout=12, verify=True) as client:
            for url in urls:
                try:
                    snaps = await _snapshots(client, url)
                except Exception:
                    continue
                for ts, snap_url in snaps:
                    try:
                        r = await client.get(snap_url)
                        text = r.text
                    except Exception:
                        continue
                    for loc in extract_locations_from_text(text):
                        place = parse_address(loc)
                        if not place or not any(place.values()):
                            continue
                        key = canonical_key(place, None, None)
                        if key in seen:
                            continue
                        seen.add(key)
                        scrubbed = key not in current
                        signals.append(GeoSignal(
                            kind="archived_location", place=place, source="wayback",
                            source_url=snap_url, observed_at=_ts_to_date(ts),
                            attribution_confidence=record_attribution(
                                {"value": loc}, source=url, base=base,
                                kind="archived_location", search_params=params),
                            raw={"scrubbed": scrubbed, "snapshot": ts, "profile_url": url},
                        ))
    except Exception as e:  # pragma: no cover
        logger.debug("archived-location mining failed: %s", e)
    return signals


async def _snapshots(client, url: str) -> List[Tuple[str, str]]:
    q = (f"{CDX}?url={quote(url, safe='')}&output=json&fl=timestamp,original"
         f"&collapse=digest&limit={_MAX_SNAPS}")
    r = await client.get(q)
    return parse_cdx_snapshots(r.json())
