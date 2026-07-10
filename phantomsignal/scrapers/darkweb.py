"""
PhantomSignal Dark-Web Monitor — Leak Exposure Tracking

Phase 4 (identity / dark web). Defensive exposure monitoring for an authorized
target: does the org appear on a ransomware leak site? This is part 1 — keyless,
clearnet, high-signal (>50% of modern breaches surface on leak sites). Part 2
adds Tor .onion crawling, paste sweeps, and stealer-log correlation.

Guardrails (enforced here and by design for part 2):
  • target-scoped — results are filtered to the authorized target, not bulk data.
  • no credential store — we report the FACT of exposure; any credential-shaped
    value is redacted via mask_secret() (never store/emit plaintext secrets).

Source: ransomware.live v2 API (keyless). Design: HTTP I/O in the class; parsing,
target-scoping, and masking are pure module-level functions with unit tests.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger("phantomsignal.scrapers.darkweb")

RANSOMWARE_API = "https://api.ransomware.live/v2"

_HOST_RE = re.compile(r"^(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


# ── pure helpers (unit-tested) ──────────────────────────────────────────────

def mask_secret(value: str) -> str:
    """
    Redact a credential-shaped value: report only that a secret exists and its
    length, never any plaintext. Used for stolen-credential exposure so the tool
    stays a breach-EXPOSURE monitor, not a credential store.
    """
    if not value:
        return ""
    return f"[redacted:{len(str(value))}]"


def extract_domain(target: str) -> Optional[str]:
    t = (target or "").strip().lower()
    t = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].split("@")[-1]
    return t if t and _HOST_RE.match(t) else None


def registered_name(domain: str) -> str:
    """Second-level label used as the leak-site search query (eTLD+1 minus suffix)."""
    try:
        import tldextract
        ext = tldextract.extract(domain)
        if ext.domain:
            return ext.domain.lower()
    except Exception:
        pass
    parts = (domain or "").lower().split(".")
    return parts[-2] if len(parts) >= 2 else (domain or "").lower()


def parse_ransomware_victims(payload) -> List[Dict]:
    """Normalize ransomware.live v2 victim records to the fields we surface."""
    if not isinstance(payload, list):
        return []
    out: List[Dict] = []
    for rec in payload:
        if not isinstance(rec, dict):
            continue
        out.append({
            "victim":      (rec.get("victim") or "").strip(),
            "group":       (rec.get("group") or "").strip(),
            "domain":      (rec.get("domain") or "").strip().lower(),
            "attack_date": rec.get("attackdate") or "",
            "discovered":  rec.get("discovered") or "",
            "country":     rec.get("country") or "",
            "activity":    rec.get("activity") or "",
            "claim_url":   rec.get("claim_url") or "",
            "record_url":  rec.get("url") or "",
            "infostealer": bool(rec.get("infostealer")),
        })
    return out


def _is_junk_victim(name: str) -> bool:
    """A real org name never contains HTML/markup artifacts — ransomware.live
    occasionally scrapes such fragments; they must not drive a name match."""
    return (not name) or any(c in name for c in "<>=")


def victim_matches_target(record: Dict, domain: str) -> Optional[str]:
    """
    Scope a fuzzy leak-site hit to the authorized target. Returns the match
    strength ("domain" | "name") or None. Domain match is reliable; name match is
    advisory (fuzzy search on a common brand is noisy), and junk victim strings
    are rejected. The searchvictims endpoint fuzzy-matches names, so we confirm
    the hit actually concerns this target before reporting.
    """
    dom = (domain or "").lower()
    sld = registered_name(dom)
    rec_domain = (record.get("domain") or "").lower()
    if rec_domain and (rec_domain == dom or rec_domain.endswith("." + dom) or dom.endswith("." + rec_domain)):
        return "domain"
    victim = (record.get("victim") or "").lower()
    if _is_junk_victim(victim):
        return None
    if sld and len(sld) >= 3 and re.search(rf"\b{re.escape(sld)}\b", victim):
        return "name"
    return None


class DarkWebMonitor:
    """Keyless, clearnet leak-exposure monitoring for an authorized target."""

    def __init__(self, config):
        self.config      = config
        self.timeout     = config.get("darkweb", "timeout",     default=20)
        self.max_results = config.get("darkweb", "max_results", default=50)

    async def run(self, target: str) -> List[Dict]:
        domain = extract_domain(target)
        if not domain:
            return []
        matches = await self._ransomware_leaks(domain)
        return self._build_results(domain, matches)

    async def _ransomware_leaks(self, domain: str) -> List[Dict]:
        query = registered_name(domain)
        if not query:
            return []
        url = f"{RANSOMWARE_API}/searchvictims/{quote(query)}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True,
                headers={"User-Agent": "PhantomSignal-OSINT/1.0"},
            ) as client:
                r = await client.get(url)
                payload = r.json() if r.status_code == 200 else []
        except Exception as exc:
            logger.debug("ransomware.live query failed for %s: %s", domain, exc)
            return []

        scoped: List[Dict] = []
        for rec in parse_ransomware_victims(payload):
            strength = victim_matches_target(rec, domain)
            if strength:
                rec["match"] = strength
                scoped.append(rec)
        return scoped[:self.max_results]

    def _build_results(self, domain: str, matches: List[Dict]) -> List[Dict]:
        results: List[Dict] = []
        for rec in matches:
            results.append({
                "type":   "ransomware_exposure",
                "source": "darkweb",
                "data": {
                    "target":      domain,
                    "victim":      rec["victim"],
                    "group":       rec["group"],
                    "attack_date": rec["attack_date"],
                    "discovered":  rec["discovered"],
                    "country":     rec["country"],
                    "activity":    rec["activity"],
                    "claim_url":   rec["claim_url"],
                    "record_url":  rec["record_url"],
                    "has_infostealer_data": rec["infostealer"],
                    "match":       rec["match"],
                },
                # a domain-confirmed leak is near-certain; a name match is weaker
                "confidence":      0.95 if rec["match"] == "domain" else 0.6,
                "relevance_score": 1.0 if rec["match"] == "domain" else 0.7,
                "tags":            ["darkweb", "ransomware", "leak", "breach"],
                # only a domain-confirmed hit is a real alert; a fuzzy name match
                # is advisory and must not raise a false anomaly.
                "is_anomaly":      rec["match"] == "domain",
            })

        results.append({
            "type":   "darkweb_summary",
            "source": "darkweb",
            "data": {
                "target":            domain,
                "ransomware_hits":   len(matches),
                "domain_confirmed":  sum(1 for m in matches if m["match"] == "domain"),
                "name_matches":      sum(1 for m in matches if m["match"] == "name"),
                "groups":            sorted({m["group"] for m in matches if m["group"]}),
                "sources_checked":   ["ransomware.live"],
            },
            "confidence":      1.0,
            "relevance_score": 0.8 if matches else 0.4,
            "tags":            ["darkweb", "summary"],
            # a confirmed leak is the alert; name-only fuzzy hits don't raise one
            "is_anomaly":      any(m["match"] == "domain" for m in matches),
        })
        return results
