"""
PhantomSignal Profile Pivot — Recursive Identity Expansion

Phase 4 (identity). Takes the handles/profiles surfaced by username enumeration
and mines each profile page for *linked* identities the person publishes about
themselves: cross-linked handles on other platforms, emails, personal domains,
and gravatar avatar hashes. Handles linked from multiple confirmed profiles are
high-confidence the same person. Optionally re-enumerates newly found handles
one hop deeper (bounded), turning a single seed handle into an identity graph.

Design: the identifier extractor is pure and unit-tested; the engine composes an
(injectable) username enumerator + HTTP fetch around it, with depth/budget/dedup
guards mirroring the entity `RecursivePivotEngine`.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx

from phantomsignal.scrapers.username_enum import (
    UsernameEnumerator, clean_username, is_valid_username,
)

logger = logging.getLogger("phantomsignal.intel.profile_pivot")

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
# hrefs and bare URLs
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_GRAVATAR_RE = re.compile(r"gravatar\.com/avatar/([0-9a-fA-F]{32})")

# Profile-URL shapes → (platform, handle). Ordered; first match wins per URL.
_SOCIAL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("github", re.compile(r"github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))(?:[/?#]|$)")),
    ("gitlab", re.compile(r"gitlab\.com/([A-Za-z0-9][A-Za-z0-9_.\-]{0,38})(?:[/?#]|$)")),
    ("twitter", re.compile(r"(?:twitter|x)\.com/([A-Za-z0-9_]{1,15})(?:[/?#]|$)")),
    ("reddit", re.compile(r"reddit\.com/u(?:ser)?/([A-Za-z0-9_\-]{3,20})(?:[/?#]|$)")),
    ("instagram", re.compile(r"instagram\.com/([A-Za-z0-9_.]{1,30})(?:[/?#]|$)")),
    ("telegram", re.compile(r"t\.me/([A-Za-z0-9_]{5,32})(?:[/?#]|$)")),
    ("linkedin", re.compile(r"linkedin\.com/in/([A-Za-z0-9\-]{3,100})(?:[/?#]|$)")),
    ("tiktok", re.compile(r"tiktok\.com/@([A-Za-z0-9_.]{1,24})(?:[/?#]|$)")),
    ("youtube", re.compile(r"youtube\.com/@([A-Za-z0-9_.\-]{1,30})(?:[/?#]|$)")),
    ("facebook", re.compile(r"facebook\.com/([A-Za-z0-9.]{5,50})(?:[/?#]|$)")),
    ("keybase", re.compile(r"keybase\.io/([A-Za-z0-9_]{1,25})(?:[/?#]|$)")),
    ("medium", re.compile(r"medium\.com/@([A-Za-z0-9_.\-]{1,50})(?:[/?#]|$)")),
    ("twitch", re.compile(r"twitch\.tv/([A-Za-z0-9_]{3,25})(?:[/?#]|$)")),
    ("soundcloud", re.compile(r"soundcloud\.com/([A-Za-z0-9_\-]{3,25})(?:[/?#]|$)")),
    ("pinterest", re.compile(r"pinterest\.com/([A-Za-z0-9_]{3,30})(?:[/?#]|$)")),
]
# Reserved path segments that look like handles but aren't.
_RESERVED = {
    "home", "about", "explore", "settings", "login", "signup", "signin", "help",
    "share", "intent", "i", "search", "notifications", "messages", "privacy",
    "terms", "tos", "status", "watch", "results", "feed", "trending", "hashtag",
    "policies", "legal", "support", "developers", "dashboard", "new", "account",
}
# Domains that are never a "personal" site when linked.
_INFRA_DOMAINS = {
    "gravatar.com", "googleusercontent.com", "gstatic.com", "google.com",
    "cloudflare.com", "cdn.jsdelivr.net", "w3.org", "schema.org", "youtube.com",
    "twitter.com", "x.com", "github.com", "gitlab.com", "instagram.com",
    "facebook.com", "linkedin.com", "reddit.com", "t.me", "tiktok.com",
    "medium.com", "twitch.tv", "keybase.io", "soundcloud.com", "pinterest.com",
    "licensebuttons.net", "creativecommons.org", "wp.com", "gravatar.org",
}


def _registered_domain(host: str) -> str:
    try:
        import tldextract
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def extract_profile_identifiers(html: str, base_url: str = "") -> Dict:
    """
    Pull linked identities out of a profile page. Returns dict of sets:
    ``handles`` {(platform, handle)}, ``emails``, ``domains`` (candidate personal
    sites, registered-domain form), ``gravatar_hashes`` (md5 of an email).
    Pure and network-free.
    """
    handles: Set[Tuple[str, str]] = set()
    emails: Set[str] = set()
    domains: Set[str] = set()
    gravatars: Set[str] = set()

    for m in _GRAVATAR_RE.finditer(html):
        gravatars.add(m.group(1).lower())
    for m in _EMAIL_RE.finditer(html):
        emails.add(m.group(0).lower())

    self_reg = _registered_domain(urlparse(base_url).netloc) if base_url else ""

    for m in _URL_RE.finditer(html):
        url = m.group(0).rstrip('".,)\'')
        low = url.lower()
        matched_social = False
        for platform, pat in _SOCIAL_PATTERNS:
            sm = pat.search(low)
            if sm:
                handle = sm.group(1)
                if handle not in _RESERVED:
                    handles.add((platform, handle))
                matched_social = True
                break
        if matched_social:
            continue
        host = urlparse(low).netloc
        if not host:
            continue
        reg = _registered_domain(host)
        if reg and reg not in _INFRA_DOMAINS and reg != self_reg:
            domains.add(reg)

    return {"handles": handles, "emails": emails,
            "domains": domains, "gravatar_hashes": gravatars}


class ProfilePivotEngine:
    """Expand a seed handle into linked identities by parsing its profiles."""

    def __init__(self, config, enumerator: Optional[UsernameEnumerator] = None):
        self.config = config
        self.enumerator = enumerator or UsernameEnumerator(config)
        self.max_profiles = config.get("profile_pivot", "max_profiles", default=30)
        # 0 = parse the seed's profiles only (cheap default). Each extra hop
        # re-runs the full ~700-site username enum on discovered handles, so
        # deeper pivoting is explicit opt-in.
        self.max_depth = config.get("profile_pivot", "max_depth", default=0)
        self.max_recurse = config.get("profile_pivot", "max_recurse_handles", default=5)
        self.timeout = config.get("profile_pivot", "timeout", default=10)

    async def run(self, target: str) -> List[Dict]:
        seed = clean_username(target)
        if "@" in (target or "") or "." in seed or not is_valid_username(seed):
            return []

        seen_handles: Set[str] = {seed.lower()}
        # provenance maps: identity -> set of profile URLs it was linked from
        prov_handles: Dict[Tuple[str, str], Set[str]] = {}
        prov_emails: Dict[str, Set[str]] = {}
        prov_domains: Dict[str, Set[str]] = {}
        gravatars: Dict[str, Set[str]] = {}
        profiles_seen: Set[str] = set()

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (PhantomSignal-OSINT)"},
        ) as client:
            frontier = [seed]
            for depth in range(self.max_depth + 1):
                next_handles: Set[str] = set()
                for handle in frontier:
                    urls = await self._profile_urls(handle)
                    for url in urls[:self.max_profiles]:
                        if url in profiles_seen:
                            continue
                        profiles_seen.add(url)
                        html = await self._fetch(client, url)
                        if not html:
                            continue
                        ids = extract_profile_identifiers(html, url)
                        for h in ids["handles"]:
                            prov_handles.setdefault(h, set()).add(url)
                            if h[1].lower() not in seen_handles:
                                next_handles.add(h[1].lower())
                        for e in ids["emails"]:
                            prov_emails.setdefault(e, set()).add(url)
                        for d in ids["domains"]:
                            prov_domains.setdefault(d, set()).add(url)
                        for g in ids["gravatar_hashes"]:
                            gravatars.setdefault(g, set()).add(url)

                if depth >= self.max_depth:
                    break
                # bounded recursion: re-enumerate the most-linked new handles
                ranked = sorted(next_handles,
                                key=lambda hv: -sum(1 for k, s in prov_handles.items()
                                                    if k[1].lower() == hv))
                frontier = []
                for hv in ranked[:self.max_recurse]:
                    if hv not in seen_handles and is_valid_username(hv):
                        seen_handles.add(hv)
                        frontier.append(hv)
                if not frontier:
                    break

        return self._build_results(seed, prov_handles, prov_emails,
                                   prov_domains, gravatars, len(profiles_seen))

    async def _profile_urls(self, handle: str) -> List[str]:
        try:
            results = await self.enumerator.run(handle)
        except Exception as exc:
            logger.debug("enumerator failed for %s: %s", handle, exc)
            return []
        return [r["data"]["url"] for r in results
                if r.get("type") == "username_account" and r.get("data", {}).get("url")]

    async def _fetch(self, client, url: str) -> Optional[str]:
        try:
            r = await client.get(url)
            return r.text if r.status_code == 200 else None
        except Exception:
            return None

    def _build_results(self, seed, prov_handles, prov_emails, prov_domains,
                       gravatars, profiles_parsed) -> List[Dict]:
        results: List[Dict] = []

        def conf(sources: Set[str]) -> float:
            # linked from more distinct profiles → more likely the same person
            return min(0.6 + 0.15 * (len(sources) - 1), 0.95)

        for (platform, handle), sources in sorted(prov_handles.items()):
            if handle.lower() == seed.lower():
                continue
            results.append({
                "type": "linked_identity", "source": "profile_pivot",
                "data": {"seed": seed, "kind": "handle", "platform": platform,
                         "value": handle, "linked_from": sorted(sources),
                         "link_count": len(sources)},
                "confidence": conf(sources), "relevance_score": 0.75,
                "tags": ["identity", "pivot", "handle", platform],
                "is_anomaly": len(sources) >= 2,
            })
        for email, sources in sorted(prov_emails.items()):
            results.append({
                "type": "linked_identity", "source": "profile_pivot",
                "data": {"seed": seed, "kind": "email", "value": email,
                         "linked_from": sorted(sources), "link_count": len(sources)},
                "confidence": conf(sources), "relevance_score": 0.85,
                "tags": ["identity", "pivot", "email"], "is_anomaly": True,
            })
        for domain, sources in sorted(prov_domains.items()):
            results.append({
                "type": "linked_identity", "source": "profile_pivot",
                "data": {"seed": seed, "kind": "domain", "value": domain,
                         "linked_from": sorted(sources), "link_count": len(sources)},
                "confidence": conf(sources), "relevance_score": 0.7,
                "tags": ["identity", "pivot", "domain"],
            })
        for ghash, sources in sorted(gravatars.items()):
            results.append({
                "type": "linked_identity", "source": "profile_pivot",
                "data": {"seed": seed, "kind": "gravatar_md5", "value": ghash,
                         "linked_from": sorted(sources), "link_count": len(sources),
                         "note": "md5 of an email — hash a candidate email to confirm"},
                "confidence": 0.7, "relevance_score": 0.6,
                "tags": ["identity", "pivot", "gravatar"],
            })

        results.append({
            "type": "profile_pivot_summary", "source": "profile_pivot",
            "data": {
                "seed": seed,
                "profiles_parsed": profiles_parsed,
                "linked_handles": len([k for k in prov_handles
                                       if k[1].lower() != seed.lower()]),
                "linked_emails": len(prov_emails),
                "linked_domains": len(prov_domains),
                "gravatar_hashes": len(gravatars),
            },
            "confidence": 1.0, "relevance_score": 0.8,
            "tags": ["identity", "pivot", "summary"],
        })
        return results
