"""
PhantomSignal Username Enumeration — Handle Hunting Across the Grid

Phase 4 (identity). Keyless username presence-checking across ~700 sites, in the
WhatsMyName / Sherlock lineage. For a given handle it probes each site's profile
URL and applies that site's community-maintained detection rule (expected status
+ marker string), with a false-positive guard that re-checks positives against an
improbable control handle to drop catch-all sites.

No API keys. Detection rules are vendored from WhatsMyName (CC BY-SA 4.0) rather
than hand-authored — the rules are the error-prone part and the community set is
tested; see scrapers/data/README.md.

Design: HTTP I/O in the class; rule evaluation and URL templating are pure
module-level functions with unit tests.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE (bundled wmn-data.json is CC BY-SA 4.0)
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
from pathlib import Path
from typing import Dict, List, Tuple

import httpx

logger = logging.getLogger("phantomsignal.scrapers.username_enum")

_DATA_FILE = Path(__file__).parent / "data" / "wmn-data.json"
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
# A handle present on at least this many sites is a broadly-exposed footprint —
# the notable signal worth flagging as an anomaly (vs routine "found an account").
_BROAD_EXPOSURE_THRESHOLD = 10


# ── pure helpers (unit-tested) ──────────────────────────────────────────────

def clean_username(target: str) -> str:
    """Normalise a handle: strip scheme/leading @, u/, trailing slashes/space."""
    t = (target or "").strip().strip("/")
    t = t.rsplit("/", 1)[-1]                 # last path segment if a URL was passed
    t = t.lstrip("@")
    if t.lower().startswith("u/"):
        t = t[2:]
    return t


def is_valid_username(account: str) -> bool:
    return bool(_USERNAME_RE.match(account or ""))


def build_check_url(rule: Dict, account: str) -> str:
    return str(rule.get("uri_check", "")).replace("{account}", account)


def evaluate_site(rule: Dict, status_code: int, body: str) -> bool:
    """
    Apply a WhatsMyName rule: a hit requires the expected status code AND (when
    present) the expected marker string, and must NOT contain the miss marker.
    """
    try:
        e_code = int(rule.get("e_code"))
    except (TypeError, ValueError):
        return False
    if status_code != e_code:
        return False
    e_string = rule.get("e_string") or ""
    if e_string and e_string not in body:
        return False
    m_string = rule.get("m_string") or ""
    if m_string and m_string in body:
        return False
    return True


class UsernameEnumerator:
    """Check a username's presence across the vendored WhatsMyName site set."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("username_enum", "timeout", default=10)
        self.concurrency = config.get("username_enum", "concurrency", default=25)
        self.fp_check = config.get("username_enum", "fp_check", default=True)
        self.categories = config.get("username_enum", "categories", default=None)
        self._sites = self._load_sites()

    def _load_sites(self) -> List[Dict]:
        try:
            sites = json.loads(_DATA_FILE.read_text(encoding="utf-8")).get("sites", [])
        except Exception as exc:
            logger.error("could not load WhatsMyName data: %s", exc)
            return []
        if self.categories:
            wanted = set(self.categories)
            sites = [s for s in sites if s.get("cat") in wanted]
        return sites

    async def run(self, target: str) -> List[Dict]:
        # Consistent with the framework's target classification, a dotted or
        # @-bearing target is a domain/email, not a bare handle — skip it so a
        # full-spectrum scan on a domain doesn't probe the domain string as a
        # username across every site.
        if "@" in (target or "") or "." in clean_username(target):
            return []
        username = clean_username(target)
        if not is_valid_username(username):
            logger.debug("not a valid username: %r", target)
            return []
        if not self._sites:
            return []

        logger.info("Username enum for '%s' across %d sites", username, len(self._sites))
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (PhantomSignal-OSINT)"},
        ) as client:
            hits = await self._check_all(client, username)
            if self.fp_check and hits:
                hits = await self._drop_false_positives(client, hits)
        return self._build_results(username, hits)

    async def _check_all(self, client, account: str) -> List[Tuple[Dict, str]]:
        sem = asyncio.Semaphore(self.concurrency)

        async def one(site):
            async with sem:
                url = build_check_url(site, account)
                if await self._matches(client, site, account):
                    return site, url
                return None

        gathered = await asyncio.gather(*(one(s) for s in self._sites),
                                        return_exceptions=True)
        return [g for g in gathered if isinstance(g, tuple)]

    async def _matches(self, client, site: Dict, account: str) -> bool:
        url = build_check_url(site, account)
        try:
            r = await client.get(url)
        except Exception:
            return False
        return evaluate_site(site, r.status_code, r.text)

    async def _drop_false_positives(self, client, hits: List[Tuple[Dict, str]]
                                    ) -> List[Tuple[Dict, str]]:
        """Re-check each positive with an improbable control handle; a site that
        also "matches" that is a catch-all and its hit is discarded."""
        control = "zzq" + secrets.token_hex(7)      # ~no real account has this

        async def is_catch_all(site):
            return await self._matches(client, site, control)

        flags = await asyncio.gather(*(is_catch_all(s) for s, _ in hits),
                                     return_exceptions=True)
        kept = [(s, u) for (s, u), f in zip(hits, flags) if f is False]
        if len(kept) != len(hits):
            logger.debug("FP guard dropped %d catch-all site(s)", len(hits) - len(kept))
        return kept

    def _build_results(self, username: str, hits: List[Tuple[Dict, str]]) -> List[Dict]:
        results: List[Dict] = []
        by_category: Dict[str, int] = {}
        for site, url in sorted(hits, key=lambda h: h[0].get("name", "").lower()):
            cat = site.get("cat", "misc")
            by_category[cat] = by_category.get(cat, 0) + 1
            results.append({
                "type": "username_account",
                "source": "username_enum",
                "data": {"username": username, "site": site.get("name"),
                           "category": cat, "url": url},
                "confidence": 0.9,
                "relevance_score": 0.7,
                "tags": ["username", "account", "identity", cat],
            })

        results.append({
            "type": "username_enum_summary",
            "source": "username_enum",
            "data": {
                "username": username,
                "sites_checked": len(self._sites),
                "accounts_found": len(hits),
                "by_category": by_category,
                "profiles": sorted(u for _, u in hits),
            },
            "confidence": 1.0,
            "relevance_score": 0.85,
            "tags": ["username", "summary", "identity"],
            # Finding accounts is the normal success case; only a broadly-exposed
            # handle (present on many sites) is a notable highlight.
            "is_anomaly": len(hits) >= _BROAD_EXPOSURE_THRESHOLD,
        })
        return results
