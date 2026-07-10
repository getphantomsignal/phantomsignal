"""
PhantomSignal Email Oracle — Account Discovery by Email

Phase 4 (identity). Holehe-style: given an email, determine which services it is
registered on, keylessly, by reading account-existence oracles. The anchor oracle
is Gravatar — a rock-solid keyless check (avatar 200 vs 404) whose public profile
also yields the person's display name, employer, location, and linked social
accounts, feeding the identity graph (username_enum / profile_pivot).

Honest scope: password-reset/registration oracles for large sites are fragile and
ToS-sensitive, and hand-authored rules would be silently wrong. So the shipped
oracle set is the ones we can verify (Gravatar); the classifier is data-driven so
more GET-based existence oracles can be added as rules without code changes.

Design: HTTP I/O in the class; hashing, validation, response classification, and
profile parsing are pure module-level functions with unit tests.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

logger = logging.getLogger("phantomsignal.scrapers.email_oracle")

_EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")


# ── pure helpers (unit-tested) ──────────────────────────────────────────────

def is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match((email or "").strip().lower()))


def email_md5(email: str) -> str:
    return hashlib.md5((email or "").strip().lower().encode("utf-8")).hexdigest()


# A GET existence oracle: request ``url`` (templated with {md5}/{email}); the
# email exists on the service when the response matches exists_status (+ optional
# marker) and is absent on not_exists_status. Data-driven → extensible.
GET_ORACLES: List[Dict] = [
    {"name": "gravatar", "category": "identity",
     "url": "https://www.gravatar.com/avatar/{md5}?d=404",
     "exists_status": 200, "not_exists_status": 404},
]


def classify_oracle_response(rule: Dict, status: int, body: str) -> str:
    """Return 'exists' | 'not_exists' | 'unknown' for one oracle response."""
    if status == rule.get("exists_status"):
        marker = rule.get("exists_string")
        if marker and marker not in (body or ""):
            return "unknown"
        return "exists"
    if status == rule.get("not_exists_status"):
        return "not_exists"
    return "unknown"


def parse_gravatar_profile(payload) -> Dict:
    """Extract identity fields + linked accounts from a Gravatar profile JSON."""
    entry = (payload or {}).get("entry") if isinstance(payload, dict) else None
    if not entry:
        return {}
    e = entry[0]
    accounts: List[Tuple[str, str]] = []
    for a in e.get("accounts", []) or []:
        service = a.get("shortname") or a.get("name")
        handle = a.get("username") or a.get("userid") or a.get("display")
        if service and handle:
            accounts.append((str(service).lower(), str(handle)))
    return {
        "display_name": e.get("displayName") or "",
        "username":     e.get("preferredUsername") or "",
        "company":      e.get("company") or "",
        "job_title":    e.get("job_title") or "",
        "location":     e.get("currentLocation") or "",
        "accounts":     accounts,
    }


class EmailOracle:
    """Discover which services an email is registered on (keyless)."""

    def __init__(self, config):
        self.config  = config
        self.timeout = config.get("email_oracle", "timeout", default=10)
        self.oracles = GET_ORACLES

    async def run(self, target: str) -> List[Dict]:
        email = (target or "").strip().lower()
        if not is_valid_email(email):
            return []
        md5 = email_md5(email)

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (PhantomSignal-OSINT)"},
        ) as client:
            found: List[str] = []
            for rule in self.oracles:
                url = rule["url"].format(md5=md5, email=quote(email))
                status, body = await self._get(client, url)
                if classify_oracle_response(rule, status, body) == "exists":
                    found.append(rule["name"])
            profile: Dict = {}
            if "gravatar" in found:
                profile = await self._gravatar_profile(client, md5)

        return self._build_results(email, found, profile)

    async def _get(self, client, url: str) -> Tuple[int, str]:
        try:
            r = await client.get(url)
            return r.status_code, r.text
        except Exception:
            return 0, ""

    async def _gravatar_profile(self, client, md5: str) -> Dict:
        try:
            r = await client.get(f"https://gravatar.com/{md5}.json")
            return parse_gravatar_profile(r.json()) if r.status_code == 200 else {}
        except Exception:
            return {}

    def _build_results(self, email: str, found: List[str], profile: Dict) -> List[Dict]:
        results: List[Dict] = []
        for service in found:
            results.append({
                "type":   "email_account",
                "source": "email_oracle",
                "data":   {"email": email, "service": service, "registered": True},
                "confidence":      0.95,
                "relevance_score": 0.8,
                "tags":            ["email", "account", "identity", service],
            })

        if profile and any(profile.get(k) for k in ("display_name", "username", "accounts")):
            results.append({
                "type":   "email_profile",
                "source": "email_oracle",
                "data": {"email": email, "source_service": "gravatar",
                         "display_name": profile.get("display_name"),
                         "username": profile.get("username"),
                         "company": profile.get("company"),
                         "job_title": profile.get("job_title"),
                         "location": profile.get("location")},
                "confidence":      0.9,
                "relevance_score": 0.85,
                "tags":            ["email", "profile", "identity"],
                "is_anomaly":      True,
            })
            for service, handle in profile.get("accounts", []):
                results.append({
                    "type":   "email_linked_account",
                    "source": "email_oracle",
                    "data":   {"email": email, "via": "gravatar",
                               "service": service, "handle": handle},
                    "confidence":      0.9,
                    "relevance_score": 0.75,
                    "tags":            ["email", "identity", "linked", service],
                })

        results.append({
            "type":   "email_oracle_summary",
            "source": "email_oracle",
            "data": {
                "email":            email,
                "services_checked": len(self.oracles),
                "registered_on":    found,
                "has_profile":      bool(profile),
                "linked_accounts":  len(profile.get("accounts", [])) if profile else 0,
            },
            "confidence":      1.0,
            "relevance_score": 0.8,
            "tags":            ["email", "summary", "identity"],
            "is_anomaly":      bool(found),
        })
        return results
