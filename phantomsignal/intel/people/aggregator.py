"""
PhantomSignal Shadow Profiler — People Intelligence Aggregator
Synthesizes data from multiple sources into a unified shadow profile.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional

from phantomsignal.intel.apis.base import get_registered_apis, APICategory

logger = logging.getLogger("phantomsignal.people.aggregator")


class ShadowProfileBuilder:
    """
    Builds a comprehensive shadow profile from multiple intel sources.
    Cross-correlates data points to maximize signal confidence.
    """

    def __init__(self, config):
        self.config = config

    async def build_profile(
        self,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        username: Optional[str] = None,
        address: Optional[str] = None,
        dob: Optional[str] = None,
    ) -> Dict:
        """
        Build a shadow profile from whatever identifiers are provided.
        Uses all configured people-intel APIs in parallel.
        """
        queries = self._build_queries(
            first_name, last_name, email, phone, username
        )
        if not queries:
            return {}

        registry = get_registered_apis()
        people_apis = [
            cls(self.config)
            for name, cls in registry.items()
            if APICategory.PEOPLE in cls.CATEGORIES
            and cls(self.config).is_configured
        ]

        if not people_apis:
            logger.warning("No people intel APIs configured — add API keys to unlock this module.")
            return await self._public_fallback(first_name, last_name, email, username)

        all_raw_results = []
        for query in queries:
            tasks = [
                self._safe_search(api, query)
                for api in people_apis
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    all_raw_results.extend(r)

        return self._merge_profiles(all_raw_results, {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "phone": phone,
            "username": username,
        })

    def _build_queries(self, first_name, last_name, email, phone, username) -> List[str]:
        queries = []
        if email:
            queries.append(email)
        if phone:
            queries.append(re.sub(r"[^\d+]", "", phone))
        if first_name and last_name:
            queries.append(f"{first_name} {last_name}")
        elif username:
            queries.append(username)
        return queries

    async def _safe_search(self, api, query: str) -> List[Dict]:
        try:
            return await asyncio.wait_for(api.search(query), timeout=20)
        except Exception as e:
            logger.debug(f"People API {api.NAME} failed: {e}")
            return []

    def _merge_profiles(self, results: List[Dict], search_params: Dict) -> Dict:
        """Merge multiple API results into one unified shadow profile."""
        profile = {
            "search_params": search_params,
            "names": [],
            "emails": [],
            "phones": [],
            "addresses": [],
            "usernames": [],
            "social_profiles": {},
            "employers": [],
            "education": [],
            "relatives": [],
            "breach_data": [],
            "images": [],
            "sources": [],
            "confidence": 0.0,
            "raw_results": results,
        }

        seen_emails = set()
        seen_phones = set()

        for result in results:
            if not isinstance(result, dict):
                continue
            source = result.get("source", "unknown")
            data = result.get("data", {})

            if source not in profile["sources"]:
                profile["sources"].append(source)

            # Normalize and merge common fields
            for email in (data.get("emails") or []):
                val = email.get("value", email) if isinstance(email, dict) else email
                if val and val not in seen_emails:
                    seen_emails.add(val)
                    profile["emails"].append({"value": val, "source": source})

            for phone in (data.get("phones") or []):
                val = phone.get("number", phone) if isinstance(phone, dict) else phone
                val = re.sub(r"[^\d+]", "", str(val))
                if val and val not in seen_phones:
                    seen_phones.add(val)
                    profile["phones"].append({"value": val, "source": source})

            for addr in (data.get("addresses") or []):
                if addr not in profile["addresses"]:
                    profile["addresses"].append(addr)

            for name in (data.get("names") or []):
                display = name.get("display", name) if isinstance(name, dict) else name
                if display and display not in profile["names"]:
                    profile["names"].append(display)

            for job in (data.get("jobs") or data.get("employers") or []):
                if job not in profile["employers"]:
                    profile["employers"].append(job)

            for edu in (data.get("educations") or data.get("education") or []):
                if edu not in profile["education"]:
                    profile["education"].append(edu)

            # Social profiles
            for social in (data.get("urls") or data.get("social_profiles") or []):
                if isinstance(social, dict):
                    url = social.get("url", "")
                    for platform in ["twitter", "linkedin", "facebook", "instagram", "github"]:
                        if platform in url.lower():
                            profile["social_profiles"][platform] = url

            # Breach data
            if data.get("breached"):
                for breach in (data.get("breaches") or []):
                    profile["breach_data"].append(breach)

            # Images
            for img in (data.get("images") or data.get("photos") or []):
                url = img.get("url", img) if isinstance(img, dict) else img
                if url and url not in profile["images"]:
                    profile["images"].append(url)

        # Compute confidence based on corroboration
        if profile["emails"]:
            profile["confidence"] += 0.3
        if profile["phones"]:
            profile["confidence"] += 0.2
        if profile["addresses"]:
            profile["confidence"] += 0.15
        if len(profile["sources"]) > 1:
            profile["confidence"] += 0.2
        profile["confidence"] = min(round(profile["confidence"], 2), 1.0)

        # Compute shadow score for people profiles
        profile["shadow_score"] = self._compute_people_shadow_score(profile)

        return profile

    def _compute_people_shadow_score(self, profile: Dict) -> float:
        """Higher score = more publicly exposed digital footprint."""
        score = 0.0
        score += len(profile["emails"]) * 8
        score += len(profile["phones"]) * 7
        score += len(profile["addresses"]) * 5
        score += len(profile["social_profiles"]) * 4
        score += len(profile["employers"]) * 3
        score += len(profile["breach_data"]) * 15
        score += len(profile["images"]) * 2
        return min(round(score, 1), 100.0)

    async def _public_fallback(
        self,
        first_name: Optional[str],
        last_name: Optional[str],
        email: Optional[str],
        username: Optional[str],
    ) -> Dict:
        """
        Fallback people search using only free/no-key sources:
        GitHub, Twitter/X, crt.sh, and Google dorking hints.
        """
        from phantomsignal.intel.apis.base import get_registered_apis
        registry = get_registered_apis()
        results = []

        free_social = [
            name for name, cls in registry.items()
            if APICategory.SOCIAL in cls.CATEGORIES
            and not cls.REQUIRES_KEY
        ]

        queries = []
        if email:
            queries.append(email)
        if username:
            queries.append(username)
        if first_name and last_name:
            queries.append(f"{first_name} {last_name}")

        for query in queries:
            for api_name in free_social:
                cls = registry[api_name]
                api = cls(self.config)
                try:
                    r = await asyncio.wait_for(api.search(query), timeout=10)
                    results.extend(r or [])
                except Exception:
                    pass

        return self._merge_profiles(results, {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "username": username,
        })
