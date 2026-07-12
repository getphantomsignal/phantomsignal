"""
PhantomSignal Shadow Profiler — People Intelligence Aggregator
Synthesizes data from multiple sources into a unified shadow profile.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional

from phantomsignal.intel.apis import shodan_api, all_apis  # noqa: F401 — trigger API registration
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

        all_raw_results = []

        if people_apis:
            for query in queries:
                tasks = [self._safe_search(api, query) for api in people_apis]
                gathered = await asyncio.gather(*tasks, return_exceptions=True)
                for r in gathered:
                    if isinstance(r, list):
                        all_raw_results.extend(r)

        if not all_raw_results:
            # No keyed people APIs configured or none returned results —
            # run all free no-key sources for a baseline profile.
            logger.info("Running free-source people scan (no API keys required).")
            return await self._public_fallback(first_name, last_name, email, username)

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

    # Direct result-type → social platform mapping for native social API results
    _SOCIAL_RESULT_TYPES = {
        "github_profile": ("github", "github.com/{username}"),
        "twitter_profile": ("twitter", "twitter.com/{username}"),
        "reddit_profile": ("reddit", "reddit.com/u/{username}"),
        "keybase_identity": ("keybase", "keybase.io/{username}"),
        "twitch_profile": ("twitch", "twitch.tv/{username}"),
        "youtube_channel": ("youtube", None),
        "instagram_profile": ("instagram", "instagram.com/{username}"),
        "tiktok_profile": ("tiktok", "tiktok.com/@{username}"),
        "linkedin_profile": ("linkedin", "linkedin.com/in/{username}"),
        "mastodon_profile": ("mastodon", None),
        "hackernews_profile": ("hackernews", "news.ycombinator.com/user?id={username}"),
        "tumblr_blog": ("tumblr", None),
        "flickr_profile": ("flickr", None),
        "spotify_profile": ("spotify", None),
        "steam_profile": ("steam", None),
        "vk_profile": ("vk", "vk.com/{username}"),
        "telegram_channel": ("telegram", "t.me/{username}"),
        "discord_user": ("discord", None),
        "discord_server": ("discord", None),
        "facebook_page": ("facebook", "facebook.com/{username}"),
        "gravatar_profile": ("gravatar", None),
    }

    def _merge_profiles(self, results: List[Dict], search_params: Dict) -> Dict:
        """Merge multiple API results into one unified profile."""
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
        seen_usernames = set()

        for result in results:
            if not isinstance(result, dict):
                continue
            source = result.get("source", "unknown")
            data = result.get("data", {})
            rtype = result.get("type", "")

            if source not in profile["sources"]:
                profile["sources"].append(source)

            # Emails
            for email in (data.get("emails") or []):
                val = email.get("value", email) if isinstance(email, dict) else email
                if val and isinstance(val, str) and "@" in val and val not in seen_emails:
                    seen_emails.add(val)
                    profile["emails"].append({"value": val, "source": source})

            # Phones
            for phone in (data.get("phones") or []):
                val = phone.get("number", phone) if isinstance(phone, dict) else phone
                val = re.sub(r"[^\d+]", "", str(val))
                if val and len(val) >= 7 and val not in seen_phones:
                    seen_phones.add(val)
                    profile["phones"].append({"value": val, "source": source})

            # Phone validation results
            if rtype == "phone_validation" and data.get("valid"):
                val = re.sub(r"[^\d+]", "", data.get("phone", ""))
                if val and val not in seen_phones:
                    seen_phones.add(val)
                    profile["phones"].append({
                        "value": val,
                        "source": source,
                        "carrier": data.get("carrier"),
                        "type": data.get("type"),
                        "country": data.get("country_name"),
                    })

            # Addresses
            for addr in (data.get("addresses") or []):
                if addr not in profile["addresses"]:
                    profile["addresses"].append(addr)

            # Names — also pull from native profile fields
            for name in (data.get("names") or []):
                display = name.get("display", name) if isinstance(name, dict) else name
                if display and display not in profile["names"]:
                    profile["names"].append(display)

            for name_field in ["full_name", "realname", "real_name", "display_name", "global_name"]:
                val = data.get(name_field)
                if val and val not in profile["names"]:
                    profile["names"].append(val)

            # First+Last name combo
            if data.get("first_name") and data.get("last_name"):
                full = f"{data['first_name']} {data['last_name']}"
                if full not in profile["names"]:
                    profile["names"].append(full)

            # Employment
            for job in (data.get("jobs") or data.get("employers") or []):
                if job not in profile["employers"]:
                    profile["employers"].append(job)
            if data.get("company"):
                entry = {"name": data["company"], "source": source}
                if entry not in profile["employers"]:
                    profile["employers"].append(entry)
            if data.get("occupation"):
                entry = {"name": data["occupation"], "source": source}
                if entry not in profile["employers"]:
                    profile["employers"].append(entry)

            # Education
            for edu in (data.get("educations") or data.get("education") or []):
                if edu not in profile["education"]:
                    profile["education"].append(edu)

            # Social profiles — from URL arrays
            for social in (data.get("urls") or data.get("social_profiles") or []):
                if isinstance(social, dict):
                    url = social.get("url") or social.get("value", "")
                    for platform in [
                        "twitter", "linkedin", "facebook", "instagram", "github",
                        "twitch", "youtube", "tiktok", "reddit", "discord",
                        "telegram", "mastodon", "keybase", "steam", "spotify",
                        "vk", "tumblr", "flickr",
                    ]:
                        if platform in url.lower() and platform not in profile["social_profiles"]:
                            profile["social_profiles"][platform] = url

            # Social profiles — from native social API result types
            if rtype in self._SOCIAL_RESULT_TYPES:
                platform, url_template = self._SOCIAL_RESULT_TYPES[rtype]
                profile_url = data.get("profile_url") or data.get("url") or data.get("external_url")
                if not profile_url and url_template:
                    uname = data.get("username") or data.get("login") or data.get("screen_name") or data.get("id")
                    if uname:
                        profile_url = url_template.replace("{username}", str(uname))
                if profile_url and platform not in profile["social_profiles"]:
                    profile["social_profiles"][platform] = profile_url

            # Username harvesting from social profiles
            for uname_field in ["username", "login", "screen_name", "preferred_username"]:
                val = data.get(uname_field)
                if val and val not in seen_usernames:
                    seen_usernames.add(val)
                    profile["usernames"].append({"value": val, "platform": source})

            # Keybase verified cross-proofs
            if rtype == "keybase_identity":
                for platform in ["twitter", "github", "reddit", "hackernews"]:
                    handle = data.get(platform)
                    if handle and platform not in profile["social_profiles"]:
                        urls_map = {
                            "twitter": f"https://twitter.com/{handle}",
                            "github": f"https://github.com/{handle}",
                            "reddit": f"https://reddit.com/u/{handle}",
                            "hackernews": f"https://news.ycombinator.com/user?id={handle}",
                        }
                        profile["social_profiles"][platform] = urls_map[platform]

            # EmailRep cross-platform profiles
            if rtype == "email_reputation":
                for p in data.get("profiles", []):
                    if isinstance(p, str) and p not in profile["social_profiles"]:
                        profile["social_profiles"][p] = f"[found via emailrep on {p}]"

            # Gravatar linked accounts
            if rtype == "gravatar_profile":
                for acct in data.get("accounts", []):
                    domain = acct.get("domain", "")
                    url = acct.get("url")
                    if domain and url and domain not in profile["social_profiles"]:
                        profile["social_profiles"][domain] = url

            # Breach data
            if data.get("breached") or data.get("credentials_leaked"):
                for breach in (data.get("breaches") or []):
                    profile["breach_data"].append(breach)

            if rtype == "intelx_leak" and data.get("total_hits", 0) > 0:
                profile["breach_data"].append({
                    "name": "Intelligence X",
                    "source": "intelx",
                    "hits": data.get("total_hits"),
                    "buckets": data.get("buckets", []),
                })

            # Images
            for img in (data.get("images") or data.get("photos") or []):
                url = img.get("url", img) if isinstance(img, dict) else img
                if url and url not in profile["images"]:
                    profile["images"].append(url)

            for img_field in ["avatar_url", "profile_image_url", "photo_url", "photo_max", "icon_img"]:
                url = data.get(img_field)
                if url and url not in profile["images"]:
                    profile["images"].append(url)

        # Confidence: increases with corroborating data points
        if profile["emails"]:
            profile["confidence"] += 0.3
        if profile["phones"]:
            profile["confidence"] += 0.2
        if profile["addresses"]:
            profile["confidence"] += 0.15
        if len(profile["sources"]) > 1:
            profile["confidence"] += 0.2
        if profile["social_profiles"]:
            profile["confidence"] += 0.1
        if profile["breach_data"]:
            profile["confidence"] += 0.05
        profile["confidence"] = min(round(profile["confidence"], 2), 1.0)

        profile["shadow_score"] = self._compute_people_shadow_score(profile)

        return profile

    def _compute_people_shadow_score(self, profile: Dict) -> float:
        """Higher score = more publicly exposed digital footprint."""
        score = 0.0
        score += len(profile["emails"]) * 8
        score += len(profile["phones"]) * 7
        score += len(profile["addresses"]) * 5
        score += len(profile["social_profiles"]) * 5
        score += len(profile["usernames"]) * 3
        score += len(profile["employers"]) * 3
        score += len(profile["breach_data"]) * 15
        score += len(profile["images"]) * 2
        score += len(profile["sources"]) * 2
        return min(round(score, 1), 100.0)

    async def _public_fallback(
        self,
        first_name: Optional[str],
        last_name: Optional[str],
        email: Optional[str],
        username: Optional[str],
    ) -> Dict:
        """
        Free-tier people scan — runs all no-key-required APIs against every available
        identifier. Covers GitHub, Reddit, Keybase, Gravatar, HackerNews, Mastodon,
        and EmailRep without any API keys configured.
        """
        from phantomsignal.intel.apis.base import get_registered_apis
        registry = get_registered_apis()
        results = []

        free_apis = [
            cls(self.config)
            for name, cls in registry.items()
            if not cls.REQUIRES_KEY
            and any(cat in cls.CATEGORIES for cat in [
                APICategory.SOCIAL, APICategory.PEOPLE, APICategory.EMAIL,
            ])
        ]

        queries = []
        if email:
            queries.append(email)
        if username:
            queries.append(username)
        if first_name and last_name:
            queries.append(f"{first_name} {last_name}")
        elif first_name:
            queries.append(first_name)

        tasks = [
            self._safe_search(api, query)
            for api in free_apis
            for query in queries
        ]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        for r in gathered:
            if isinstance(r, list):
                results.extend(r)

        return self._merge_profiles(results, {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "username": username,
        })
