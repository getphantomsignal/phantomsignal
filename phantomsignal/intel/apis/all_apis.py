"""
PhantomSignal Intelligence API Registry
All API integrations — the full ghost key arsenal.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Optional

import httpx

from phantomsignal.intel.apis.base import (
    APICategory, APITier, BaseIntelAPI, register_api
)


# ═══════════════════════════════════════════════════════════
# NETWORK & INFRASTRUCTURE INTELLIGENCE
# ═══════════════════════════════════════════════════════════

@register_api
class CensysAPI(BaseIntelAPI):
    NAME = "censys"
    DESCRIPTION = "Internet-wide scanning for hosts, certs, and domains"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.NETWORK, APICategory.DOMAIN]
    BASE_URL = "https://search.censys.io/api"
    DOCS_URL = "https://search.censys.io/api"
    SIGN_UP_URL = "https://accounts.censys.io/register"
    RATE_LIMIT_PER_MINUTE = 120

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        api_id = self.config.get_api_key("censys_id")
        api_secret = self.config.get_api_key("censys_secret")
        if not api_id or not api_secret:
            return []

        import base64
        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}

        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))

        if is_ip:
            data = await self._get(
                f"{self.BASE_URL}/v2/hosts/{query}",
                headers=headers,
            )
            if "error" in data:
                return []
            result = data.get("result", {})
            return [self._wrap_result(
                "censys_host",
                {
                    "ip": query,
                    "services": result.get("services", []),
                    "location": result.get("location", {}),
                    "autonomous_system": result.get("autonomous_system", {}),
                    "labels": result.get("labels", []),
                    "last_updated": result.get("last_updated_at"),
                },
                confidence=1.0, relevance_score=0.9,
                tags=["censys", "host", "network"],
            )]
        else:
            data = await self._post(
                f"{self.BASE_URL}/v2/hosts/search",
                json={"q": query, "per_page": 50},
                headers=headers,
            )
            hits = data.get("result", {}).get("hits", [])
            return [self._wrap_result(
                "censys_search",
                {"query": query, "total": data.get("result", {}).get("total", 0), "hits": hits[:50]},
                confidence=0.9, relevance_score=0.8, tags=["censys", "search"],
            )]


@register_api
class ZoomEyeAPI(BaseIntelAPI):
    NAME = "zoomeye"
    DESCRIPTION = "Chinese cyberspace search engine — global device intelligence"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.NETWORK]
    BASE_URL = "https://api.zoomeye.org"
    DOCS_URL = "https://www.zoomeye.org/doc"
    SIGN_UP_URL = "https://www.zoomeye.org/signup"

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        headers = {"API-KEY": self._api_key}
        data = await self._get(
            f"{self.BASE_URL}/host/search",
            params={"query": query, "page": 1},
            headers=headers,
        )
        if "error" in data:
            return []
        return [self._wrap_result(
            "zoomeye_search",
            {
                "query": query,
                "total": data.get("total", 0),
                "matches": data.get("matches", [])[:50],
            },
            confidence=0.9, relevance_score=0.8, tags=["zoomeye", "network"],
        )]


@register_api
class BinaryEdgeAPI(BaseIntelAPI):
    NAME = "binaryedge"
    DESCRIPTION = "Real-time internet scanning and threat intelligence"
    REQUIRES_KEY = True
    TIER = APITier.FREEMIUM
    CATEGORIES = [APICategory.NETWORK, APICategory.VULNERABILITY]
    BASE_URL = "https://api.binaryedge.io/v2"
    DOCS_URL = "https://docs.binaryedge.io"
    SIGN_UP_URL = "https://www.binaryedge.io/pricing.html"
    RATE_LIMIT_PER_MINUTE = 15

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        headers = {"X-Key": self._api_key}
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))
        endpoint = f"/query/ip/{query}" if is_ip else f"/query/search?query={query}"
        data = await self._get(f"{self.BASE_URL}{endpoint}", headers=headers)
        if "error" in data:
            return []
        return [self._wrap_result(
            "binaryedge_result",
            data, confidence=0.9, relevance_score=0.85, tags=["binaryedge", "network"],
        )]


@register_api
class GreyNoiseAPI(BaseIntelAPI):
    NAME = "greynoise"
    DESCRIPTION = "Distinguish malicious internet scanners from legitimate traffic"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.THREAT_INTEL, APICategory.NETWORK]
    BASE_URL = "https://api.greynoise.io/v3"
    DOCS_URL = "https://docs.greynoise.io"
    SIGN_UP_URL = "https://viz.greynoise.io/signup"

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))
        if not is_ip:
            return []

        headers = {"key": self._api_key}
        data = await self._get(f"{self.BASE_URL}/community/{query}", headers=headers)
        if "error" in data:
            return []

        is_malicious = data.get("classification") == "malicious"
        return [self._wrap_result(
            "greynoise_ip",
            {
                "ip": query,
                "noise": data.get("noise"),
                "riot": data.get("riot"),
                "classification": data.get("classification"),
                "name": data.get("name"),
                "link": data.get("link"),
                "last_seen": data.get("last_seen"),
                "message": data.get("message"),
            },
            confidence=0.95, relevance_score=0.9,
            tags=["greynoise", "threat_intel", "ip"] + (["malicious"] if is_malicious else []),
            is_anomaly=is_malicious,
        )]


@register_api
class IPInfoAPI(BaseIntelAPI):
    NAME = "ipinfo"
    DESCRIPTION = "IP geolocation, ASN, carrier, and hostname data"
    REQUIRES_KEY = False
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.GEOLOCATION, APICategory.NETWORK]
    BASE_URL = "https://ipinfo.io"
    DOCS_URL = "https://ipinfo.io/developers"
    SIGN_UP_URL = "https://ipinfo.io/signup"
    RATE_LIMIT_PER_MINUTE = 50

    async def search(self, query: str, **kwargs) -> List[Dict]:
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))
        if not is_ip:
            return []

        params = {"token": self._api_key} if self._api_key else {}
        data = await self._get(f"{self.BASE_URL}/{query}/json", params=params)

        if "error" in data or "ip" not in data:
            return []

        loc = data.get("loc", ",").split(",")
        return [self._wrap_result(
            "ip_geolocation",
            {
                "ip": data.get("ip"),
                "hostname": data.get("hostname"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "postal": data.get("postal"),
                "timezone": data.get("timezone"),
                "org": data.get("org"),
                "asn": data.get("org", "").split(" ")[0] if data.get("org") else None,
                "latitude": float(loc[0]) if len(loc) == 2 else None,
                "longitude": float(loc[1]) if len(loc) == 2 else None,
                "is_vpn": "vpn" in data.get("privacy", {}).get("service", "").lower() if "privacy" in data else None,
                "is_proxy": data.get("privacy", {}).get("proxy"),
                "is_tor": data.get("privacy", {}).get("tor"),
            },
            confidence=0.95, relevance_score=0.8, tags=["ip", "geolocation", "network"],
        )]


# ═══════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════

@register_api
class VirusTotalAPI(BaseIntelAPI):
    NAME = "virustotal"
    DESCRIPTION = "Multi-engine malware scanner — URLs, IPs, domains, files"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.THREAT_INTEL, APICategory.DOMAIN, APICategory.NETWORK]
    BASE_URL = "https://www.virustotal.com/api/v3"
    DOCS_URL = "https://developers.virustotal.com/reference"
    SIGN_UP_URL = "https://www.virustotal.com/gui/join-us"
    RATE_LIMIT_PER_MINUTE = 4

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        headers = {"x-apikey": self._api_key}
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))
        is_url = query.startswith("http")
        is_hash = bool(re.match(r"^[a-f0-9]{32,64}$", query, re.IGNORECASE))

        if is_ip:
            endpoint = f"/ip_addresses/{query}"
        elif is_hash:
            endpoint = f"/files/{query}"
        elif is_url:
            import base64
            url_id = base64.urlsafe_b64encode(query.encode()).decode().rstrip("=")
            endpoint = f"/urls/{url_id}"
        else:
            endpoint = f"/domains/{query}"

        data = await self._get(f"{self.BASE_URL}{endpoint}", headers=headers)
        if "error" in data or "data" not in data:
            return []

        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        is_dangerous = malicious > 3 or (malicious + suspicious) > 5
        return [self._wrap_result(
            "virustotal_analysis",
            {
                "query": query,
                "type": data["data"].get("type"),
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "clean_engines": stats.get("undetected", 0),
                "total_engines": total,
                "detection_rate": f"{malicious}/{total}" if total else "0/0",
                "reputation": attrs.get("reputation"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "tags": attrs.get("tags", []),
                "categories": attrs.get("categories", {}),
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "analysis_stats": stats,
            },
            confidence=0.98, relevance_score=0.95,
            tags=["virustotal", "threat_intel"] + (["malicious"] if is_dangerous else ["clean"]),
            is_anomaly=is_dangerous,
        )]


@register_api
class AbuseIPDBAPI(BaseIntelAPI):
    NAME = "abuseipdb"
    DESCRIPTION = "IP address abuse confidence and report database"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.THREAT_INTEL, APICategory.NETWORK]
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    DOCS_URL = "https://docs.abuseipdb.com"
    SIGN_UP_URL = "https://www.abuseipdb.com/register"
    RATE_LIMIT_PER_MINUTE = 60

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))
        if not is_ip:
            return []

        data = await self._get(
            f"{self.BASE_URL}/check",
            params={"ipAddress": query, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": self._api_key, "Accept": "application/json"},
        )
        if "errors" in data or "data" not in data:
            return []

        d = data["data"]
        abuse_score = d.get("abuseConfidenceScore", 0)
        is_abusive = abuse_score > 25

        return [self._wrap_result(
            "ip_abuse_report",
            {
                "ip": query,
                "abuse_confidence_score": abuse_score,
                "total_reports": d.get("totalReports", 0),
                "num_distinct_users": d.get("numDistinctUsers", 0),
                "last_reported": d.get("lastReportedAt"),
                "country_code": d.get("countryCode"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "is_tor": d.get("isTor"),
                "is_public": d.get("isPublic"),
                "usage_type": d.get("usageType"),
                "hostnames": d.get("hostnames", []),
                "recent_reports": d.get("reports", [])[:10],
            },
            confidence=0.95, relevance_score=0.9,
            tags=["abuseipdb", "ip", "reputation"] + (["malicious", "abusive"] if is_abusive else []),
            is_anomaly=is_abusive,
        )]


@register_api
class AlienVaultOTXAPI(BaseIntelAPI):
    NAME = "alienvault"
    DESCRIPTION = "Open Threat Exchange — community-powered threat intelligence"
    REQUIRES_KEY = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.THREAT_INTEL]
    BASE_URL = "https://otx.alienvault.com/api/v1"
    DOCS_URL = "https://otx.alienvault.com/api"
    SIGN_UP_URL = "https://otx.alienvault.com/accounts/register"
    RATE_LIMIT_PER_MINUTE = 60

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        headers = {"X-OTX-API-KEY": self._api_key}

        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))
        is_hash = bool(re.match(r"^[a-f0-9]{32,64}$", query, re.IGNORECASE))

        if is_ip:
            indicator_type = "IPv4"
            sections = ["general", "reputation", "geo", "malware", "passive_dns"]
        elif is_hash:
            indicator_type = "file"
            sections = ["general", "analysis"]
        elif "@" in query:
            indicator_type = "email"
            sections = ["general"]
        else:
            indicator_type = "domain"
            sections = ["general", "passive_dns", "malware", "whois", "http_scans"]

        async def _fetch(section: str):
            import asyncio as _asyncio
            data = await _asyncio.wait_for(
                self._get(
                    f"{self.BASE_URL}/indicators/{indicator_type}/{query}/{section}",
                    headers=headers,
                ),
                timeout=8,
            )
            return section, data

        import asyncio as _asyncio
        fetched = await _asyncio.gather(*[_fetch(s) for s in sections], return_exceptions=True)
        all_data = {}
        for item in fetched:
            if isinstance(item, Exception):
                continue
            section, data = item
            if "error" not in data:
                all_data[section] = data

        if not all_data:
            return []

        general = all_data.get("general", {})
        pulse_count = general.get("pulse_info", {}).get("count", 0)
        is_malicious = pulse_count > 5 or general.get("reputation", 0) < -5

        return [self._wrap_result(
            "otx_indicator",
            {
                "indicator": query,
                "type": indicator_type,
                "pulse_count": pulse_count,
                "reputation": general.get("reputation"),
                "country": general.get("country_name"),
                "city": general.get("city"),
                "asn": general.get("asn"),
                "validation": general.get("validation", []),
                "sections": all_data,
            },
            confidence=0.9, relevance_score=0.85,
            tags=["alienvault", "otx", "threat_intel"] + (["malicious"] if is_malicious else []),
            is_anomaly=is_malicious,
        )]


# ═══════════════════════════════════════════════════════════
# EMAIL INTELLIGENCE
# ═══════════════════════════════════════════════════════════

@register_api
class HunterIOAPI(BaseIntelAPI):
    NAME = "hunter"
    DESCRIPTION = "Email finder, verifier, and domain email discovery"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.EMAIL]
    BASE_URL = "https://api.hunter.io/v2"
    DOCS_URL = "https://hunter.io/api-documentation"
    SIGN_UP_URL = "https://hunter.io/users/sign_up"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        results = []
        if "@" in query:
            results.extend(await self._verify_email(query))
        else:
            results.extend(await self._domain_search(query))
        return results

    async def _domain_search(self, domain: str) -> List[Dict]:
        data = await self._get(
            f"{self.BASE_URL}/domain-search",
            params={"domain": domain, "api_key": self._api_key, "limit": 100},
        )
        if "errors" in data or "data" not in data:
            return []

        d = data["data"]
        emails = d.get("emails", [])
        return [self._wrap_result(
            "email_discovery",
            {
                "domain": domain,
                "organization": d.get("organization"),
                "email_count": d.get("total", 0),
                "pattern": d.get("pattern"),
                "emails": [
                    {
                        "value": e.get("value"),
                        "type": e.get("type"),
                        "confidence": e.get("confidence"),
                        "first_name": e.get("first_name"),
                        "last_name": e.get("last_name"),
                        "position": e.get("position"),
                        "department": e.get("department"),
                        "linkedin": e.get("linkedin"),
                        "twitter": e.get("twitter"),
                        "phone_number": e.get("phone_number"),
                        "sources": e.get("sources", []),
                    }
                    for e in emails[:50]
                ],
                "technologies": d.get("technologies", []),
                "disposable": d.get("disposable"),
                "webmail": d.get("webmail"),
                "mx_records": d.get("mx_records"),
                "smtp_server": d.get("smtp_server"),
                "smtp_check": d.get("smtp_check"),
                "accept_all": d.get("accept_all"),
            },
            confidence=0.9, relevance_score=0.9,
            tags=["hunter", "email", "discovery"],
        )]

    async def _verify_email(self, email: str) -> List[Dict]:
        data = await self._get(
            f"{self.BASE_URL}/email-verifier",
            params={"email": email, "api_key": self._api_key},
        )
        if "errors" in data or "data" not in data:
            return []

        d = data["data"]
        return [self._wrap_result(
            "email_verification",
            {
                "email": email,
                "result": d.get("result"),
                "score": d.get("score"),
                "regexp": d.get("regexp"),
                "gibberish": d.get("gibberish"),
                "disposable": d.get("disposable"),
                "webmail": d.get("webmail"),
                "mx_records": d.get("mx_records"),
                "smtp_server": d.get("smtp_server"),
                "smtp_check": d.get("smtp_check"),
                "accept_all": d.get("accept_all"),
                "block": d.get("block"),
                "sources": d.get("sources", []),
            },
            confidence=0.95, relevance_score=0.85,
            tags=["hunter", "email", "verification"],
        )]


@register_api
class HaveIBeenPwnedAPI(BaseIntelAPI):
    NAME = "hibp"
    DESCRIPTION = "Check if email/password appears in known data breaches"
    REQUIRES_KEY = True
    TIER = APITier.PAID
    CATEGORIES = [APICategory.BREACH, APICategory.EMAIL]
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    DOCS_URL = "https://haveibeenpwned.com/API/v3"
    SIGN_UP_URL = "https://haveibeenpwned.com/API/Key"
    RATE_LIMIT_PER_MINUTE = 10
    IS_COMMERCIAL = True

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        results = []
        if "@" in query:
            results.extend(await self._check_email(query))
        return results

    async def _check_email(self, email: str) -> List[Dict]:
        headers = {
            "hibp-api-key": self._api_key,
            "User-Agent": "PhantomSignal-OSINT/1.0",
        }
        data = await self._get(
            f"{self.BASE_URL}/breachedaccount/{email}",
            params={"truncateResponse": "false", "includeUnverified": "true"},
            headers=headers,
        )

        if isinstance(data, dict) and data.get("error"):
            if "404" in str(data.get("error", "")):
                return [self._wrap_result(
                    "breach_data",
                    {"email": email, "breached": False, "breach_count": 0, "breaches": []},
                    confidence=0.99, relevance_score=0.9, tags=["hibp", "breach", "clean"],
                )]
            return []

        breaches = data if isinstance(data, list) else []
        is_breached = len(breaches) > 0

        return [self._wrap_result(
            "breach_data",
            {
                "email": email,
                "breached": is_breached,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b.get("Name"),
                        "title": b.get("Title"),
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "added_date": b.get("AddedDate"),
                        "pwn_count": b.get("PwnCount"),
                        "description": b.get("Description", "")[:300],
                        "data_classes": b.get("DataClasses", []),
                        "is_verified": b.get("IsVerified"),
                        "is_sensitive": b.get("IsSensitive"),
                        "is_spam_list": b.get("IsSpamList"),
                    }
                    for b in breaches
                ],
            },
            confidence=0.99, relevance_score=1.0,
            tags=["hibp", "breach"] + (["compromised"] if is_breached else ["clean"]),
            is_anomaly=is_breached,
        )]


# ═══════════════════════════════════════════════════════════
# DOMAIN & WEB INTELLIGENCE
# ═══════════════════════════════════════════════════════════

@register_api
class SecurityTrailsAPI(BaseIntelAPI):
    NAME = "securitytrails"
    DESCRIPTION = "Historical DNS, WHOIS, subdomains, and IP intelligence"
    REQUIRES_KEY = True
    TIER = APITier.FREEMIUM
    CATEGORIES = [APICategory.DOMAIN, APICategory.NETWORK]
    BASE_URL = "https://api.securitytrails.com/v1"
    DOCS_URL = "https://securitytrails.com/corp/api"
    SIGN_UP_URL = "https://securitytrails.com/app/signup"
    RATE_LIMIT_PER_MINUTE = 50

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        headers = {"APIKEY": self._api_key}
        results = []

        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))

        if is_ip:
            for endpoint, rtype in [("/ips/nearby", "nearby_ips"), ("/ips/{}/whois", "whois")]:
                url = f"{self.BASE_URL}{endpoint.format(query) if '{}' in endpoint else endpoint}"
                params = {} if "{}" in endpoint else {"ipaddress": query}
                data = await self._get(url, params=params, headers=headers)
                if "error" not in data:
                    results.append(self._wrap_result(
                        f"securitytrails_{rtype}",
                        {"query": query, **data},
                        confidence=0.9, relevance_score=0.8, tags=["securitytrails", rtype],
                    ))
        else:
            for section in ["general", "subdomains", "dns"]:
                url = f"{self.BASE_URL}/domain/{query}{'/' + section if section != 'general' else ''}"
                data = await self._get(url, headers=headers)
                if "error" not in data and data:
                    results.append(self._wrap_result(
                        f"securitytrails_{section}",
                        {"domain": query, **data},
                        confidence=0.9, relevance_score=0.85, tags=["securitytrails", "domain", section],
                    ))
        return results


@register_api
class URLScanAPI(BaseIntelAPI):
    NAME = "urlscan"
    DESCRIPTION = "URL/website sandbox scanner with screenshot and DOM analysis"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.DOMAIN, APICategory.THREAT_INTEL]
    BASE_URL = "https://urlscan.io/api/v1"
    DOCS_URL = "https://urlscan.io/docs/api/"
    SIGN_UP_URL = "https://urlscan.io/user/signup"
    RATE_LIMIT_PER_MINUTE = 20

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        headers = {"API-Key": self._api_key}

        search_data = await self._get(
            f"{self.BASE_URL}/search/",
            params={"q": f"domain:{query}" if "." in query else query, "size": 20},
            headers=headers,
        )
        if "error" in search_data or "results" not in search_data:
            return []

        results = []
        for scan in search_data["results"][:20]:
            page = scan.get("page", {})
            verdicts = scan.get("verdicts", {})
            is_malicious = verdicts.get("overall", {}).get("malicious", False)
            results.append(self._wrap_result(
                "urlscan_result",
                {
                    "uuid": scan.get("_id"),
                    "url": page.get("url"),
                    "domain": page.get("domain"),
                    "ip": page.get("ip"),
                    "country": page.get("country"),
                    "server": page.get("server"),
                    "screenshot": f"https://urlscan.io/screenshots/{scan.get('_id')}.png",
                    "result_url": f"https://urlscan.io/result/{scan.get('_id')}",
                    "malicious": is_malicious,
                    "verdicts": verdicts,
                    "time": scan.get("task", {}).get("time"),
                },
                confidence=0.9, relevance_score=0.85,
                tags=["urlscan", "web"] + (["malicious"] if is_malicious else []),
                is_anomaly=is_malicious,
            ))
        return results

    async def submit_scan(self, url: str, visibility: str = "public") -> Dict:
        """Submit a URL for active scanning."""
        data = await self._post(
            f"{self.BASE_URL}/scan/",
            json={"url": url, "visibility": visibility},
            headers={"API-Key": self._api_key, "Content-Type": "application/json"},
        )
        return data


# ═══════════════════════════════════════════════════════════
# PEOPLE & IDENTITY INTELLIGENCE (Commercial — require paid keys)
# ═══════════════════════════════════════════════════════════

@register_api
class PiplAPI(BaseIntelAPI):
    NAME = "pipl"
    DESCRIPTION = "Deep web people search — identity resolution and enrichment"
    REQUIRES_KEY = True
    TIER = APITier.ENTERPRISE
    CATEGORIES = [APICategory.PEOPLE]
    BASE_URL = "https://api.pipl.com/search"
    DOCS_URL = "https://docs.pipl.com/reference"
    SIGN_UP_URL = "https://pipl.com/api/"
    IS_COMMERCIAL = True
    RATE_LIMIT_PER_MINUTE = 60

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        params = {"key": self._api_key, "pretty": False}

        if "@" in query:
            params["email"] = query
        elif re.match(r"^\+?[\d\s\-\(\)]{10,}$", query):
            params["phone"] = re.sub(r"[^\d+]", "", query)
        else:
            parts = query.strip().split()
            if len(parts) >= 2:
                params["first_name"] = parts[0]
                params["last_name"] = " ".join(parts[1:])
            else:
                params["username"] = query

        data = await self._get(self.BASE_URL, params=params)
        if "error" in data or "person" not in data:
            return []

        person = data["person"]
        return [self._wrap_result(
            "people_profile",
            {
                "query": query,
                "names": person.get("names", []),
                "emails": person.get("emails", []),
                "phones": person.get("phones", []),
                "addresses": person.get("addresses", []),
                "jobs": person.get("jobs", []),
                "educations": person.get("educations", []),
                "images": person.get("images", []),
                "urls": person.get("urls", []),
                "relationships": person.get("relationships", []),
                "user_ids": person.get("user_ids", []),
                "dob": person.get("dob", {}).get("display"),
                "gender": person.get("gender", {}).get("content"),
                "match_score": data.get("@person_count", 1),
                "source": "pipl",
            },
            confidence=0.9, relevance_score=1.0, tags=["pipl", "people", "identity"],
        )]


@register_api
class FullContactAPI(BaseIntelAPI):
    NAME = "fullcontact"
    DESCRIPTION = "Person and company identity resolution from email/social"
    REQUIRES_KEY = True
    TIER = APITier.PAID
    CATEGORIES = [APICategory.PEOPLE, APICategory.EMAIL]
    BASE_URL = "https://api.fullcontact.com/v3"
    DOCS_URL = "https://docs.fullcontact.com"
    SIGN_UP_URL = "https://dashboard.fullcontact.com/register"
    IS_COMMERCIAL = True

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        headers = {"Authorization": f"Bearer {self._api_key}"}

        if "@" in query:
            payload = {"email": query}
        elif re.match(r"^\+?[\d]{10,}$", query.replace(" ", "").replace("-", "")):
            payload = {"phone": query}
        else:
            payload = {"twitter": query}

        data = await self._post(f"{self.BASE_URL}/person.enrich", json=payload, headers=headers)
        if "error" in data or "fullName" not in data and "name" not in data:
            return []

        return [self._wrap_result(
            "people_enrichment",
            {
                "query": query,
                "full_name": data.get("fullName"),
                "age_range": data.get("ageRange"),
                "gender": data.get("gender"),
                "location": data.get("location"),
                "bio": data.get("bio"),
                "organization": data.get("organization"),
                "title": data.get("title"),
                "photos": data.get("photos", []),
                "social_profiles": data.get("socialProfiles", []),
                "employment": data.get("employment", []),
                "education": data.get("education", []),
                "details": data.get("details", {}),
                "likelihood": data.get("likelihood"),
            },
            confidence=0.85, relevance_score=0.95, tags=["fullcontact", "people", "enrichment"],
        )]


@register_api
class WhitePagesAPI(BaseIntelAPI):
    NAME = "whitepages"
    DESCRIPTION = "US people search — address, phone, relatives, criminal records"
    REQUIRES_KEY = True
    TIER = APITier.PAID
    CATEGORIES = [APICategory.PEOPLE]
    BASE_URL = "https://proapi.whitepages.com/3.3"
    DOCS_URL = "https://pro.whitepages.com/developer/documentation/"
    SIGN_UP_URL = "https://pro.whitepages.com/developer/"
    IS_COMMERCIAL = True

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        params = {"api_key": self._api_key}

        if re.match(r"^\+?[\d\s\-\(\)]{10,}$", query):
            params["phone.phone_number"] = re.sub(r"[^\d]", "", query)
            endpoint = "/phone.json"
        else:
            parts = query.split()
            params["name.first_name"] = parts[0] if parts else ""
            params["name.last_name"] = " ".join(parts[1:]) if len(parts) > 1 else ""
            endpoint = "/person.json"

        data = await self._get(f"{self.BASE_URL}{endpoint}", params=params)
        if "error" in data:
            return []

        return [self._wrap_result(
            "whitepages_result",
            {"query": query, **data},
            confidence=0.85, relevance_score=0.9, tags=["whitepages", "people"],
        )]


@register_api
class SpokeoPeopleAPI(BaseIntelAPI):
    NAME = "spokeo"
    DESCRIPTION = "People search aggregator — contact info, social, public records"
    REQUIRES_KEY = True
    TIER = APITier.PAID
    CATEGORIES = [APICategory.PEOPLE]
    BASE_URL = "https://api.spokeo.com/v1"
    DOCS_URL = "https://www.spokeo.com/api"
    SIGN_UP_URL = "https://www.spokeo.com/developers"
    IS_COMMERCIAL = True

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        headers = {"Authorization": f"Bearer {self._api_key}"}
        data = await self._get(
            f"{self.BASE_URL}/search",
            params={"query": query, "type": "person"},
            headers=headers,
        )
        if "error" in data:
            return []
        return [self._wrap_result(
            "spokeo_result",
            {"query": query, **data},
            confidence=0.8, relevance_score=0.85, tags=["spokeo", "people"],
        )]


@register_api
class ClearbitAPI(BaseIntelAPI):
    NAME = "clearbit"
    DESCRIPTION = "B2B identity enrichment — company and person data from email"
    REQUIRES_KEY = True
    TIER = APITier.PAID
    CATEGORIES = [APICategory.PEOPLE, APICategory.EMAIL]
    BASE_URL = "https://person.clearbit.com/v2"
    DOCS_URL = "https://clearbit.com/docs"
    SIGN_UP_URL = "https://clearbit.com"
    IS_COMMERCIAL = True

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured or "@" not in query:
            return []
        import base64
        auth = base64.b64encode(f"{self._api_key}:".encode()).decode()
        data = await self._get(
            f"{self.BASE_URL}/combined/find",
            params={"email": query},
            headers={"Authorization": f"Basic {auth}"},
        )
        if "error" in data:
            return []
        return [self._wrap_result(
            "clearbit_enrichment",
            {"email": query, **data},
            confidence=0.85, relevance_score=0.9, tags=["clearbit", "people", "enrichment"],
        )]


# ═══════════════════════════════════════════════════════════
# SOCIAL MEDIA INTELLIGENCE
# ═══════════════════════════════════════════════════════════

@register_api
class GitHubAPI(BaseIntelAPI):
    NAME = "github"
    DESCRIPTION = "GitHub user/org OSINT — repos, contributions, email harvest"
    REQUIRES_KEY = False
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://api.github.com"
    DOCS_URL = "https://docs.github.com/en/rest"
    SIGN_UP_URL = "https://github.com/settings/tokens"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self._api_key:
            headers["Authorization"] = f"token {self._api_key}"

        results = []
        username_data = await self._get(f"{self.BASE_URL}/users/{query}", headers=headers)
        if "login" in username_data:
            repos = await self._get(
                f"{self.BASE_URL}/users/{query}/repos",
                params={"per_page": 30, "sort": "updated"},
                headers=headers,
            )
            events = await self._get(
                f"{self.BASE_URL}/users/{query}/events/public",
                params={"per_page": 30},
                headers=headers,
            )

            emails = set()
            for event in (events if isinstance(events, list) else []):
                payload = event.get("payload", {})
                for commit in payload.get("commits", []):
                    author = commit.get("author", {})
                    email = author.get("email", "")
                    if email and "noreply" not in email:
                        emails.add(email)

            results.append(self._wrap_result(
                "github_profile",
                {
                    "username": username_data.get("login"),
                    "name": username_data.get("name"),
                    "bio": username_data.get("bio"),
                    "email": username_data.get("email"),
                    "discovered_emails": list(emails),
                    "company": username_data.get("company"),
                    "location": username_data.get("location"),
                    "blog": username_data.get("blog"),
                    "twitter": username_data.get("twitter_username"),
                    "followers": username_data.get("followers"),
                    "following": username_data.get("following"),
                    "public_repos": username_data.get("public_repos"),
                    "created_at": username_data.get("created_at"),
                    "avatar_url": username_data.get("avatar_url"),
                    "repos": [
                        {
                            "name": r.get("name"),
                            "description": r.get("description"),
                            "language": r.get("language"),
                            "stars": r.get("stargazers_count"),
                            "url": r.get("html_url"),
                            "topics": r.get("topics", []),
                        }
                        for r in (repos if isinstance(repos, list) else [])[:20]
                    ],
                },
                confidence=1.0, relevance_score=0.8, tags=["github", "social", "developer"],
            ))
        else:
            search_data = await self._get(
                f"{self.BASE_URL}/search/users",
                params={"q": query, "per_page": 10},
                headers=headers,
            )
            if "items" in search_data:
                results.append(self._wrap_result(
                    "github_search",
                    {"query": query, "total": search_data.get("total_count"), "users": search_data["items"][:10]},
                    confidence=0.8, relevance_score=0.7, tags=["github", "search"],
                ))
        return results


@register_api
class TwitterXAPI(BaseIntelAPI):
    NAME = "twitter"
    DESCRIPTION = "X/Twitter user OSINT — profile, tweets, associations"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.SOCIAL]
    BASE_URL = "https://api.twitter.com/2"
    DOCS_URL = "https://developer.twitter.com/en/docs"
    SIGN_UP_URL = "https://developer.twitter.com/en/portal/dashboard"
    RATE_LIMIT_PER_MINUTE = 15

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        bearer = self.config.get_api_key("twitter_bearer") or self._api_key
        headers = {"Authorization": f"Bearer {bearer}"}

        username = query.lstrip("@")
        user_data = await self._get(
            f"{self.BASE_URL}/users/by/username/{username}",
            params={
                "user.fields": "description,location,public_metrics,created_at,url,entities,profile_image_url,verified"
            },
            headers=headers,
        )

        if "errors" in user_data or "data" not in user_data:
            return []

        user = user_data["data"]
        metrics = user.get("public_metrics", {})

        tweets_data = await self._get(
            f"{self.BASE_URL}/users/{user['id']}/tweets",
            params={"max_results": 20, "tweet.fields": "created_at,geo,entities,public_metrics"},
            headers=headers,
        )

        return [self._wrap_result(
            "twitter_profile",
            {
                "username": user.get("username"),
                "name": user.get("name"),
                "id": user.get("id"),
                "bio": user.get("description"),
                "location": user.get("location"),
                "url": user.get("url"),
                "created_at": user.get("created_at"),
                "verified": user.get("verified"),
                "followers": metrics.get("followers_count"),
                "following": metrics.get("following_count"),
                "tweet_count": metrics.get("tweet_count"),
                "profile_image": user.get("profile_image_url"),
                "recent_tweets": [
                    {
                        "text": t.get("text"),
                        "created_at": t.get("created_at"),
                        "likes": t.get("public_metrics", {}).get("like_count"),
                        "retweets": t.get("public_metrics", {}).get("retweet_count"),
                    }
                    for t in tweets_data.get("data", [])[:10]
                ],
            },
            confidence=0.95, relevance_score=0.8, tags=["twitter", "social", "profile"],
        )]


# ═══════════════════════════════════════════════════════════
# WHOIS & DOMAIN REGISTRATION
# ═══════════════════════════════════════════════════════════

@register_api
class WhoisXMLAPI(BaseIntelAPI):
    NAME = "whoisxml"
    DESCRIPTION = "WHOIS lookup with historical data and registrant info"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.DOMAIN]
    BASE_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    DOCS_URL = "https://whois.whoisxmlapi.com/documentation/making-requests"
    SIGN_UP_URL = "https://www.whoisxmlapi.com/sign-up.php"

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        data = await self._get(
            self.BASE_URL,
            params={
                "domainName": query,
                "apiKey": self._api_key,
                "outputFormat": "JSON",
                "prefetchWhoisData": 1,
            },
        )
        if "error" in data or "WhoisRecord" not in data:
            return []

        record = data["WhoisRecord"]
        registrant = record.get("registrant", {})
        return [self._wrap_result(
            "whois_record",
            {
                "domain": query,
                "registrar": record.get("registrarName"),
                "created_date": record.get("createdDate"),
                "updated_date": record.get("updatedDate"),
                "expires_date": record.get("expiresDate"),
                "status": record.get("status"),
                "nameservers": record.get("nameServers", {}).get("hostNames", []),
                "registrant_name": registrant.get("name"),
                "registrant_org": registrant.get("organization"),
                "registrant_email": registrant.get("email"),
                "registrant_country": registrant.get("country"),
                "privacy_protected": bool(registrant.get("organization", "").lower() in ["whoisguard", "domains by proxy", "privacy protect"]),
                "estimated_domain_age": record.get("estimatedDomainAge"),
                "contact_email": record.get("contactEmail"),
            },
            confidence=0.95, relevance_score=0.85, tags=["whois", "domain", "registration"],
        )]


@register_api
class LocalWHOISAPI(BaseIntelAPI):
    """Fallback WHOIS using local python-whois library — no API key needed."""
    NAME = "whois_local"
    DESCRIPTION = "Local WHOIS lookup — no API key required"
    REQUIRES_KEY = False
    TIER = APITier.FREE
    CATEGORIES = [APICategory.DOMAIN]

    async def search(self, query: str, **kwargs) -> List[Dict]:
        import whois as python_whois
        loop = __import__("asyncio").get_event_loop()
        try:
            data = await loop.run_in_executor(None, python_whois.whois, query)
            if not data:
                return []

            def safe_str(val):
                if isinstance(val, list):
                    return [str(v) for v in val]
                return str(val) if val else None

            return [self._wrap_result(
                "whois_record",
                {
                    "domain": query,
                    "registrar": safe_str(data.registrar),
                    "creation_date": safe_str(data.creation_date),
                    "expiration_date": safe_str(data.expiration_date),
                    "updated_date": safe_str(data.updated_date),
                    "nameservers": safe_str(data.name_servers),
                    "status": safe_str(data.status),
                    "emails": safe_str(data.emails),
                    "dnssec": safe_str(data.dnssec),
                    "name": safe_str(data.name),
                    "org": safe_str(data.org),
                    "country": safe_str(data.country),
                },
                confidence=0.9, relevance_score=0.8, tags=["whois", "domain"],
            )]
        except Exception:
            return []


# ═══════════════════════════════════════════════════════════
# SOCIAL MEDIA PLATFORMS
# ═══════════════════════════════════════════════════════════

@register_api
class RedditAPI(BaseIntelAPI):
    NAME = "reddit"
    DESCRIPTION = "Reddit user OSINT — karma, posts, active subreddits, account age"
    REQUIRES_KEY = False
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://www.reddit.com"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        username = query.lstrip("u/").lstrip("@")
        headers = {"User-Agent": "PhantomSignal-OSINT/1.0 (security research)"}

        user_data = await self._get(
            f"{self.BASE_URL}/user/{username}/about.json",
            headers=headers,
        )
        if "error" in user_data or "data" not in user_data:
            return []

        data = user_data["data"]

        posts_data = await self._get(
            f"{self.BASE_URL}/user/{username}/submitted.json",
            params={"limit": 25},
            headers=headers,
        )
        subreddits: set = set()
        recent_posts = []
        for child in posts_data.get("data", {}).get("children", []):
            p = child.get("data", {})
            if p.get("subreddit"):
                subreddits.add(p["subreddit"])
            recent_posts.append({
                "title": p.get("title"),
                "subreddit": p.get("subreddit"),
                "score": p.get("score"),
                "created_utc": p.get("created_utc"),
                "url": p.get("url"),
            })

        return [self._wrap_result(
            "reddit_profile",
            {
                "username": data.get("name"),
                "id": data.get("id"),
                "created_utc": data.get("created_utc"),
                "link_karma": data.get("link_karma"),
                "comment_karma": data.get("comment_karma"),
                "total_karma": data.get("total_karma"),
                "is_gold": data.get("is_gold"),
                "verified": data.get("verified"),
                "has_verified_email": data.get("has_verified_email"),
                "icon_img": data.get("icon_img"),
                "subreddits_active_in": sorted(subreddits)[:20],
                "recent_posts": recent_posts[:10],
                "profile_url": f"https://www.reddit.com/u/{username}",
            },
            confidence=0.95, relevance_score=0.75, tags=["reddit", "social", "profile"],
        )]


@register_api
class YouTubeAPI(BaseIntelAPI):
    NAME = "youtube"
    DESCRIPTION = "YouTube (Google) channel OSINT — subscribers, video count, metadata"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.SOCIAL]
    BASE_URL = "https://www.googleapis.com/youtube/v3"
    DOCS_URL = "https://developers.google.com/youtube/v3"
    SIGN_UP_URL = "https://console.cloud.google.com/apis/library/youtube.googleapis.com"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        key = self.config.get_api_key("youtube") or self._api_key

        search_data = await self._get(
            f"{self.BASE_URL}/search",
            params={"q": query, "type": "channel", "part": "snippet", "maxResults": 3, "key": key},
        )
        items = search_data.get("items", [])
        if not items:
            return []

        results = []
        for item in items[:3]:
            snippet = item.get("snippet", {})
            channel_id = item.get("id", {}).get("channelId")
            if not channel_id:
                continue

            stats_data = await self._get(
                f"{self.BASE_URL}/channels",
                params={"id": channel_id, "part": "statistics,brandingSettings", "key": key},
            )
            stats = {}
            branding = {}
            for ch in stats_data.get("items", []):
                stats = ch.get("statistics", {})
                branding = ch.get("brandingSettings", {}).get("channel", {})

            results.append(self._wrap_result(
                "youtube_channel",
                {
                    "channel_id": channel_id,
                    "title": snippet.get("title"),
                    "description": snippet.get("description"),
                    "published_at": snippet.get("publishedAt"),
                    "country": branding.get("country"),
                    "keywords": branding.get("keywords"),
                    "thumbnail": snippet.get("thumbnails", {}).get("default", {}).get("url"),
                    "subscriber_count": stats.get("subscriberCount"),
                    "video_count": stats.get("videoCount"),
                    "view_count": stats.get("viewCount"),
                    "hidden_subscriber_count": stats.get("hiddenSubscriberCount"),
                    "profile_url": f"https://www.youtube.com/channel/{channel_id}",
                },
                confidence=0.9, relevance_score=0.72, tags=["youtube", "google", "social", "channel"],
            ))
        return results


@register_api
class InstagramAPI(BaseIntelAPI):
    NAME = "instagram"
    DESCRIPTION = "Instagram (Meta) profile OSINT via Graph API — bio, follower count, posts"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://graph.facebook.com/v19.0"
    DOCS_URL = "https://developers.facebook.com/docs/instagram-basic-display-api"
    SIGN_UP_URL = "https://developers.facebook.com/apps"
    RATE_LIMIT_PER_MINUTE = 20

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        token = self.config.get_api_key("instagram") or self._api_key
        username = query.lstrip("@")

        # Business/Creator account lookup via Graph API
        await self._get(
            f"{self.BASE_URL}/ig_hashtag_search",
            params={"user_id": "me", "q": username, "access_token": token},
        )

        # Instagram user search by username (Business API)
        ig_data = await self._get(
            f"{self.BASE_URL}/{username}",
            params={
                "fields": "id,name,biography,followers_count,media_count,profile_picture_url,website",
                "access_token": token,
            },
        )

        if "error" in ig_data or ("id" not in ig_data and "name" not in ig_data):
            return []

        return [self._wrap_result(
            "instagram_profile",
            {
                "username": username,
                "id": ig_data.get("id"),
                "name": ig_data.get("name"),
                "bio": ig_data.get("biography"),
                "followers_count": ig_data.get("followers_count"),
                "media_count": ig_data.get("media_count"),
                "profile_picture_url": ig_data.get("profile_picture_url"),
                "website": ig_data.get("website"),
                "platform": "Instagram",
                "profile_url": f"https://www.instagram.com/{username}/",
            },
            confidence=0.85, relevance_score=0.8, tags=["instagram", "meta", "social", "profile"],
        )]


@register_api
class TikTokAPI(BaseIntelAPI):
    NAME = "tiktok"
    DESCRIPTION = "TikTok user OSINT via Research API — profile, follower count, video stats"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://open.tiktokapis.com/v2"
    DOCS_URL = "https://developers.tiktok.com/doc/research-api-specs-query-user-info"
    SIGN_UP_URL = "https://developers.tiktok.com"
    RATE_LIMIT_PER_MINUTE = 10

    async def _get_access_token(self) -> Optional[str]:
        client_key = self.config.get_api_key("tiktok_client_key")
        client_secret = self.config.get_api_key("tiktok_client_secret") or self._api_key
        if not client_key or not client_secret:
            return None

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                "https://open.tiktokapis.com/v2/oauth/token/",
                data={
                    "client_key": client_key,
                    "client_secret": client_secret,
                    "grant_type": "client_credentials",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if resp.status_code == 200:
            return resp.json().get("access_token")
        return None

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        token = await self._get_access_token()
        if not token:
            return []

        username = query.lstrip("@")
        await self._get(
            f"{self.BASE_URL}/research/user/info/",
            params={
                "fields": "display_name,bio_description,avatar_url,is_verified,follower_count,following_count,likes_count,video_count",
            },
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )

        # Research API uses POST for user lookup
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{self.BASE_URL}/research/user/info/",
                json={"username": username},
                params={"fields": "display_name,bio_description,avatar_url,is_verified,follower_count,following_count,likes_count,video_count"},
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
        if resp.status_code != 200:
            return []

        body = resp.json()
        user = body.get("data", {}).get("user", {})
        if not user:
            return []

        return [self._wrap_result(
            "tiktok_profile",
            {
                "username": username,
                "display_name": user.get("display_name"),
                "bio": user.get("bio_description"),
                "avatar_url": user.get("avatar_url"),
                "is_verified": user.get("is_verified"),
                "follower_count": user.get("follower_count"),
                "following_count": user.get("following_count"),
                "likes_count": user.get("likes_count"),
                "video_count": user.get("video_count"),
                "profile_url": f"https://www.tiktok.com/@{username}",
            },
            confidence=0.9, relevance_score=0.82, tags=["tiktok", "social", "profile"],
        )]


@register_api
class LinkedInAPI(BaseIntelAPI):
    NAME = "linkedin"
    DESCRIPTION = "LinkedIn profile OSINT via RapidAPI — name, headline, connections, company"
    REQUIRES_KEY = True
    TIER = APITier.FREEMIUM
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://linkedin-data-api.p.rapidapi.com"
    DOCS_URL = "https://rapidapi.com/rockapis-rockapis-default/api/linkedin-data-api"
    SIGN_UP_URL = "https://rapidapi.com/hub"
    RATE_LIMIT_PER_MINUTE = 10

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        rapidapi_key = self.config.get_api_key("linkedin_rapidapi") or self._api_key
        headers = {
            "x-rapidapi-host": "linkedin-data-api.p.rapidapi.com",
            "x-rapidapi-key": rapidapi_key,
        }

        # Try username/vanity URL lookup first
        username = query.lstrip("@").split("/")[-1]
        profile_data = await self._get(
            f"{self.BASE_URL}/get-profile-data-by-url",
            params={"url": f"https://www.linkedin.com/in/{username}/"},
            headers=headers,
        )

        if "error" in profile_data or not profile_data.get("firstName"):
            # Fall back to name search
            profile_data = await self._get(
                f"{self.BASE_URL}/search-people",
                params={"keywords": query, "start": "0"},
                headers=headers,
            )
            items = profile_data.get("items", [])
            if not items:
                return []
            profile_data = items[0]

        return [self._wrap_result(
            "linkedin_profile",
            {
                "first_name": profile_data.get("firstName"),
                "last_name": profile_data.get("lastName"),
                "headline": profile_data.get("headline"),
                "summary": profile_data.get("summary"),
                "location": profile_data.get("geoLocationName") or profile_data.get("locationName"),
                "industry": profile_data.get("industryName"),
                "connections": profile_data.get("connectionsCount"),
                "followers": profile_data.get("followersCount"),
                "company": profile_data.get("companyName"),
                "school": profile_data.get("educations", [{}])[0].get("schoolName") if profile_data.get("educations") else None,
                "profile_url": profile_data.get("profileUrl") or f"https://www.linkedin.com/in/{username}/",
                "avatar_url": profile_data.get("profilePicture"),
            },
            confidence=0.88, relevance_score=0.85, tags=["linkedin", "social", "professional", "profile"],
        )]


# ═══════════════════════════════════════════════════════════
# EXPANDED SOCIAL MEDIA INTELLIGENCE
# ═══════════════════════════════════════════════════════════

@register_api
class TwitchAPI(BaseIntelAPI):
    NAME = "twitch"
    DESCRIPTION = "Twitch streamer OSINT — followers, activity, channel data, stream history"
    REQUIRES_KEY = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://api.twitch.tv/helix"
    DOCS_URL = "https://dev.twitch.tv/docs/api/"
    SIGN_UP_URL = "https://dev.twitch.tv/console/apps/create"
    RATE_LIMIT_PER_MINUTE = 60

    @property
    def is_configured(self) -> bool:
        return bool(
            self.config.get_api_key("twitch_client_id")
            and self.config.get_api_key("twitch_client_secret")
        )

    async def _get_app_token(self) -> Optional[str]:
        client_id = self.config.get_api_key("twitch_client_id")
        client_secret = self.config.get_api_key("twitch_client_secret")
        data = await self._post(
            "https://id.twitch.tv/oauth2/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            },
        )
        return data.get("access_token")

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        if "@" in query or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
            return []

        token = await self._get_app_token()
        if not token:
            return []

        client_id = self.config.get_api_key("twitch_client_id")
        headers = {"Authorization": f"Bearer {token}", "Client-Id": client_id}

        user_data = await self._get(
            f"{self.BASE_URL}/users",
            params={"login": query.lstrip("@")},
            headers=headers,
        )
        users = user_data.get("data", [])
        if not users:
            return []

        user = users[0]
        user_id = user.get("id")

        channel_data = await self._get(
            f"{self.BASE_URL}/channels",
            params={"broadcaster_id": user_id},
            headers=headers,
        )
        channel = (channel_data.get("data") or [{}])[0]

        followers_data = await self._get(
            f"{self.BASE_URL}/channels/followers",
            params={"broadcaster_id": user_id, "first": 1},
            headers=headers,
        )

        streams_data = await self._get(
            f"{self.BASE_URL}/streams",
            params={"user_id": user_id},
            headers=headers,
        )
        live_stream = (streams_data.get("data") or [None])[0]

        return [self._wrap_result(
            "twitch_profile",
            {
                "username": user.get("login"),
                "display_name": user.get("display_name"),
                "id": user_id,
                "bio": user.get("description"),
                "profile_image_url": user.get("profile_image_url"),
                "view_count": user.get("view_count"),
                "broadcaster_type": user.get("broadcaster_type"),
                "created_at": user.get("created_at"),
                "game_name": channel.get("game_name"),
                "title": channel.get("title"),
                "language": channel.get("broadcaster_language"),
                "follower_count": followers_data.get("total"),
                "is_live": live_stream is not None,
                "viewer_count": live_stream.get("viewer_count") if live_stream else None,
                "profile_url": f"https://www.twitch.tv/{user.get('login')}",
            },
            confidence=0.97, relevance_score=0.82,
            tags=["twitch", "social", "gaming", "streamer"],
        )]


@register_api
class MastodonAPI(BaseIntelAPI):
    NAME = "mastodon"
    DESCRIPTION = "Mastodon/Fediverse profile lookup — federated social network search across instances"
    REQUIRES_KEY = False
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://mastodon.social/api/v2"
    DOCS_URL = "https://docs.joinmastodon.org/api/"
    SIGN_UP_URL = "https://mastodon.social"
    RATE_LIMIT_PER_MINUTE = 30

    _INSTANCES = [
        "https://mastodon.social",
        "https://infosec.exchange",
        "https://fosstodon.org",
        "https://hachyderm.io",
    ]

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if "@" in query and "." in query.split("@")[-1]:
            # Full fediverse handle: @user@instance
            parts = query.lstrip("@").split("@")
            username, instance = parts[0], parts[1]
            instances_to_try = [f"https://{instance}"]
        else:
            username = query.lstrip("@")
            instances_to_try = self._INSTANCES

        results = []
        seen_accts = set()

        for base in instances_to_try:
            # resolve=true requires auth on most instances; omit for anonymous search
            data = await self._get(
                f"{base}/api/v2/search",
                params={"q": username, "type": "accounts", "limit": 3},
            )
            for account in data.get("accounts", []):
                acct = account.get("acct", "")
                if acct in seen_accts:
                    continue
                if username.lower() not in acct.lower():
                    continue
                seen_accts.add(acct)
                results.append(self._wrap_result(
                    "mastodon_profile",
                    {
                        "username": acct,
                        "display_name": account.get("display_name"),
                        "bio": re.sub(r"<[^>]+>", "", account.get("note", "")),
                        "followers_count": account.get("followers_count"),
                        "following_count": account.get("following_count"),
                        "statuses_count": account.get("statuses_count"),
                        "created_at": account.get("created_at"),
                        "url": account.get("url"),
                        "avatar": account.get("avatar_static"),
                        "bot": account.get("bot"),
                        "fields": [
                            {"name": f.get("name"), "value": re.sub(r"<[^>]+>", "", f.get("value", ""))}
                            for f in account.get("fields", [])
                        ],
                    },
                    confidence=0.9, relevance_score=0.75,
                    tags=["mastodon", "fediverse", "social"],
                ))
        return results


@register_api
class KeybaseAPI(BaseIntelAPI):
    NAME = "keybase"
    DESCRIPTION = "Keybase verified identity lookup — cross-platform social proof, PGP keys"
    REQUIRES_KEY = False
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://keybase.io/_/api/1.0"
    DOCS_URL = "https://keybase.io/docs/api/1.0"
    SIGN_UP_URL = "https://keybase.io"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if "@" in query:
            return []
        username = query.lstrip("@")
        data = await self._get(
            f"{self.BASE_URL}/user/lookup.json",
            params={"usernames": username, "fields": "basics,profile,proofs_summary,pgp_keys"},
        )
        if data.get("status", {}).get("code") != 0:
            return []

        them = (data.get("them") or [None])[0]
        if not them:
            return []

        basics = them.get("basics", {})
        profile = them.get("profile", {})
        proofs = them.get("proofs_summary", {}).get("all", [])

        proof_map = {}
        for proof in proofs:
            service = proof.get("proof_type", "")
            proof_map.setdefault(service, []).append(proof.get("nametag") or proof.get("service_url", ""))

        pgp_keys = [
            {"fingerprint": k.get("key_fingerprint"), "bits": k.get("bits")}
            for k in them.get("pgp_keys", [])
        ]

        return [self._wrap_result(
            "keybase_identity",
            {
                "username": basics.get("username"),
                "uid": basics.get("uid"),
                "full_name": profile.get("full_name"),
                "bio": profile.get("bio"),
                "location": profile.get("location"),
                "twitter": proof_map.get("twitter", [None])[0],
                "github": proof_map.get("github", [None])[0],
                "reddit": proof_map.get("reddit", [None])[0],
                "hackernews": proof_map.get("hackernews", [None])[0],
                "website": proof_map.get("generic_web_site", [None])[0],
                "all_proofs": proof_map,
                "pgp_keys": pgp_keys,
                "pgp_key_count": len(pgp_keys),
                "profile_url": f"https://keybase.io/{basics.get('username')}",
            },
            confidence=0.99, relevance_score=0.9,
            tags=["keybase", "identity", "pgp", "social_proof"],
        )]


@register_api
class GravatarAPI(BaseIntelAPI):
    NAME = "gravatar"
    DESCRIPTION = "Gravatar email-linked global avatar and profile lookup"
    REQUIRES_KEY = False
    TIER = APITier.FREE
    CATEGORIES = [APICategory.PEOPLE, APICategory.EMAIL]
    BASE_URL = "https://www.gravatar.com"
    DOCS_URL = "https://gravatar.com/site/implement/profiles/json/"
    SIGN_UP_URL = "https://gravatar.com"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if "@" not in query:
            return []
        import hashlib
        email_hash = hashlib.md5(query.strip().lower().encode()).hexdigest()
        data = await self._get(f"{self.BASE_URL}/{email_hash}.json")
        if "error" in data or "entry" not in data:
            return []

        entry = data["entry"][0]
        accounts = [
            {"domain": a.get("domain"), "url": a.get("url"), "username": a.get("username", {}).get("value")}
            for a in entry.get("accounts", [])
        ]
        photos = [p.get("value") for p in entry.get("photos", [])]

        return [self._wrap_result(
            "gravatar_profile",
            {
                "email": query,
                "email_hash": email_hash,
                "username": entry.get("preferredUsername"),
                "display_name": entry.get("displayName"),
                "about": entry.get("aboutMe"),
                "location": entry.get("currentLocation"),
                "avatar_url": photos[0] if photos else f"https://www.gravatar.com/avatar/{email_hash}",
                "profile_url": entry.get("profileUrl") or f"https://www.gravatar.com/{email_hash}",
                "accounts": accounts,
                "urls": [u.get("value") for u in entry.get("urls", [])],
            },
            confidence=0.97, relevance_score=0.88,
            tags=["gravatar", "email", "profile", "identity"],
        )]


@register_api
class HackerNewsAPI(BaseIntelAPI):
    NAME = "hackernews"
    DESCRIPTION = "Hacker News user OSINT — karma, submissions, account age, bio"
    REQUIRES_KEY = False
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://hacker-news.firebaseio.com/v0"
    DOCS_URL = "https://github.com/HackerNews/API"
    SIGN_UP_URL = "https://news.ycombinator.com"
    RATE_LIMIT_PER_MINUTE = 60

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if "@" in query or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
            return []
        username = query.lstrip("@")
        data = await self._get(f"{self.BASE_URL}/user/{username}.json")
        if not data or "error" in data or not data.get("id"):
            return []

        import datetime as dt
        created_ts = data.get("created", 0)
        created_str = dt.datetime.utcfromtimestamp(created_ts).isoformat() if created_ts else None

        submitted = data.get("submitted", [])
        return [self._wrap_result(
            "hackernews_profile",
            {
                "username": data.get("id"),
                "karma": data.get("karma"),
                "about": re.sub(r"<[^>]+>", "", data.get("about") or ""),
                "created_at": created_str,
                "submission_count": len(submitted),
                "recent_items": submitted[:10],
                "profile_url": f"https://news.ycombinator.com/user?id={data.get('id')}",
            },
            confidence=0.98, relevance_score=0.78,
            tags=["hackernews", "hn", "social", "developer"],
        )]


@register_api
class TumblrAPI(BaseIntelAPI):
    NAME = "tumblr"
    DESCRIPTION = "Tumblr blog OSINT — posts, activity, theme, description"
    REQUIRES_KEY = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://api.tumblr.com/v2"
    DOCS_URL = "https://www.tumblr.com/docs/en/api/v2"
    SIGN_UP_URL = "https://www.tumblr.com/oauth/apps"
    RATE_LIMIT_PER_MINUTE = 60

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        if "@" in query or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
            return []

        blogname = query.lstrip("@")
        identifier = blogname if "." in blogname else f"{blogname}.tumblr.com"

        data = await self._get(
            f"{self.BASE_URL}/blog/{identifier}/info",
            params={"api_key": self._api_key},
        )
        if "error" in data or data.get("meta", {}).get("status", 0) != 200:
            return []

        blog = data.get("response", {}).get("blog", {})
        if not blog.get("name"):
            return []

        return [self._wrap_result(
            "tumblr_blog",
            {
                "name": blog.get("name"),
                "title": blog.get("title"),
                "description": re.sub(r"<[^>]+>", "", blog.get("description") or ""),
                "url": blog.get("url"),
                "total_posts": blog.get("total_posts"),
                "updated": blog.get("updated"),
                "is_nsfw": blog.get("is_nsfw"),
                "avatar": f"https://api.tumblr.com/v2/blog/{identifier}/avatar/512",
                "profile_url": blog.get("url") or f"https://{identifier}",
            },
            confidence=0.93, relevance_score=0.76,
            tags=["tumblr", "social", "blog"],
        )]


@register_api
class FlickrAPI(BaseIntelAPI):
    NAME = "flickr"
    DESCRIPTION = "Flickr photo platform OSINT — profile, photo count, geolocation data, albums"
    REQUIRES_KEY = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://www.flickr.com/services/rest"
    DOCS_URL = "https://www.flickr.com/services/api/"
    SIGN_UP_URL = "https://www.flickr.com/services/apps/create/"
    RATE_LIMIT_PER_MINUTE = 60

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
            return []

        base_params = {"api_key": self._api_key, "format": "json", "nojsoncallback": 1}

        # Find by username or email
        if "@" in query:
            find_data = await self._get(self.BASE_URL, params={
                **base_params, "method": "flickr.people.findByEmail", "find_email": query,
            })
        else:
            find_data = await self._get(self.BASE_URL, params={
                **base_params, "method": "flickr.people.findByUsername", "username": query,
            })

        if find_data.get("stat") != "ok":
            return []

        user_id = find_data.get("user", {}).get("id")
        if not user_id:
            return []

        info_data = await self._get(self.BASE_URL, params={
            **base_params, "method": "flickr.people.getInfo", "user_id": user_id,
        })
        if info_data.get("stat") != "ok":
            return []

        person = info_data.get("person", {})
        photos = person.get("photos", {})

        return [self._wrap_result(
            "flickr_profile",
            {
                "nsid": user_id,
                "username": person.get("username", {}).get("_content"),
                "realname": person.get("realname", {}).get("_content"),
                "description": person.get("description", {}).get("_content"),
                "location": person.get("location", {}).get("_content"),
                "timezone": person.get("timezone", {}).get("label"),
                "photo_count": photos.get("count", {}).get("_content"),
                "first_date": photos.get("firstdate", {}).get("_content"),
                "first_date_taken": photos.get("firstdatetaken", {}).get("_content"),
                "profile_url": person.get("profileurl", {}).get("_content"),
                "photos_url": person.get("photosurl", {}).get("_content"),
                "avatar_url": f"https://farm{person.get('iconfarm')}.staticflickr.com/{person.get('iconserver')}/buddyicons/{user_id}.jpg",
                "is_pro": bool(person.get("ispro")),
                "can_buy_pro": bool(person.get("can_buy_pro")),
            },
            confidence=0.95, relevance_score=0.78,
            tags=["flickr", "social", "photos", "creative"],
        )]


@register_api
class SpotifyAPI(BaseIntelAPI):
    NAME = "spotify"
    DESCRIPTION = "Spotify public profile OSINT — playlists, followers, listening activity"
    REQUIRES_KEY = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://api.spotify.com/v1"
    DOCS_URL = "https://developer.spotify.com/documentation/web-api"
    SIGN_UP_URL = "https://developer.spotify.com/dashboard"
    RATE_LIMIT_PER_MINUTE = 60

    @property
    def is_configured(self) -> bool:
        return bool(
            self.config.get_api_key("spotify_client_id")
            and self.config.get_api_key("spotify_client_secret")
        )

    async def _get_token(self) -> Optional[str]:
        import base64
        client_id = self.config.get_api_key("spotify_client_id")
        client_secret = self.config.get_api_key("spotify_client_secret")
        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        data = await self._post(
            "https://accounts.spotify.com/api/token",
            data={"grant_type": "client_credentials"},
            headers={"Authorization": f"Basic {credentials}", "Content-Type": "application/x-www-form-urlencoded"},
        )
        return data.get("access_token")

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        if "@" in query or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
            return []

        token = await self._get_token()
        if not token:
            return []

        headers = {"Authorization": f"Bearer {token}"}
        username = query.lstrip("@")

        # Try direct user profile lookup first
        user_data = await self._get(f"{self.BASE_URL}/users/{username}", headers=headers)
        if "error" not in user_data and user_data.get("id"):
            playlists = await self._get(
                f"{self.BASE_URL}/users/{username}/playlists",
                params={"limit": 10},
                headers=headers,
            )
            return [self._wrap_result(
                "spotify_profile",
                {
                    "id": user_data.get("id"),
                    "display_name": user_data.get("display_name"),
                    "follower_count": user_data.get("followers", {}).get("total"),
                    "images": [i.get("url") for i in user_data.get("images", [])],
                    "external_url": user_data.get("external_urls", {}).get("spotify"),
                    "playlist_count": playlists.get("total"),
                    "public_playlists": [
                        {"name": p.get("name"), "tracks": p.get("tracks", {}).get("total"), "url": p.get("external_urls", {}).get("spotify")}
                        for p in playlists.get("items", [])[:5]
                    ],
                    "profile_url": user_data.get("external_urls", {}).get("spotify"),
                },
                confidence=0.94, relevance_score=0.77,
                tags=["spotify", "social", "music"],
            )]

        # Fall back to artist search
        search_data = await self._get(
            f"{self.BASE_URL}/search",
            params={"q": username, "type": "user", "limit": 3},
            headers=headers,
        )
        results = []
        for item in search_data.get("users", {}).get("items", []):
            if item:
                results.append(self._wrap_result(
                    "spotify_profile",
                    {
                        "id": item.get("id"),
                        "display_name": item.get("display_name"),
                        "follower_count": item.get("followers", {}).get("total"),
                        "external_url": item.get("external_urls", {}).get("spotify"),
                        "profile_url": item.get("external_urls", {}).get("spotify"),
                    },
                    confidence=0.8, relevance_score=0.7,
                    tags=["spotify", "social", "music"],
                ))
        return results


@register_api
class SteamAPI(BaseIntelAPI):
    NAME = "steam"
    DESCRIPTION = "Steam gaming platform OSINT — profile, game library, play hours, groups"
    REQUIRES_KEY = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://api.steampowered.com"
    DOCS_URL = "https://steamcommunity.com/dev/apikey"
    SIGN_UP_URL = "https://steamcommunity.com/dev/apikey"
    RATE_LIMIT_PER_MINUTE = 60

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        if "@" in query or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
            return []

        username = query.lstrip("@")
        key = self._api_key

        # Resolve vanity URL → SteamID64
        vanity = await self._get(
            f"{self.BASE_URL}/ISteamUser/ResolveVanityURL/v1/",
            params={"key": key, "vanityurl": username},
        )
        if vanity.get("response", {}).get("success") != 1:
            # Try as raw 64-bit SteamID
            if not re.match(r"^\d{17}$", username):
                return []
            steam_id = username
        else:
            steam_id = vanity["response"]["steamid"]

        summary = await self._get(
            f"{self.BASE_URL}/ISteamUser/GetPlayerSummaries/v2/",
            params={"key": key, "steamids": steam_id},
        )
        players = summary.get("response", {}).get("players", [])
        if not players:
            return []
        player = players[0]

        games_data = await self._get(
            f"{self.BASE_URL}/IPlayerService/GetOwnedGames/v1/",
            params={"key": key, "steamid": steam_id, "include_appinfo": 1, "include_played_free_games": 1},
        )
        games = games_data.get("response", {})
        game_count = games.get("game_count", 0)
        total_hours = sum(g.get("playtime_forever", 0) for g in games.get("games", [])) / 60

        import datetime as dt
        created = player.get("timecreated")
        created_str = dt.datetime.utcfromtimestamp(created).isoformat() if created else None

        return [self._wrap_result(
            "steam_profile",
            {
                "steam_id": steam_id,
                "username": player.get("personaname"),
                "real_name": player.get("realname"),
                "profile_url": player.get("profileurl"),
                "avatar_url": player.get("avatarfull"),
                "country": player.get("loccountrycode"),
                "state": player.get("locstatecode"),
                "community_visibility": player.get("communityvisibilitystate"),
                "profile_state": player.get("profilestate"),
                "last_logoff": dt.datetime.utcfromtimestamp(player.get("lastlogoff", 0)).isoformat() if player.get("lastlogoff") else None,
                "created_at": created_str,
                "current_game": player.get("gameextrainfo"),
                "game_count": game_count,
                "total_play_hours": round(total_hours, 1),
            },
            confidence=0.97, relevance_score=0.83,
            tags=["steam", "gaming", "social", "profile"],
        )]


@register_api
class VkAPI(BaseIntelAPI):
    NAME = "vk"
    DESCRIPTION = "VKontakte (VK) social network OSINT — profile, friends, photos, groups"
    REQUIRES_KEY = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://api.vk.com/method"
    DOCS_URL = "https://vk.com/dev/first_guide"
    SIGN_UP_URL = "https://vk.com/dev/access_token"
    RATE_LIMIT_PER_MINUTE = 60

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        base_params = {"access_token": self._api_key, "v": "5.199"}
        is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query)
        if is_ip:
            return []

        if "@" in query:
            # Search by name
            search_data = await self._get(f"{self.BASE_URL}/users.search", params={
                **base_params, "q": query, "count": 5, "fields": "screen_name,photo_max,city,country",
            })
            users = search_data.get("response", {}).get("items", [])
        else:
            # Direct lookup by screen_name or ID
            user_data = await self._get(f"{self.BASE_URL}/users.get", params={
                **base_params,
                "user_ids": query.lstrip("@"),
                "fields": "screen_name,photo_max,bdate,city,country,followers_count,occupation,education,site,status,verified",
            })
            users = user_data.get("response", [])

        results = []
        for user in users[:3]:
            if user.get("deactivated"):
                continue
            city = user.get("city", {}).get("title") if isinstance(user.get("city"), dict) else None
            country = user.get("country", {}).get("title") if isinstance(user.get("country"), dict) else None
            results.append(self._wrap_result(
                "vk_profile",
                {
                    "id": user.get("id"),
                    "first_name": user.get("first_name"),
                    "last_name": user.get("last_name"),
                    "screen_name": user.get("screen_name"),
                    "status": user.get("status"),
                    "bdate": user.get("bdate"),
                    "city": city,
                    "country": country,
                    "followers_count": user.get("followers_count"),
                    "verified": bool(user.get("verified")),
                    "photo_url": user.get("photo_max"),
                    "site": user.get("site"),
                    "occupation": user.get("occupation", {}).get("name") if isinstance(user.get("occupation"), dict) else None,
                    "profile_url": f"https://vk.com/{user.get('screen_name') or 'id' + str(user.get('id', ''))}",
                },
                confidence=0.9, relevance_score=0.8,
                tags=["vk", "vkontakte", "social", "russia"],
            ))
        return results


@register_api
class TelegramChannelAPI(BaseIntelAPI):
    NAME = "telegram"
    DESCRIPTION = "Telegram public channel, group, and bot OSINT via Bot API"
    REQUIRES_KEY = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://api.telegram.org"
    DOCS_URL = "https://core.telegram.org/bots/api"
    SIGN_UP_URL = "https://t.me/BotFather"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        if "@" in query and "." in query.split("@")[-1]:
            return []
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
            return []

        token = self._api_key
        username = "@" + query.lstrip("@")

        data = await self._post(
            f"{self.BASE_URL}/bot{token}/getChat",
            json={"chat_id": username},
        )
        if not data.get("ok"):
            return []

        chat = data.get("result", {})
        chat_type = chat.get("type", "")
        member_count = None
        if chat_type in ("channel", "supergroup", "group"):
            count_data = await self._post(
                f"{self.BASE_URL}/bot{token}/getChatMemberCount",
                json={"chat_id": username},
            )
            if count_data.get("ok"):
                member_count = count_data.get("result")

        photo_url = None
        photo = chat.get("photo")
        if photo:
            file_id = photo.get("big_file_id") or photo.get("small_file_id")
            if file_id:
                file_data = await self._post(
                    f"{self.BASE_URL}/bot{token}/getFile",
                    json={"file_id": file_id},
                )
                if file_data.get("ok"):
                    file_path = file_data.get("result", {}).get("file_path")
                    if file_path:
                        photo_url = f"https://api.telegram.org/file/bot{token}/{file_path}"

        return [self._wrap_result(
            "telegram_channel",
            {
                "id": chat.get("id"),
                "type": chat_type,
                "username": chat.get("username"),
                "title": chat.get("title") or chat.get("first_name"),
                "description": chat.get("description") or chat.get("bio"),
                "member_count": member_count,
                "invite_link": chat.get("invite_link"),
                "photo_url": photo_url,
                "linked_chat_id": chat.get("linked_chat_id"),
                "is_verified": chat.get("is_verified"),
                "is_scam": chat.get("is_scam"),
                "is_fake": chat.get("is_fake"),
                "profile_url": f"https://t.me/{chat.get('username')}" if chat.get("username") else None,
            },
            confidence=0.98, relevance_score=0.84,
            tags=["telegram", "social", "messaging"] + (["scam"] if chat.get("is_scam") else []),
            is_anomaly=bool(chat.get("is_scam") or chat.get("is_fake")),
        )]


@register_api
class DiscordAPI(BaseIntelAPI):
    NAME = "discord"
    DESCRIPTION = "Discord user lookup by snowflake ID via Bot API — avatar, badges, account age"
    REQUIRES_KEY = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://discord.com/api/v10"
    DOCS_URL = "https://discord.com/developers/docs/intro"
    SIGN_UP_URL = "https://discord.com/developers/applications"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        if "@" in query or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
            return []

        token = self._api_key
        headers = {"Authorization": f"Bot {token}"}

        # Accept either a numeric snowflake ID or a guild invite code
        query = query.strip().lstrip("@")

        if re.match(r"^\d{15,22}$", query):
            # Snowflake ID — direct user lookup
            data = await self._get(f"{self.BASE_URL}/users/{query}", headers=headers)
            if "code" in data:
                return []

            import datetime as dt
            # Decode snowflake timestamp (Discord epoch: 2015-01-01)
            discord_epoch = 1420070400000
            ts_ms = (int(query) >> 22) + discord_epoch
            created_at = dt.datetime.utcfromtimestamp(ts_ms / 1000).isoformat()

            avatar_hash = data.get("avatar")
            avatar_url = (
                f"https://cdn.discordapp.com/avatars/{query}/{avatar_hash}.{'gif' if avatar_hash and avatar_hash.startswith('a_') else 'png'}"
                if avatar_hash else None
            )

            flags = data.get("public_flags", 0)
            badges = [
                name for name, bit in [
                    ("Discord Staff", 1), ("Partnered Server Owner", 2), ("HypeSquad Events", 4),
                    ("Bug Hunter Level 1", 8), ("HypeSquad Bravery", 64), ("HypeSquad Brilliance", 128),
                    ("HypeSquad Balance", 256), ("Early Supporter", 512), ("Bug Hunter Level 2", 16384),
                    ("Verified Bot Developer", 131072), ("Active Developer", 4194304),
                ]
                if flags & bit
            ]

            return [self._wrap_result(
                "discord_user",
                {
                    "id": data.get("id"),
                    "username": data.get("username"),
                    "global_name": data.get("global_name"),
                    "discriminator": data.get("discriminator"),
                    "avatar_url": avatar_url,
                    "banner_color": data.get("banner_color"),
                    "accent_color": data.get("accent_color"),
                    "bot": data.get("bot", False),
                    "system": data.get("system", False),
                    "public_flags": flags,
                    "badges": badges,
                    "created_at": created_at,
                    "profile_url": f"https://discord.com/users/{query}",
                },
                confidence=1.0, relevance_score=0.86,
                tags=["discord", "social", "gaming"] + badges,
            )]

        # Try as a guild invite code to get server info
        invite_data = await self._get(
            f"{self.BASE_URL}/invites/{query}",
            params={"with_counts": "true", "with_expiration": "true"},
            headers=headers,
        )
        if "code" in invite_data and invite_data.get("type") is None:
            return []

        guild = invite_data.get("guild", {})
        if not guild:
            return []

        return [self._wrap_result(
            "discord_server",
            {
                "invite_code": query,
                "guild_id": guild.get("id"),
                "name": guild.get("name"),
                "description": guild.get("description"),
                "member_count": invite_data.get("approximate_member_count"),
                "online_count": invite_data.get("approximate_presence_count"),
                "verification_level": guild.get("verification_level"),
                "nsfw": guild.get("nsfw"),
                "features": guild.get("features", []),
                "invite_url": f"https://discord.gg/{query}",
            },
            confidence=0.95, relevance_score=0.8,
            tags=["discord", "server", "community"],
        )]


@register_api
class FacebookAPI(BaseIntelAPI):
    NAME = "facebook"
    DESCRIPTION = "Facebook/Meta Graph API — public page lookup, fan count, contact info"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://graph.facebook.com/v19.0"
    DOCS_URL = "https://developers.facebook.com/docs/graph-api"
    SIGN_UP_URL = "https://developers.facebook.com/apps"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []
        is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query)
        if is_ip:
            return []

        token = self._api_key
        username = query.lstrip("@")

        # Direct page/profile slug lookup
        page_data = await self._get(
            f"{self.BASE_URL}/{username}",
            params={
                "fields": "id,name,about,fan_count,followers_count,location,website,emails,phone,username,verification_status,category",
                "access_token": token,
            },
        )
        if "error" not in page_data and page_data.get("id"):
            return [self._wrap_result(
                "facebook_page",
                {
                    "id": page_data.get("id"),
                    "name": page_data.get("name"),
                    "username": page_data.get("username"),
                    "about": page_data.get("about"),
                    "category": page_data.get("category"),
                    "fan_count": page_data.get("fan_count"),
                    "followers_count": page_data.get("followers_count"),
                    "location": page_data.get("location"),
                    "website": page_data.get("website"),
                    "emails": page_data.get("emails", []),
                    "phone": page_data.get("phone"),
                    "verified": page_data.get("verification_status") == "blue_verified",
                    "profile_url": f"https://www.facebook.com/{username}",
                },
                confidence=0.92, relevance_score=0.82,
                tags=["facebook", "meta", "social", "page"],
            )]

        # Page search
        search_data = await self._get(
            f"{self.BASE_URL}/search",
            params={
                "q": username,
                "type": "page",
                "fields": "id,name,about,fan_count,category",
                "access_token": token,
                "limit": 5,
            },
        )
        results = []
        for page in search_data.get("data", [])[:3]:
            results.append(self._wrap_result(
                "facebook_page",
                {
                    "id": page.get("id"),
                    "name": page.get("name"),
                    "about": page.get("about"),
                    "category": page.get("category"),
                    "fan_count": page.get("fan_count"),
                    "profile_url": f"https://www.facebook.com/{page.get('id')}",
                },
                confidence=0.8, relevance_score=0.72,
                tags=["facebook", "meta", "social", "page"],
            ))
        return results


# ═══════════════════════════════════════════════════════════
# EMAIL & BREACH INTELLIGENCE — EXPANDED
# ═══════════════════════════════════════════════════════════

@register_api
class EmailRepAPI(BaseIntelAPI):
    NAME = "emailrep"
    DESCRIPTION = "Email reputation — spam score, breach status, profiles, deliverability"
    REQUIRES_KEY = False
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.EMAIL, APICategory.PEOPLE, APICategory.BREACH]
    BASE_URL = "https://emailrep.io"
    DOCS_URL = "https://docs.emailrep.io"
    SIGN_UP_URL = "https://emailrep.io/key"
    RATE_LIMIT_PER_MINUTE = 10

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if "@" not in query:
            return []

        headers = {"User-Agent": "PhantomSignal-OSINT/1.0"}
        if self._api_key:
            headers["Key"] = self._api_key

        data = await self._get(f"{self.BASE_URL}/{query}", headers=headers)
        if "error" in data or not data.get("email"):
            return []

        details = data.get("details", {})
        is_suspicious = data.get("suspicious", False)
        profiles = details.get("profiles", [])

        return [self._wrap_result(
            "email_reputation",
            {
                "email": query,
                "reputation": data.get("reputation"),
                "suspicious": is_suspicious,
                "references": data.get("references"),
                "blacklisted": details.get("blacklisted"),
                "malicious_activity": details.get("malicious_activity"),
                "malicious_activity_recent": details.get("malicious_activity_recent"),
                "credentials_leaked": details.get("credentials_leaked"),
                "credentials_leaked_recent": details.get("credentials_leaked_recent"),
                "data_breach": details.get("data_breach"),
                "first_seen": details.get("first_seen"),
                "last_seen": details.get("last_seen"),
                "domain_exists": details.get("domain_exists"),
                "domain_reputation": details.get("domain_reputation"),
                "new_domain": details.get("new_domain"),
                "days_since_domain_creation": details.get("days_since_domain_creation"),
                "suspicious_tld": details.get("suspicious_tld"),
                "spam": details.get("spam"),
                "free_provider": details.get("free_provider"),
                "disposable": details.get("disposable"),
                "deliverable": details.get("deliverable"),
                "accept_all": details.get("accept_all"),
                "valid_mx": details.get("valid_mx"),
                "profiles": profiles,
                "sport_found_on": profiles,
            },
            confidence=0.92, relevance_score=0.88,
            tags=["emailrep", "email", "reputation"] + (["suspicious", "breach"] if is_suspicious else []),
            is_anomaly=is_suspicious,
        )]


@register_api
class IntelligenceXAPI(BaseIntelAPI):
    NAME = "intelx"
    DESCRIPTION = "Intelligence X — dark web, leaks, breach data, and paste search"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.BREACH, APICategory.DARK_WEB, APICategory.EMAIL, APICategory.PEOPLE]
    BASE_URL = "https://2.intelx.io"
    DOCS_URL = "https://intelx.io/product#api"
    SIGN_UP_URL = "https://intelx.io/signup"
    RATE_LIMIT_PER_MINUTE = 10

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        headers = {"x-key": self._api_key, "Content-Type": "application/json"}

        # Initiate search
        search_resp = await self._post(
            f"{self.BASE_URL}/intelligent/search",
            json={
                "term": query,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": 20,
                "timeout": 5,
                "datefrom": "",
                "dateto": "",
                "sort": 4,
                "media": 0,
                "terminate": [],
            },
            headers=headers,
        )
        if "error" in search_resp or not search_resp.get("id"):
            return []

        search_id = search_resp["id"]

        # Brief pause then fetch results
        await asyncio.sleep(2)

        results_resp = await self._get(
            f"{self.BASE_URL}/intelligent/search/result",
            params={"id": search_id, "limit": 20, "offset": 0},
            headers={"x-key": self._api_key},
        )

        records = results_resp.get("records", [])
        if not records:
            return []

        hits = [
            {
                "name": r.get("name"),
                "bucket": r.get("bucket"),
                "type": r.get("type"),
                "date": r.get("date"),
                "size": r.get("size"),
                "media": r.get("media"),
            }
            for r in records[:20]
        ]

        return [self._wrap_result(
            "intelx_leak",
            {
                "query": query,
                "total_hits": results_resp.get("total", len(hits)),
                "hits": hits,
                "buckets": list({h.get("bucket") for h in hits if h.get("bucket")}),
            },
            confidence=0.85, relevance_score=0.9,
            tags=["intelx", "breach", "darkweb", "leak"],
            is_anomaly=len(hits) > 0,
        )]


# ═══════════════════════════════════════════════════════════
# PHONE INTELLIGENCE
# ═══════════════════════════════════════════════════════════

@register_api
class AbstractPhoneAPI(BaseIntelAPI):
    NAME = "abstractapi_phone"
    DESCRIPTION = "Phone number validation — carrier, line type, location, WhatsApp-compatible format"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.PEOPLE]
    BASE_URL = "https://phonevalidation.abstractapi.com/v1"
    DOCS_URL = "https://app.abstractapi.com/api/phone-validation/documentation"
    SIGN_UP_URL = "https://app.abstractapi.com/api/phone-validation/pricing/select"
    RATE_LIMIT_PER_MINUTE = 3

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        # Only act on phone-like strings
        clean = re.sub(r"[^\d+]", "", query)
        if len(clean) < 7 or "@" in query or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
            return []

        data = await self._get(
            self.BASE_URL,
            params={"api_key": self._api_key, "phone": clean},
        )
        if "error" in data or not data.get("phone"):
            return []

        return [self._wrap_result(
            "phone_validation",
            {
                "phone": data.get("phone"),
                "valid": data.get("valid"),
                "format": data.get("format", {}),
                "country": data.get("country", {}),
                "location": data.get("location"),
                "type": data.get("type"),
                "carrier": data.get("carrier"),
                "international_format": data.get("format", {}).get("international"),
                "local_format": data.get("format", {}).get("local"),
                "country_code": data.get("country", {}).get("code"),
                "country_name": data.get("country", {}).get("name"),
                "country_prefix": data.get("country", {}).get("prefix"),
            },
            confidence=0.96, relevance_score=0.85,
            tags=["phone", "carrier", "validation"],
        )]


# ═══════════════════════════════════════════════════════════
# CUSTOM API TEMPLATE
# ═══════════════════════════════════════════════════════════

@register_api
class CustomAPI(BaseIntelAPI):
    """
    PhantomSignal Custom API Integration — Plug in any REST/JSON API.
    Configure via phantomsignal.yaml or the Settings UI.

    Example config:
        api_keys:
          custom: "your-key-here"
        custom_api:
          base_url: "https://api.example.com/v1"
          auth_header: "X-API-Key"
          search_path: "/search"
          query_param: "q"
    """
    NAME = "custom"
    DESCRIPTION = "User-defined custom API integration"
    REQUIRES_KEY = False
    TIER = APITier.FREE
    CATEGORIES = []

    async def search(self, query: str, **kwargs) -> List[Dict]:
        custom_config = self.config.get("custom_api") or {}
        if not custom_config.get("base_url"):
            return []

        base_url = custom_config["base_url"].rstrip("/")
        auth_header = custom_config.get("auth_header", "Authorization")
        search_path = custom_config.get("search_path", "/search")
        query_param = custom_config.get("query_param", "q")
        extra_params = custom_config.get("extra_params", {})

        headers = {}
        if self._api_key:
            headers[auth_header] = self._api_key

        params = {query_param: query, **extra_params}
        data = await self._get(f"{base_url}{search_path}", params=params, headers=headers)

        if "error" in data:
            return []

        return [self._wrap_result(
            "custom_api_result",
            {"query": query, "source_url": base_url, "data": data},
            confidence=0.8, relevance_score=0.7, tags=["custom", "user_defined"],
        )]
