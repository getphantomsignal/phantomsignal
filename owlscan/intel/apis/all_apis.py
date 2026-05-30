"""
OwlScan Intelligence API Registry
All API integrations — the full ghost key arsenal.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from owlscan.intel.apis.base import (
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

        all_data = {}
        for section in sections:
            data = await self._get(
                f"{self.BASE_URL}/indicators/{indicator_type}/{query}/{section}",
                headers=headers,
            )
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
            "User-Agent": "OwlScan-OSINT/1.0",
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
    CATEGORIES = [APICategory.SOCIAL]
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
        headers = {"User-Agent": "OwlScan-OSINT/1.0 (security research)"}

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
        data = await self._get(
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
        data = await self._get(
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
# CUSTOM API TEMPLATE
# ═══════════════════════════════════════════════════════════

@register_api
class CustomAPI(BaseIntelAPI):
    """
    OwlScan Custom API Integration — Plug in any REST/JSON API.
    Configure via owlscan.yaml or the Settings UI.

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
