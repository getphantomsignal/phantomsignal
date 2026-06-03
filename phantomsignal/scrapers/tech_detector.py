"""
PhantomSignal Tech Detector — X-Ray Vision for the Web Stack
Identifies technologies, frameworks, CMS, CDN, WAF, and more.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("phantomsignal.tech_detector")

# Technology fingerprints — headers, cookies, HTML patterns, JS vars
TECH_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # === Web Servers ===
    "nginx": {
        "headers": {"server": r"nginx"},
        "category": "Web Server", "icon": "🌐",
    },
    "apache": {
        "headers": {"server": r"apache"},
        "category": "Web Server", "icon": "🌐",
    },
    "iis": {
        "headers": {"server": r"Microsoft-IIS"},
        "category": "Web Server", "icon": "🌐",
    },
    "caddy": {
        "headers": {"server": r"caddy"},
        "category": "Web Server",
    },
    "lighttpd": {
        "headers": {"server": r"lighttpd"},
        "category": "Web Server",
    },
    # === CMS ===
    "wordpress": {
        "html": [r"wp-content", r"wp-includes", r"wordpress"],
        "headers": {"x-powered-by": r"wordpress"},
        "cookies": [r"wordpress_"],
        "category": "CMS",
    },
    "drupal": {
        "html": [r"Drupal\.settings", r"/sites/default/files"],
        "headers": {"x-generator": r"Drupal"},
        "cookies": [r"SESS[a-f0-9]+"],
        "category": "CMS",
    },
    "joomla": {
        "html": [r"Joomla!", r"/media/jui/"],
        "category": "CMS",
    },
    "ghost": {
        "html": [r"ghost\.io", r"content=\"Ghost"],
        "category": "CMS",
    },
    "shopify": {
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "cookies": [r"_shopify"],
        "category": "E-Commerce",
    },
    "woocommerce": {
        "html": [r"woocommerce"],
        "cookies": [r"woocommerce_"],
        "category": "E-Commerce",
    },
    "magento": {
        "html": [r"Mage\.Cookies", r"/skin/frontend/"],
        "cookies": [r"frontend="],
        "category": "E-Commerce",
    },
    "prestashop": {
        "html": [r"prestashop", r"PrestaShop"],
        "category": "E-Commerce",
    },
    # === JavaScript Frameworks ===
    "react": {
        "html": [r"react", r"__REACT"],
        "js_vars": [r"React\.version", r"__REACT_DEVTOOLS"],
        "category": "JavaScript Framework",
    },
    "vue": {
        "html": [r"vue\.js", r"__vue"],
        "js_vars": [r"Vue\.version"],
        "category": "JavaScript Framework",
    },
    "angular": {
        "html": [r"ng-app", r"ng-controller", r"angular\.js"],
        "category": "JavaScript Framework",
    },
    "next.js": {
        "html": [r"__NEXT_DATA__", r"_next/static"],
        "category": "JavaScript Framework",
    },
    "nuxt.js": {
        "html": [r"__NUXT__", r"/_nuxt/"],
        "category": "JavaScript Framework",
    },
    "svelte": {
        "html": [r"svelte"],
        "category": "JavaScript Framework",
    },
    "jquery": {
        "html": [r"jquery\.min\.js", r"jquery-[0-9]"],
        "js_vars": [r"jQuery\.fn\.jquery"],
        "category": "JavaScript Library",
    },
    "bootstrap": {
        "html": [r"bootstrap\.min\.css", r"bootstrap\.css"],
        "category": "UI Framework",
    },
    "tailwind": {
        "html": [r"tailwind", r"tailwindcss"],
        "category": "UI Framework",
    },
    # === Backend Frameworks ===
    "django": {
        "headers": {"x-powered-by": r"django"},
        "cookies": [r"csrftoken", r"sessionid"],
        "html": [r"csrfmiddlewaretoken"],
        "category": "Web Framework",
    },
    "flask": {
        "headers": {"server": r"Werkzeug"},
        "cookies": [r"session=\."],
        "category": "Web Framework",
    },
    "fastapi": {
        "html": [r"fastapi", r"OpenAPI"],
        "category": "Web Framework",
    },
    "laravel": {
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
        "html": [r"laravel"],
        "category": "Web Framework",
    },
    "ruby_on_rails": {
        "headers": {"x-powered-by": r"Phusion Passenger"},
        "cookies": [r"_session_id"],
        "category": "Web Framework",
    },
    "express": {
        "headers": {"x-powered-by": r"Express"},
        "category": "Web Framework",
    },
    "spring": {
        "headers": {"x-application-context": r".+"},
        "category": "Web Framework",
    },
    "asp.net": {
        "headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r".+"},
        "cookies": [r"ASP\.NET_SessionId", r"__RequestVerificationToken"],
        "category": "Web Framework",
    },
    # === CDN / WAF ===
    "cloudflare": {
        "headers": {"cf-ray": r".+", "server": r"cloudflare"},
        "category": "CDN/WAF",
    },
    "aws_cloudfront": {
        "headers": {"x-amz-cf-id": r".+", "via": r"CloudFront"},
        "category": "CDN",
    },
    "fastly": {
        "headers": {"x-served-by": r"cache-.+", "x-cache": r".+fastly"},
        "category": "CDN",
    },
    "akamai": {
        "headers": {"x-check-cacheable": r".+"},
        "category": "CDN",
    },
    "sucuri": {
        "headers": {"x-sucuri-id": r".+"},
        "category": "WAF",
    },
    "imperva": {
        "headers": {"x-iinfo": r".+"},
        "category": "WAF",
    },
    "f5_bigip": {
        "cookies": [r"BIGipServer"],
        "category": "Load Balancer",
    },
    # === Analytics / Tracking ===
    "google_analytics": {
        "html": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d+-\d+", r"G-[A-Z0-9]+"],
        "category": "Analytics",
    },
    "google_tag_manager": {
        "html": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
        "category": "Tag Manager",
    },
    "facebook_pixel": {
        "html": [r"connect\.facebook\.net", r"fbq\("],
        "category": "Analytics",
    },
    "hotjar": {
        "html": [r"static\.hotjar\.com"],
        "category": "Analytics",
    },
    # === Databases (exposed endpoints) ===
    "elasticsearch": {
        "html": [r"\"cluster_name\"", r"\"number_of_nodes\""],
        "category": "Database",
    },
    "mongodb": {
        "html": [r"\"errmsg\"\s*:", r"\"$oid\""],
        "category": "Database",
    },
    "graphql": {
        "html": [r"\"__typename\"", r"\"errors\":\s*\["],
        "category": "API",
    },
    # === Hosting / Cloud ===
    "aws_s3": {
        "html": [r"s3\.amazonaws\.com", r"AmazonS3"],
        "headers": {"server": r"AmazonS3"},
        "category": "Cloud Storage",
    },
    "vercel": {
        "headers": {"x-vercel-id": r".+"},
        "category": "PaaS",
    },
    "netlify": {
        "headers": {"x-nf-request-id": r".+", "server": r"Netlify"},
        "category": "PaaS",
    },
    "heroku": {
        "headers": {"via": r"1\.1 vegur"},
        "category": "PaaS",
    },
    # === Security ===
    "lets_encrypt": {
        "html": [r"letsencrypt\.org"],
        "category": "SSL Certificate",
    },
    "recaptcha": {
        "html": [r"google\.com/recaptcha", r"g-recaptcha"],
        "category": "Bot Protection",
    },
    "hcaptcha": {
        "html": [r"hcaptcha\.com"],
        "category": "Bot Protection",
    },
}

INTERESTING_HEADERS = [
    "server", "x-powered-by", "x-generator", "x-framework",
    "x-aspnet-version", "x-runtime", "x-version", "x-build",
    "via", "cf-ray", "x-amz-cf-id", "x-cache", "x-varnish",
    "x-drupal-cache", "x-wp-total", "content-security-policy",
    "strict-transport-security", "x-frame-options",
]


class TechDetector:
    """Technology stack fingerprinting engine."""

    def __init__(self, config):
        self.config = config

    async def detect(self, target: str) -> List[Dict]:
        """Run full technology detection against a target URL."""
        url = target if target.startswith("http") else f"https://{target}"
        results = []

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=20,
                verify=False,
            ) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                )

                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                cookies_str = "; ".join(f"{k}={v}" for k, v in response.cookies.items())
                html = response.text

                detected = self._fingerprint(headers_lower, cookies_str, html)

                for tech_name, tech_info in detected.items():
                    results.append({
                        "type": "technology",
                        "source": "tech_detector",
                        "data": {
                            "name": tech_name,
                            "category": tech_info.get("category", "Unknown"),
                            "version": tech_info.get("version"),
                            "confidence": tech_info.get("confidence", 0.9),
                            "evidence": tech_info.get("evidence", []),
                        },
                        "confidence": tech_info.get("confidence", 0.9),
                        "relevance_score": 0.7,
                        "tags": ["technology", tech_info.get("category", "").lower().replace(" ", "_")],
                    })

                # Interesting headers
                interesting = {
                    k: v for k, v in headers_lower.items()
                    if k in INTERESTING_HEADERS
                }
                if interesting:
                    results.append({
                        "type": "http_headers",
                        "source": "tech_detector",
                        "data": {
                            "interesting_headers": interesting,
                            "all_headers": dict(headers_lower),
                            "server_fingerprint": headers_lower.get("server"),
                            "powered_by": headers_lower.get("x-powered-by"),
                        },
                        "confidence": 1.0,
                        "relevance_score": 0.8,
                        "tags": ["headers", "fingerprint"],
                    })

                # SSL/TLS info
                if url.startswith("https"):
                    tls_info = await self._get_tls_info(urlparse(url).hostname)
                    if tls_info:
                        results.append({
                            "type": "tls_certificate",
                            "source": "tech_detector",
                            "data": tls_info,
                            "confidence": 1.0,
                            "relevance_score": 0.7,
                            "tags": ["ssl", "tls", "certificate"],
                        })

                # Security header analysis
                sec_score = self._security_header_score(headers_lower)
                results.append({
                    "type": "security_posture",
                    "source": "tech_detector",
                    "data": sec_score,
                    "confidence": 1.0,
                    "relevance_score": 0.9,
                    "tags": ["security", "headers", "posture"],
                    "is_anomaly": sec_score["score"] < 40,
                })

        except Exception as e:
            logger.error(f"Tech detection failed for {target}: {e}")

        return results

    def _fingerprint(
        self, headers: Dict, cookies: str, html: str
    ) -> Dict[str, Dict]:
        detected = {}

        for tech_name, sig in TECH_SIGNATURES.items():
            evidence = []
            confidence = 0.0

            # Check headers
            for header_key, pattern in sig.get("headers", {}).items():
                val = headers.get(header_key, "")
                if val and re.search(pattern, val, re.IGNORECASE):
                    evidence.append(f"header:{header_key}")
                    confidence = max(confidence, 0.95)
                    version_match = re.search(r"(\d+[\.\d]*)", val)
                    if version_match:
                        sig["version"] = version_match.group(1)

            # Check cookies
            for cookie_pattern in sig.get("cookies", []):
                if re.search(cookie_pattern, cookies, re.IGNORECASE):
                    evidence.append(f"cookie:{cookie_pattern}")
                    confidence = max(confidence, 0.85)

            # Check HTML patterns
            for html_pattern in sig.get("html", []):
                if re.search(html_pattern, html, re.IGNORECASE):
                    evidence.append(f"html:{html_pattern[:30]}")
                    confidence = max(confidence, 0.75)

            if evidence:
                detected[tech_name] = {
                    "category": sig.get("category", "Unknown"),
                    "version": sig.get("version"),
                    "confidence": confidence,
                    "evidence": evidence,
                }

        return detected

    async def _get_tls_info(self, hostname: str) -> Optional[Dict]:
        import ssl
        import socket
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "hostname": hostname,
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": cert.get("subjectAltName", []),
                    }
        except Exception:
            return None

    def _security_header_score(self, headers: Dict) -> Dict:
        checks = {
            "strict-transport-security": ("HSTS", 20),
            "content-security-policy": ("CSP", 25),
            "x-frame-options": ("X-Frame-Options", 15),
            "x-content-type-options": ("X-Content-Type-Options", 10),
            "x-xss-protection": ("XSS Protection", 10),
            "referrer-policy": ("Referrer Policy", 10),
            "permissions-policy": ("Permissions Policy", 10),
        }
        score = 0
        present = {}
        missing = []

        for header, (name, weight) in checks.items():
            if header in headers:
                score += weight
                present[name] = headers[header]
            else:
                missing.append(name)

        rating = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
        return {
            "score": score,
            "rating": rating,
            "present": present,
            "missing": missing,
            "recommendation": f"Implement {', '.join(missing[:3])} to improve security posture." if missing else "Excellent security headers.",
        }
