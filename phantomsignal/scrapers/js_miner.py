"""
PhantomSignal JavaScript Secret & Endpoint Miner

Phase 2. api_hunter probes known paths and greps HTML only; this module fetches
a target's page, pulls every linked and inline script, and mines the JavaScript
for (a) API endpoints/paths and (b) leaked secrets — cloud keys, tokens, and
high-entropy assignments (LinkFinder / trufflehog lineage). Discovered endpoints
expand the known API surface for follow-up; secret findings corroborate the
exposed-secret signature templates.

Secrets are masked in output so raw credentials are never written to the
database or exports.

Design: HTTP I/O in the class; extraction/detection are pure module-level
functions with unit tests.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import math
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger("phantomsignal.scrapers.js_miner")

# Bound the crawl so a script-heavy page can't blow up the scan.
MAX_SCRIPTS = 40
MAX_JS_BYTES = 3_000_000

# ── secret detectors ────────────────────────────────────────────────────────
# (name, compiled regex, severity). Ordering: specific → generic.
SECRET_PATTERNS: List[Tuple[str, "re.Pattern", str]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("AWS Secret Access Key",
     re.compile(r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"), "critical"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "high"),
    ("Google OAuth Client",
     re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), "medium"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high"),
    ("Slack Webhook",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "medium"),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"), "high"),
    ("GitHub Fine-grained PAT", re.compile(r"github_pat_[0-9A-Za-z_]{22,}"), "high"),
    ("Stripe Secret Key", re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{24,}"), "critical"),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), "high"),
    ("SendGrid API Key", re.compile(r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}"), "high"),
    ("Private Key",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    ("JWT",
     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "low"),
]

# Generic "keyword = long value" assignments, gated by entropy to cut noise.
_GENERIC_ASSIGN = re.compile(
    r"(?i)(api[_-]?key|apikey|secret|token|passwd|password|auth|access[_-]?key)"
    r"['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=.]{16,})['\"]"
)
_ENTROPY_MIN = 3.6  # bits/char; base64-ish secrets sit ~4.5+

# Endpoints: absolute URLs and quoted root-relative paths.
_ABS_URL = re.compile(r"https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9_\-./?=&%#:+]*)?")
_REL_PATH = re.compile(r"['\"](/(?:api|v\d|graphql|rest|internal|admin|auth|user|account|"
                       r"oauth|token|upload|download|export|webhook)[A-Za-z0-9_\-./]{0,120})['\"]")
_NOISE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2",
              ".ttf", ".ico", ".map", ".mp4", ".webp")
# XML/schema namespace URLs are not real endpoints — they litter SVG/XHTML.
_NOISE_HOSTS = ("www.w3.org", "w3.org", "schema.org", "purl.org", "ns.adobe.com",
                "xmlns.com", "www.google.com/2005/gml")
_SCRIPT_SRC = re.compile(r"<script[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                            re.IGNORECASE | re.DOTALL)


# ── pure helpers (unit-tested) ──────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_script_srcs(html: str, base_url: str) -> List[str]:
    """Absolute-ize every <script src>, keeping only .js-ish resources."""
    out: List[str] = []
    seen: Set[str] = set()
    for src in _SCRIPT_SRC.findall(html or ""):
        url = urljoin(base_url, src.strip())
        path = urlparse(url).path.lower()
        if path.endswith(_NOISE_EXT):
            continue
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def extract_inline_scripts(html: str) -> List[str]:
    return [s for s in _INLINE_SCRIPT.findall(html or "") if s.strip()]


def extract_endpoints(js_text: str, scope_host: Optional[str] = None) -> Set[str]:
    """Pull API-ish URLs and root-relative paths out of JS source."""
    found: Set[str] = set()
    for m in _ABS_URL.findall(js_text or ""):
        p = urlparse(m)
        if p.path.lower().endswith(_NOISE_EXT):
            continue
        if any(nh in p.netloc for nh in _NOISE_HOSTS):
            continue
        found.add(m.rstrip("\"';,"))
    for m in _REL_PATH.findall(js_text or ""):
        found.add(m)
    return found


def _mask(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 10:
        return s[:2] + "***"
    return f"{s[:4]}…{s[-4:]} ({len(s)} chars)"


def find_secrets(text: str) -> List[Dict]:
    """Return masked secret findings: [{kind, severity, preview}]."""
    results: List[Dict] = []
    seen: Set[Tuple[str, str]] = set()

    for name, pat, sev in SECRET_PATTERNS:
        for m in pat.finditer(text or ""):
            raw = m.group(0)
            key = (name, raw)
            if key in seen:
                continue
            seen.add(key)
            results.append({"kind": name, "severity": sev, "preview": _mask(raw)})

    for m in _GENERIC_ASSIGN.finditer(text or ""):
        label, value = m.group(1), m.group(2)
        # JWTs are owned by the specific pattern above; skip them here.
        if value.count(".") == 2 and value.startswith("eyJ"):
            continue
        if shannon_entropy(value) < _ENTROPY_MIN:
            continue
        key = ("generic", value)
        if key in seen:
            continue
        seen.add(key)
        results.append({"kind": f"High-entropy {label.lower()}",
                        "severity": "medium", "preview": _mask(value)})
    return results


# ── miner ───────────────────────────────────────────────────────────────────

class JSMiner:
    def __init__(self, config):
        self.config = config

    async def run(self, target: str) -> List[Dict]:
        base = self._base_url(target)
        if not base:
            return []
        host = urlparse(base).netloc
        logger.info("JS mining %s", base)

        async with httpx.AsyncClient(
            timeout=12, follow_redirects=True,
            headers={"User-Agent": "PhantomSignal-OSINT/1.0"},
        ) as client:
            html = await self._fetch(client, base)
            if not html:
                return []

            script_urls = extract_script_srcs(html, base)[:MAX_SCRIPTS]
            bundles = await asyncio.gather(
                *(self._fetch(client, u) for u in script_urls),
                return_exceptions=True,
            )

        # Pool inline scripts + fetched bundles, tracking provenance.
        sources: List[Tuple[str, str]] = [("(inline)", s) for s in extract_inline_scripts(html)]
        for url, body in zip(script_urls, bundles):
            if isinstance(body, str) and body:
                sources.append((url, body[:MAX_JS_BYTES]))

        endpoints: Dict[str, str] = {}   # endpoint -> first source
        secrets: List[Dict] = []
        for url, body in sources:
            for ep in extract_endpoints(body, host):
                endpoints.setdefault(ep, url)
            for sec in find_secrets(body):
                secrets.append({**sec, "source_script": url})

        return self._build_results(base, endpoints, secrets, len(sources))

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> str:
        try:
            r = await client.get(url)
            if r.status_code == 200:
                return r.text or ""
        except Exception as e:
            logger.debug("fetch %s failed: %s", url, e)
        return ""

    def _build_results(self, base: str, endpoints: Dict[str, str],
                       secrets: List[Dict], script_count: int) -> List[Dict]:
        results: List[Dict] = []
        for sec in secrets:
            results.append({
                "type": "js_secret",
                "source": "js_miner",
                "data": {
                    "kind": sec["kind"],
                    "severity": sec["severity"],
                    "preview": sec["preview"],
                    "script": sec["source_script"],
                },
                "confidence": 0.85,
                "relevance_score": 0.95,
                "tags": ["js", "secret", "exposure", sec["severity"]],
                "is_anomaly": sec["severity"] in ("critical", "high"),
            })
        for ep, src in sorted(endpoints.items()):
            results.append({
                "type": "js_endpoint",
                "source": "js_miner",
                "data": {"endpoint": ep, "script": src},
                "confidence": 0.8,
                "relevance_score": 0.6,
                "tags": ["js", "endpoint", "api"],
            })
        results.append({
            "type": "js_mine_summary",
            "source": "js_miner",
            "data": {
                "base_url": base,
                "scripts_analyzed": script_count,
                "endpoints_found": len(endpoints),
                "secrets_found": len(secrets),
            },
            "confidence": 1.0,
            "relevance_score": 0.7,
            "tags": ["js", "summary"],
        })
        return results

    def _base_url(self, target: str) -> Optional[str]:
        t = (target or "").strip()
        if not t:
            return None
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        p = urlparse(t)
        if not p.netloc:
            return None
        return f"{p.scheme}://{p.netloc}"
