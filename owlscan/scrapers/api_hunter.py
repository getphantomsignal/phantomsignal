"""
OwlScan API Hunter — Expose the Hidden Endpoints
Discovers REST APIs, GraphQL, Swagger docs, admin panels, and more.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger("owlscan.api_hunter")

API_PATHS = [
    # OpenAPI / Swagger
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json", "/api-docs", "/api-docs.json",
    "/openapi.json", "/openapi.yaml", "/v2/api-docs", "/v3/api-docs",
    "/.well-known/openapi", "/swagger-ui.html", "/swagger-ui/",
    # GraphQL
    "/graphql", "/graphiql", "/graph", "/gql", "/api/graphql",
    "/v1/graphql", "/query", "/playground",
    # Common API roots
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/latest",
    "/v1", "/v2", "/v3", "/rest", "/rest/v1", "/rest/v2",
    "/service", "/services", "/endpoints",
    # Health / Status
    "/health", "/healthz", "/health/check", "/status",
    "/ping", "/ready", "/live", "/readiness", "/liveness",
    # Admin / Management
    "/admin", "/admin/", "/administrator", "/manage",
    "/management", "/console", "/dashboard", "/panel",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/mysql",
    "/adminer", "/db-admin",
    # Auth endpoints
    "/auth", "/auth/login", "/auth/token", "/oauth",
    "/oauth/token", "/oauth2/token", "/login", "/signin",
    "/api/auth", "/api/login", "/token", "/jwt",
    # Metrics / Monitoring
    "/metrics", "/prometheus", "/actuator",
    "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/metrics", "/actuator/beans",
    "/debug", "/debug/vars", "/debug/pprof",
    # Common API discovery
    "/.well-known/", "/.well-known/security.txt",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    # Config / Environment leaks
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.json", "/config.yaml", "/app.config",
    "/settings.json", "/appsettings.json",
    # Source code / Git leaks
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.hg/hgrc",
    # Cloud metadata
    "/latest/meta-data/", "/computeMetadata/v1/",
    "/opc/v1/instance/",
    # Container / k8s
    "/version", "/api/version",
    # Misc
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/humans.txt", "/security.txt",
    "/.well-known/security.txt",
    "/CHANGELOG", "/CHANGELOG.md", "/CHANGELOG.txt",
    "/README", "/README.md",
    "/package.json", "/composer.json", "/requirements.txt",
    "/Gemfile", "/pom.xml",
]

SENSITIVE_PATH_PATTERNS = [
    r"\.env", r"\.git", r"\.svn", r"\.hg",
    r"config\.", r"settings\.", r"secret",
    r"backup", r"\.bak", r"\.old", r"\.orig",
    r"admin", r"phpmyadmin", r"adminer",
    r"actuator", r"debug", r"metrics",
]

GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    types { name kind description }
    queryType { name fields { name description args { name type { name kind } } } }
    mutationType { name }
    subscriptionType { name }
  }
}
"""


class APIHunter:
    """Discovers API endpoints, admin panels, and sensitive exposures."""

    def __init__(self, config):
        self.config = config
        self.timeout = 10
        self.concurrency = 30

    async def hunt(self, target: str) -> List[Dict]:
        """Launch the API endpoint hunt against a target."""
        base_url = target if target.startswith("http") else f"https://{target}"
        results = []

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=self.timeout,
            verify=False,
        ) as client:
            semaphore = asyncio.Semaphore(self.concurrency)

            tasks = [
                self._probe_path(client, base_url, path, semaphore)
                for path in API_PATHS
            ]
            probe_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in probe_results:
                if isinstance(result, dict) and result:
                    results.append(result)

            # Try HTTP fallback if HTTPS failed
            if not any(r for r in results if r.get("data", {}).get("status_code", 0) < 400):
                http_base = base_url.replace("https://", "http://")
                if http_base != base_url:
                    tasks2 = [
                        self._probe_path(client, http_base, path, semaphore)
                        for path in API_PATHS[:20]
                    ]
                    http_results = await asyncio.gather(*tasks2, return_exceptions=True)
                    for r in http_results:
                        if isinstance(r, dict) and r:
                            results.append(r)

            # GraphQL introspection on discovered GraphQL endpoints
            graphql_endpoints = [
                r["data"]["url"] for r in results
                if r.get("data", {}).get("endpoint_type") == "graphql"
            ]
            for gql_url in graphql_endpoints:
                introspection = await self._graphql_introspect(client, gql_url)
                if introspection:
                    results.append(introspection)

        return results

    async def _probe_path(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        path: str,
        semaphore: asyncio.Semaphore,
    ) -> Optional[Dict]:
        async with semaphore:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = await client.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; security-scanner/1.0)"},
                )
                status = response.status_code
                content_type = response.headers.get("content-type", "")
                content_len = len(response.content)

                if status in (404, 410) and content_len < 100:
                    return None

                endpoint_type = self._classify_endpoint(path, response)
                is_sensitive = any(re.search(p, path, re.IGNORECASE) for p in SENSITIVE_PATH_PATTERNS)
                is_accessible = status in (200, 201, 202, 301, 302, 307, 308, 401, 403)

                if not is_accessible:
                    return None

                data_preview = None
                if "json" in content_type and content_len < 10000:
                    try:
                        import json
                        data_preview = response.json()
                    except Exception:
                        pass

                return {
                    "type": "api_endpoint" if "api" in endpoint_type else "web_resource",
                    "source": "api_hunter",
                    "data": {
                        "url": url,
                        "path": path,
                        "status_code": status,
                        "content_type": content_type,
                        "content_length": content_len,
                        "endpoint_type": endpoint_type,
                        "is_sensitive": is_sensitive,
                        "is_accessible": status == 200,
                        "requires_auth": status in (401, 403),
                        "server": response.headers.get("server", ""),
                        "data_preview": data_preview,
                        "response_headers": dict(response.headers),
                    },
                    "confidence": 1.0,
                    "relevance_score": 0.95 if is_sensitive else 0.7,
                    "tags": self._build_tags(path, status, endpoint_type, is_sensitive),
                    "is_anomaly": is_sensitive and status == 200,
                }

            except (httpx.ConnectError, httpx.TimeoutException):
                return None
            except Exception as e:
                logger.debug(f"API probe error {url}: {e}")
                return None

    def _classify_endpoint(self, path: str, response: httpx.Response) -> str:
        content_type = response.headers.get("content-type", "")
        path_lower = path.lower()

        if any(x in path_lower for x in ["/graphql", "/graphiql", "/gql"]):
            return "graphql"
        if any(x in path_lower for x in ["swagger", "openapi", "api-docs"]):
            return "api_documentation"
        if any(x in path_lower for x in ["/admin", "/administrator", "/panel", "/console"]):
            return "admin_panel"
        if any(x in path_lower for x in ["/health", "/healthz", "/ping", "/ready"]):
            return "health_check"
        if any(x in path_lower for x in ["/metrics", "/actuator", "/debug"]):
            return "monitoring"
        if any(x in path_lower for x in ["/auth", "/login", "/token", "/oauth"]):
            return "authentication"
        if any(x in path_lower for x in ["/.env", "/.git", "config", "settings"]):
            return "sensitive_file"
        if "json" in content_type:
            return "api_json"
        if any(x in path_lower for x in ["/api/", "/v1/", "/v2/", "/rest/"]):
            return "api_rest"
        return "web_resource"

    async def _graphql_introspect(
        self, client: httpx.AsyncClient, url: str
    ) -> Optional[Dict]:
        try:
            response = await client.post(
                url,
                json={"query": GRAPHQL_INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    schema = data["data"]["__schema"]
                    return {
                        "type": "graphql_schema",
                        "source": "api_hunter",
                        "data": {
                            "url": url,
                            "introspection_enabled": True,
                            "type_count": len(schema.get("types", [])),
                            "types": [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")][:50],
                            "has_mutations": schema.get("mutationType") is not None,
                            "has_subscriptions": schema.get("subscriptionType") is not None,
                        },
                        "confidence": 1.0,
                        "relevance_score": 0.95,
                        "tags": ["graphql", "introspection", "api"],
                        "is_anomaly": True,
                    }
        except Exception:
            pass
        return None

    def _build_tags(self, path: str, status: int, endpoint_type: str, is_sensitive: bool) -> List[str]:
        tags = ["api_hunt", endpoint_type]
        if is_sensitive:
            tags.append("sensitive")
        if status == 200:
            tags.append("accessible")
        if status in (401, 403):
            tags.append("auth_required")
        if ".git" in path or ".env" in path:
            tags.append("critical_exposure")
        return tags
