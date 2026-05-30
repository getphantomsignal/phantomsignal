"""
OwlScan Intel API Base — Ghost Key Plugin Architecture
All intelligence API integrations extend this base class.
Add a new API by subclassing BaseIntelAPI and registering it.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import abc
import asyncio
import logging
import time
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Type

import httpx

logger = logging.getLogger("owlscan.intel.api")

_REGISTRY: Dict[str, Type["BaseIntelAPI"]] = {}


def register_api(cls: Type["BaseIntelAPI"]) -> Type["BaseIntelAPI"]:
    """Decorator to register an Intel API in the plugin registry."""
    _REGISTRY[cls.NAME] = cls
    return cls


def get_registered_apis() -> Dict[str, Type["BaseIntelAPI"]]:
    return dict(_REGISTRY)


def get_api_instance(name: str, config) -> Optional["BaseIntelAPI"]:
    cls = _REGISTRY.get(name)
    if cls:
        return cls(config)
    return None


class APITier(str, Enum):
    FREE = "free"
    FREE_LIMITED = "free_limited"
    FREEMIUM = "freemium"
    PAID = "paid"
    ENTERPRISE = "enterprise"


class APICategory(str, Enum):
    NETWORK = "network"
    PEOPLE = "people"
    EMAIL = "email"
    DOMAIN = "domain"
    THREAT_INTEL = "threat_intel"
    SOCIAL = "social"
    BREACH = "breach"
    GEOLOCATION = "geolocation"
    VULNERABILITY = "vulnerability"
    DARK_WEB = "dark_web"


class BaseIntelAPI(abc.ABC):
    """
    Base class for all OwlScan intelligence API integrations.

    To add a new API source:
    1. Create a new file in owlscan/intel/apis/
    2. Subclass BaseIntelAPI
    3. Set class attributes (NAME, DESCRIPTION, etc.)
    4. Implement the required abstract methods
    5. Decorate with @register_api

    Example:
        @register_api
        class MyAPI(BaseIntelAPI):
            NAME = "myapi"
            DESCRIPTION = "My custom intel source"
            REQUIRES_KEY = True
            TIER = APITier.FREE_LIMITED
            CATEGORIES = [APICategory.NETWORK]

            async def search(self, query: str, **kwargs) -> Dict:
                # your implementation
                ...
    """

    NAME: ClassVar[str] = "base"
    DESCRIPTION: ClassVar[str] = ""
    REQUIRES_KEY: ClassVar[bool] = True
    TIER: ClassVar[APITier] = APITier.FREE_LIMITED
    CATEGORIES: ClassVar[List[APICategory]] = []
    RATE_LIMIT_PER_MINUTE: ClassVar[int] = 60
    BASE_URL: ClassVar[str] = ""
    DOCS_URL: ClassVar[str] = ""
    SIGN_UP_URL: ClassVar[str] = ""
    IS_COMMERCIAL: ClassVar[bool] = False

    def __init__(self, config):
        self.config = config
        self._api_key = config.get_api_key(self.NAME)
        self._call_times: List[float] = []
        self._client: Optional[httpx.AsyncClient] = None
        self.logger = logging.getLogger(f"owlscan.intel.{self.NAME}")

    @property
    def is_configured(self) -> bool:
        """Returns True if the API is ready to use."""
        if self.REQUIRES_KEY:
            return bool(self._api_key)
        return True

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=30,
                follow_redirects=True,
                headers=self._default_headers(),
            )
        return self._client

    def _default_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": "OwlScan-OSINT/1.0 (+https://github.com/owlscan/owlscan)",
            "Accept": "application/json",
        }

    async def _rate_limit(self) -> None:
        """Enforce per-minute rate limiting."""
        now = time.time()
        self._call_times = [t for t in self._call_times if now - t < 60]
        if len(self._call_times) >= self.RATE_LIMIT_PER_MINUTE:
            sleep_time = 60 - (now - self._call_times[0]) + 0.1
            self.logger.debug(f"Rate limit reached — sleeping {sleep_time:.1f}s")
            await asyncio.sleep(sleep_time)
        self._call_times.append(time.time())

    async def _get(self, url: str, params: Dict = None, headers: Dict = None) -> Dict:
        await self._rate_limit()
        client = self._get_client()
        try:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            self.logger.warning(f"HTTP {e.response.status_code} from {url}")
            return {"error": f"HTTP {e.response.status_code}", "url": url}
        except Exception as e:
            self.logger.error(f"Request failed: {url}: {e}")
            return {"error": str(e)}

    async def _post(self, url: str, data: Dict = None, json: Dict = None, headers: Dict = None) -> Dict:
        await self._rate_limit()
        client = self._get_client()
        try:
            response = await client.post(url, data=data, json=json, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"POST failed: {url}: {e}")
            return {"error": str(e)}

    def _wrap_result(
        self,
        result_type: str,
        data: Any,
        confidence: float = 0.9,
        relevance_score: float = 0.7,
        tags: List[str] = None,
        is_anomaly: bool = False,
    ) -> Dict:
        """Wrap raw API data into OwlScan standard result format."""
        return {
            "type": result_type,
            "source": self.NAME,
            "data": data,
            "confidence": confidence,
            "relevance_score": relevance_score,
            "tags": tags or [],
            "is_anomaly": is_anomaly,
            "timestamp": datetime.utcnow().isoformat(),
        }

    @abc.abstractmethod
    async def search(self, query: str, **kwargs) -> List[Dict]:
        """
        Main search method — query this API with a target identifier.
        query can be an IP, domain, email, name, phone, etc.
        Returns a list of OwlScan-formatted result dicts.
        """
        ...

    async def enrich(self, data: Dict) -> List[Dict]:
        """Optional: enrich an existing result with additional data."""
        return []

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def info(self) -> Dict:
        return {
            "name": self.NAME,
            "description": self.DESCRIPTION,
            "requires_key": self.REQUIRES_KEY,
            "tier": self.TIER.value,
            "categories": [c.value for c in self.CATEGORIES],
            "rate_limit_per_minute": self.RATE_LIMIT_PER_MINUTE,
            "is_configured": self.is_configured,
            "docs_url": self.DOCS_URL,
            "sign_up_url": self.SIGN_UP_URL,
            "is_commercial": self.IS_COMMERCIAL,
        }
