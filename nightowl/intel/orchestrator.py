"""
NightOwl Intel Orchestrator — The Shadow Broker
Coordinates all intelligence APIs and aggregates signal data.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from nightowl.intel.apis.base import get_registered_apis
from nightowl.intel.apis import shodan_api, all_apis  # noqa: F401 — trigger registration

logger = logging.getLogger("nightowl.intel.orchestrator")


class IntelOrchestrator:
    """
    Manages parallel intelligence gathering across all configured APIs.
    Each API is queried concurrently with circuit-breaker-style error handling.
    """

    def __init__(self, config):
        self.config = config
        self._apis = {}
        self._init_apis()

    def _init_apis(self) -> None:
        registry = get_registered_apis()
        enabled = self.config.get("intel", "enabled_apis", default=[])

        for name, cls in registry.items():
            instance = cls(self.config)
            if not enabled or name in enabled or instance.is_configured:
                self._apis[name] = instance

    async def run(self, target: str, scan_type: str, options: Dict) -> List[Dict]:
        """Run all applicable intelligence APIs against a target."""
        results = []
        applicable = self._get_applicable_apis(target, scan_type)

        if not applicable:
            logger.warning("No configured intel APIs available for this scan.")
            return results

        tasks = {
            name: self._run_api(name, api, target, options)
            for name, api in applicable.items()
        }

        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for name, result in zip(tasks.keys(), gathered):
            if isinstance(result, Exception):
                logger.error(f"API {name} failed: {result}")
            elif isinstance(result, list):
                results.extend(result)

        return results

    def _get_applicable_apis(self, target: str, scan_type: str) -> Dict:
        import re
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
        is_email = "@" in target
        is_domain = "." in target and not is_ip and not is_email
        is_username = not is_ip and not is_email and not is_domain
        is_people = scan_type in ("people_intel",)

        applicable = {}
        for name, api in self._apis.items():
            if not api.is_configured:
                continue
            if is_ip and "network" in [c.value for c in api.CATEGORIES]:
                applicable[name] = api
            elif is_email and "email" in [c.value for c in api.CATEGORIES]:
                applicable[name] = api
            elif is_domain and "domain" in [c.value for c in api.CATEGORIES]:
                applicable[name] = api
            elif is_people and "people" in [c.value for c in api.CATEGORIES]:
                applicable[name] = api
            elif scan_type == "full_spectrum":
                applicable[name] = api
            elif is_ip and "threat_intel" in [c.value for c in api.CATEGORIES]:
                applicable[name] = api
            elif is_domain and "threat_intel" in [c.value for c in api.CATEGORIES]:
                applicable[name] = api

        return applicable

    async def _run_api(
        self, name: str, api, target: str, options: Dict
    ) -> List[Dict]:
        try:
            logger.debug(f"Querying {name} for {target}")
            results = await asyncio.wait_for(
                api.search(target, **options),
                timeout=30,
            )
            return results or []
        except asyncio.TimeoutError:
            logger.warning(f"API {name} timed out for target {target}")
            return []
        except Exception as e:
            logger.error(f"API {name} error: {e}")
            return []
        finally:
            try:
                await api.close()
            except Exception:
                pass

    def get_api_status(self) -> List[Dict]:
        """Return status of all registered APIs for the health dashboard."""
        return [
            {**api.info(), "name": name}
            for name, api in self._apis.items()
        ]

    def get_available_apis(self) -> List[Dict]:
        """Return all registered APIs including unconfigured ones."""
        from nightowl.intel.apis.base import get_registered_apis
        all_apis = get_registered_apis()
        return [
            {**cls(self.config).info(), "name": name}
            for name, cls in all_apis.items()
        ]
