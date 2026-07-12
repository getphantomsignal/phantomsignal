"""
PhantomSignal Intel Orchestrator — The Shadow Broker
Coordinates all intelligence APIs and aggregates signal data.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List

from phantomsignal.intel.apis.base import get_registered_apis
from phantomsignal.intel.apis import shodan_api, all_apis  # noqa: F401 — trigger registration

logger = logging.getLogger("phantomsignal.intel.orchestrator")


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
        """
        Run applicable intelligence APIs against a target.

        Single-pass by default (backward compatible). Opt into the
        attack-surface pipeline via options:
          * ``recursive`` (bool)      — feed discovered entities back in
          * ``max_depth`` (int)       — pivot depth when recursive (default 2)
          * ``allow_cross_domain``    — follow co-hosted domains outside eTLD+1
          * ``signatures`` (bool)     — run the signature/dork engine over results
        """
        options = options or {}
        if options.get("recursive") or options.get("signatures"):
            return await self.run_pipeline(target, scan_type, options)
        return await self._single_pass(target, scan_type, options)

    async def _single_pass(self, target: str, scan_type: str, options: Dict) -> List[Dict]:
        """One fan-out round: every applicable API queried concurrently."""
        results: List[Dict] = []
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

    async def run_pipeline(self, target: str, scan_type: str, options: Dict) -> List[Dict]:
        """
        Attack-surface pipeline: recursive entity pivoting + signature matching.
        Returns aggregated API results plus any signature/dork findings.
        """
        from phantomsignal.intel.pivot import RecursivePivotEngine, PivotConfig, classify

        options = options or {}

        async def _pass(t: str) -> List[Dict]:
            return await self._single_pass(t, scan_type, options)

        if options.get("recursive"):
            cfg = PivotConfig(
                max_depth=int(options.get("max_depth", 2)),
                max_entities=int(options.get("max_entities", 50)),
                allow_cross_domain=bool(options.get("allow_cross_domain", False)),
            )
            engine = RecursivePivotEngine(_pass, cfg)
            results, stats = await engine.expand(target)
            logger.info(
                "Pivot expansion: %d passes, %d entities, depth %d%s",
                stats.passes, stats.entities_discovered, stats.max_depth_reached,
                " (truncated)" if stats.truncated else "",
            )
        else:
            results = await self._single_pass(target, scan_type, options)

        if options.get("signatures"):
            from phantomsignal.intel.signatures import SignatureEngine
            sig_engine = SignatureEngine()
            findings = sig_engine.evaluate(target, results, target_kind=classify(target))
            if findings:
                logger.info("Signature engine produced %d findings", len(findings))
            results = results + findings

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
            cats = {c.value for c in api.CATEGORIES}
            if scan_type == "full_spectrum":
                applicable[name] = api
            elif is_ip and cats & {"network", "threat_intel", "geolocation", "vulnerability", "dark_web"}:
                applicable[name] = api
            elif is_email and cats & {"email", "breach", "threat_intel", "people"}:
                applicable[name] = api
            elif is_domain and cats & {"domain", "threat_intel", "email"}:
                applicable[name] = api
            elif is_people and "people" in cats:
                applicable[name] = api
            elif is_username and cats & {"social", "people"}:
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
        from phantomsignal.intel.apis.base import get_registered_apis
        registered = get_registered_apis()
        return [
            {**cls(self.config).info(), "name": name}
            for name, cls in registered.items()
        ]
