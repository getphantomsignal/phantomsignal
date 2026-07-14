"""
GeoEngine.locate — the Locate compute core.

Takes a Profiler ``profile`` dict, extracts attributed GeoSignals, optionally
geocodes string places (best-effort, through the stealth client — spec §11), then
clusters, corroborates, picks a last-known, and surfaces conflicts. Pure and
deterministic apart from the optional geocode step.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional

from phantomsignal.intel.geo import aggregate, places
from phantomsignal.intel.geo.extract import extract_signals
from phantomsignal.intel.geo.signals import GeoSignal, round_to_confidence

logger = logging.getLogger("phantomsignal.geo")


class GeoEngine:
    def __init__(self, config):
        self.config = config

    async def _geocode_fill(self, signals: List[GeoSignal]) -> None:
        """Best-effort: give coordless signals coordinates so they cluster with
        located ones. Never fails the run."""
        targets = [s for s in signals if (s.lat is None or s.lon is None) and any((s.place or {}).values())]
        if not targets:
            return
        try:
            coros = [places.geocode(self.config, s.place) for s in targets]
            results = await asyncio.gather(*coros, return_exceptions=True)
        except Exception as e:  # pragma: no cover
            logger.debug("geocode fill failed: %s", e)
            return
        for s, res in zip(targets, results):
            if isinstance(res, tuple):
                s.lat = round_to_confidence(s.kind, res[0])
                s.lon = round_to_confidence(s.kind, res[1])

    async def signals_for(self, profile: Dict, *, geocode: bool = True) -> List[GeoSignal]:
        """Extract (and optionally geocode-fill) signals from a profile — the
        collection step, split out so the store can persist them."""
        signals = extract_signals(profile)
        if geocode:
            await self._geocode_fill(signals)
        return signals

    async def locate(self, profile: Dict, *, geocode: bool = True,
                     extra_signals: Optional[List[GeoSignal]] = None) -> Dict:
        signals = await self.signals_for(profile, geocode=geocode)
        if extra_signals:
            signals.extend(extra_signals)   # manual / negative investigator inputs

        clusters = aggregate.cluster(signals)
        lk = aggregate.last_known(clusters, signals)
        conf = aggregate.conflicts(clusters, signals)

        subject = " ".join(filter(None, [
            (profile.get("search_params") or {}).get("first_name"),
            (profile.get("search_params") or {}).get("last_name"),
        ])) or (profile.get("names") or ["subject"])[0]

        return {
            "subject": subject,
            "signals": [s.to_dict() for s in signals],
            "clusters": clusters,
            "last_known": lk,
            "conflicts": conf,
            "counts": {
                "signals": len(signals),
                "clusters": len(clusters),
                "hard": sum(1 for s in signals if s.tier == "hard"),
                "conflicts": len(conf),
            },
            "sources": sorted({s.source for s in signals}),
        }
