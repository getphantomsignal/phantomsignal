"""
PhantomSignal Recursive Pivot Engine — Signal Expansion

Turns the single-pass intel orchestrator into an auto-expanding attack-surface
graph. A discovered IP, subdomain, or email is fed back in as a new target with
depth, dedup, budget, and scope guards so expansion terminates and stays in
scope. This is the piece that moves PhantomSignal from "API fan-out" toward a
SpiderFoot-class graph.

Design: the engine is decoupled from the network. It drives any
``run_pass(target) -> list[result]`` coroutine, so it can be unit-tested with a
fake pass and reused by the orchestrator with a real one.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("phantomsignal.intel.pivot")

# A pass runner: given a target string, return that target's raw result dicts.
RunPass = Callable[[str], Awaitable[List[Dict]]]

_IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@((?:[a-z0-9-]+\.)+[a-z]{2,63})$")

# Entity kinds we will pivot on. Usernames are intentionally excluded — they are
# a false-positive magnet and explode the graph.
PIVOTABLE = ("ip", "domain", "subdomain", "email")


@dataclass(frozen=True)
class PivotEntity:
    """A normalized, pivotable identifier discovered in a result."""
    kind: str          # one of PIVOTABLE
    value: str         # normalized (lowercased for host/email)
    source: str = ""   # which API/module surfaced it

    def key(self) -> Tuple[str, str]:
        return (self.kind, self.value)


def _registered_domain(host: str) -> str:
    """Best-effort eTLD+1 without a dependency. Uses tldextract if present."""
    try:
        import tldextract  # already a declared dependency
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    # Fallback: last two labels (wrong for multi-part TLDs, but bounded/safe).
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def classify(value: str) -> Optional[str]:
    """Return the pivot kind for a raw string, or None if not pivotable."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip().rstrip(".")
    if not v:
        return None
    if _IP_RE.match(v):
        return "ip"
    if _EMAIL_RE.match(v.lower()):
        return "email"
    host = v.lower()
    if _DOMAIN_RE.match(host):
        # domain vs subdomain: subdomain has more labels than its eTLD+1
        return "subdomain" if host != _registered_domain(host) else "domain"
    return None


# Result-data keys that commonly carry pivotable identifiers.
_ENTITY_KEYS = ("ip", "ip_address", "domain", "subdomain", "hostname", "email", "value")


def extract_entities(results: List[Dict]) -> List[PivotEntity]:
    """Pull normalized pivotable entities out of a batch of result dicts."""
    found: Dict[Tuple[str, str], PivotEntity] = {}

    def consider(raw, source: str) -> None:
        kind = classify(raw) if isinstance(raw, str) else None
        if not kind:
            return
        norm = raw.strip().rstrip(".")
        norm = norm.lower() if kind != "ip" else norm
        ent = PivotEntity(kind=kind, value=norm, source=source)
        found.setdefault(ent.key(), ent)

    for r in results or []:
        source = r.get("source", "")
        data = r.get("data")
        if isinstance(data, dict):
            for k in _ENTITY_KEYS:
                if k in data:
                    val = data[k]
                    if isinstance(val, list):
                        for item in val:
                            consider(item, source)
                    else:
                        consider(val, source)
        elif isinstance(data, str):
            consider(data, source)

    return list(found.values())


@dataclass
class PivotConfig:
    max_depth: int = 2            # 0 = single pass (no pivoting)
    max_entities: int = 50        # hard budget across the whole expansion
    allow_cross_domain: bool = False  # follow domains outside the root's eTLD+1
    pivot_kinds: Tuple[str, ...] = PIVOTABLE
    per_target_timeout: float = 45.0


@dataclass
class PivotStats:
    passes: int = 0
    entities_discovered: int = 0
    targets_visited: List[str] = field(default_factory=list)
    max_depth_reached: int = 0
    truncated: bool = False       # hit the entity budget


class RecursivePivotEngine:
    """
    Breadth-first expansion over discovered entities.

    Guards against runaway graphs:
      * dedup — a normalized (kind, value) target is visited at most once
      * depth — expansion stops at ``max_depth``
      * budget — total distinct targets capped at ``max_entities``
      * scope — by default, only pivots to hosts within the root's eTLD+1
        (plus any IP); set ``allow_cross_domain`` to follow co-hosted domains
    """

    def __init__(self, run_pass: RunPass, config: Optional[PivotConfig] = None):
        self._run_pass = run_pass
        self.cfg = config or PivotConfig()

    def _in_scope(self, ent: PivotEntity, root_domain: Optional[str]) -> bool:
        if ent.kind not in self.cfg.pivot_kinds:
            return False
        if self.cfg.allow_cross_domain or root_domain is None:
            return True
        if ent.kind == "ip":
            return True  # IPs are followed regardless; they can't be scoped by name
        host = ent.value.split("@", 1)[1] if ent.kind == "email" else ent.value
        return _registered_domain(host) == root_domain

    async def expand(self, target: str) -> Tuple[List[Dict], PivotStats]:
        """
        Run the root target, then recursively pivot on discovered entities.
        Returns (aggregated_results, stats). Results carry an injected
        ``pivot_depth`` and ``pivot_parent`` for graph reconstruction.
        """
        stats = PivotStats()
        root_kind = classify(target)
        root_domain = None
        if root_kind in ("domain", "subdomain"):
            root_domain = _registered_domain(target)
        elif root_kind == "email":
            root_domain = _registered_domain(target.split("@", 1)[1])

        seen: Set[Tuple[str, str]] = set()
        root_key = (root_kind or "target", target.strip().lower())
        seen.add(root_key)

        # queue holds (target, depth, parent)
        queue: List[Tuple[str, int, Optional[str]]] = [(target, 0, None)]
        aggregated: List[Dict] = []

        while queue:
            cur, depth, parent = queue.pop(0)
            try:
                batch = await asyncio.wait_for(
                    self._run_pass(cur), timeout=self.cfg.per_target_timeout
                )
            except asyncio.TimeoutError:
                logger.warning("Pivot pass timed out for %s", cur)
                batch = []
            except Exception as e:  # a bad pass must not kill the expansion
                logger.error("Pivot pass failed for %s: %s", cur, e)
                batch = []

            stats.passes += 1
            stats.targets_visited.append(cur)
            stats.max_depth_reached = max(stats.max_depth_reached, depth)

            for r in batch or []:
                r.setdefault("pivot_depth", depth)
                r.setdefault("pivot_parent", parent)
                aggregated.append(r)

            if depth >= self.cfg.max_depth:
                continue

            for ent in extract_entities(batch):
                if ent.key() in seen:
                    continue
                if not self._in_scope(ent, root_domain):
                    continue
                if len(seen) >= self.cfg.max_entities:
                    stats.truncated = True
                    logger.info("Pivot entity budget (%d) reached; truncating.",
                                self.cfg.max_entities)
                    break
                seen.add(ent.key())
                stats.entities_discovered += 1
                queue.append((ent.value, depth + 1, cur))

        return aggregated, stats
