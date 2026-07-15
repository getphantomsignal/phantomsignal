"""
PhantomSignal — OPSEC posture primitives.

The OPSEC-native flagship rests on two ideas made concrete here:

* **Every module declares how attributable its traffic is** (``OpsecLevel``), so
  the operator can see — before and after a run — which parts of a scan are
  masked and which leave a trail back to their infrastructure.
* **Every scan reports its own attribution surface** (``build_attribution_result``),
  turning the stealth layer's telemetry (``core.http.AttributionLedger``) into a
  first-class finding: what egressed, how much was proxied, which JA3 profiles
  were presented, and how often a defence challenged us.

No other OSS OSINT framework grades its own operational footprint; this module
is what makes that claim real rather than marketing.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional


class OpsecLevel(str, Enum):
    """How attributable a module's egress is.

    Ordered most-masked → least-masked so ``max()`` over a scan surfaces the
    least-safe traffic that ran.
    """
    # Routes through StealthClient: proxy pool + adaptive pacing + (optional)
    # JA3/JA4 impersonation. The operator's real IP/fingerprint is masked.
    STEALTH_GUARANTEED = "stealth_guaranteed"
    # Egresses through the proxy pool but without the full browser identity —
    # e.g. an external tool we route via the shared proxy. IP masked, TLS not.
    PROXIED = "proxied"
    # Direct from the operator's IP with no masking: raw-socket port scans,
    # DoH resolution, authenticated third-party API calls. Attributable.
    ATTRIBUTABLE = "attributable"


# Rank for "worst" (least-masked) selection and for UI severity ordering.
_RANK = {
    OpsecLevel.STEALTH_GUARANTEED: 0,
    OpsecLevel.PROXIED: 1,
    OpsecLevel.ATTRIBUTABLE: 2,
}


def worst_level(levels: List[OpsecLevel]) -> Optional[OpsecLevel]:
    """The least-masked level in a set — the one that defines a scan's exposure."""
    if not levels:
        return None
    return max(levels, key=lambda lvl: _RANK.get(lvl, 0))


def effective_opsec(results: Optional[List[Dict]], static: str) -> str:
    """A module's actual posture for a run.

    Modules whose posture is dynamic (external tools that proxy only when a proxy
    is configured) self-declare ``data["opsec"]`` per finding; the module's
    effective level is the least-masked one it actually produced. Falls back to
    the ``static`` registry tag when nothing self-declared.
    """
    seen = []
    for r in (results or []):
        data = r.get("data") if isinstance(r, dict) else None
        val = data.get("opsec") if isinstance(data, dict) else None
        if val in _RANK_BY_VALUE:
            seen.append(OpsecLevel(val))
    worst = worst_level(seen)
    return worst.value if worst else static


_RANK_BY_VALUE = {lvl.value: r for lvl, r in _RANK.items()}


def _grade(summary: Dict, module_opsec: Dict[str, str]) -> str:
    """A one-word operator posture grade from the run's telemetry + module mix.

    Honest, not flattering: any attributable module, or unproxied target-facing
    egress, caps the grade — the point of the flagship is to *tell the truth*
    about footprint, not to always read green.
    """
    levels = [OpsecLevel(v) for v in module_opsec.values() if v in _RANK]
    worst = worst_level(levels)
    total = summary.get("total_requests", 0)
    proxied_pct = summary.get("proxied_pct", 0.0)
    impersonated = summary.get("impersonated", 0)

    if worst == OpsecLevel.ATTRIBUTABLE:
        return "exposed"
    if total == 0:
        return "quiet"
    if proxied_pct >= 90 and impersonated > 0:
        return "masked"
    if proxied_pct >= 50:
        return "partial"
    return "exposed"


def build_attribution_result(summary: Dict, module_opsec: Dict[str, str],
                             pool_status: Optional[List[Dict]] = None) -> Dict:
    """Compose the ``attribution_surface`` finding for a completed scan.

    ``summary`` is ``AttributionLedger.summary()``; ``module_opsec`` maps each
    module that ran to its ``OpsecLevel`` value; ``pool_status`` is optional
    proxy-pool health for context.
    """
    grade = _grade(summary, module_opsec)
    by_level: Dict[str, List[str]] = {lvl.value: [] for lvl in OpsecLevel}
    for module, lvl in module_opsec.items():
        by_level.setdefault(lvl, []).append(module)

    data = {
        "grade": grade,
        "modules_by_opsec": by_level,
        **summary,
    }
    if pool_status:
        data["proxy_pool"] = pool_status

    return {
        "type": "attribution_surface",
        "source": "opsec",
        "data": data,
        # Not a target finding — carries no exposure weight in the shadow score.
        "confidence": 1.0,
        "relevance_score": 0.0,
        "tags": ["opsec", "attribution", grade],
    }
