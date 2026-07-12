"""
PhantomSignal ASM Diff — Attack-Surface Change Detection

Phase 5. Turns single-shot recon into continuous monitoring: compare two scans of
the same target and surface what changed — new assets (a fresh subdomain, open
port, leak or exposure), removed assets, and modified ones (a service version or
banner that moved). New sensitive assets are the alerts.

Design: the diff is pure and network/DB-free — it works on two lists of result
dicts and is fully unit-tested. ASMDiffer is the thin layer that loads the two
most recent completed scans for a target from the DB and runs the diff.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("phantomsignal.intel.asm_diff")

# Per result_type, the data fields that identify the *same asset* across scans.
# Anything not listed falls back to a hash of its whole data payload.
IDENTITY_FIELDS: Dict[str, Tuple[str, ...]] = {
    "open_port":            ("port",),
    "subdomain":            ("subdomain",),
    "ip_address":           ("ip", "value"),
    "technology":           ("name",),
    "cert_transparency":    ("value",),
    "ransomware_exposure":  ("victim", "group"),
    "credential_exposure":  ("identity", "host"),
    "username_account":     ("site", "username"),
    "email_account":        ("service",),
    "email_linked_account": ("service", "handle"),
    "linked_identity":      ("kind", "value"),
    "document_metadata":    ("url",),
    "nsec_zone_walk":       ("domain",),
    "dns_cache_snoop":      ("nameserver",),
    "smtp_users":           ("host",),
    "snmp_community":       ("community",),
    "os_detection":         ("os_name",),
    "passive_os":           ("os_family",),
    "tls_certificate":      ("sha256",),
}


# Aggregate/meta results that describe a scan, not an asset — never diffed.
def _is_skippable(result_type: str) -> bool:
    return (not result_type
            or result_type.endswith("_summary")
            or result_type in ("asm_change", "asm_diff_summary"))


# New assets of these types are alerts (anomalies) when they appear.
SENSITIVE_TYPES = {
    "open_port", "subdomain", "ransomware_exposure", "credential_exposure",
    "username_account", "email_account", "linked_identity", "cert_transparency",
    "dns_cache_snoop", "nsec_zone_walk", "smtp_users", "snmp_community",
    "document_metadata",
}
# Fields that change every scan without being a real surface change.
_VOLATILE = {"timestamp", "discovered", "attack_date", "last_seen", "first_seen",
             "scan_engine", "pivot_depth", "pivot_parent", "confidence"}


def _rtype(result: Dict) -> str:
    return result.get("result_type") or result.get("type") or ""


def result_key(result: Dict) -> Optional[Tuple[str, str]]:
    """Stable (result_type, identity) for an asset, or None if it shouldn't diff."""
    rt = _rtype(result)
    if _is_skippable(rt):
        return None
    data = result.get("data") or {}
    fields = IDENTITY_FIELDS.get(rt)
    if fields:
        parts = [str(data.get(f, "")).strip().lower() for f in fields]
        if any(parts):
            return (rt, "|".join(parts))
    # fallback: identity = canonical hash of the full (non-volatile) data
    return (rt, _canonical(data))


def _canonical(data: Dict) -> str:
    clean = {k: v for k, v in (data or {}).items() if k not in _VOLATILE}
    return json.dumps(clean, sort_keys=True, default=str)


def state_signature(result: Dict) -> str:
    """Signature of an asset's mutable state (used to detect modification)."""
    return _canonical(result.get("data") or {})


def changed_fields(old: Dict, new: Dict) -> List[str]:
    od, nd = old.get("data") or {}, new.get("data") or {}
    keys = (set(od) | set(nd)) - _VOLATILE
    return sorted(k for k in keys if od.get(k) != nd.get(k))


@dataclass
class AsmDiff:
    added: List[Dict] = field(default_factory=list)
    removed: List[Dict] = field(default_factory=list)
    modified: List[Tuple[Dict, Dict]] = field(default_factory=list)  # (old, new)

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.modified)


def _index(results: List[Dict]) -> Dict[Tuple[str, str], Dict]:
    idx: Dict[Tuple[str, str], Dict] = {}
    for r in results or []:
        key = result_key(r)
        if key and key not in idx:      # first occurrence wins on duplicate keys
            idx[key] = r
    return idx


def diff_results(old: List[Dict], new: List[Dict]) -> AsmDiff:
    """Compare two result sets → added / removed / modified assets. Pure."""
    old_idx, new_idx = _index(old), _index(new)
    old_keys, new_keys = set(old_idx), set(new_idx)

    added = [new_idx[k] for k in sorted(new_keys - old_keys)]
    removed = [old_idx[k] for k in sorted(old_keys - new_keys)]
    modified = [
        (old_idx[k], new_idx[k])
        for k in sorted(new_keys & old_keys)
        if state_signature(old_idx[k]) != state_signature(new_idx[k])
    ]
    return AsmDiff(added=added, removed=removed, modified=modified)


def build_diff_findings(target: str, diff: AsmDiff,
                        baseline: Optional[Dict] = None,
                        current: Optional[Dict] = None) -> List[Dict]:
    """Render an AsmDiff as PhantomSignal result findings."""
    results: List[Dict] = []

    def change(kind: str, res: Dict, extra: Optional[Dict] = None) -> Dict:
        rt = _rtype(res)
        alert = kind == "new" and (rt in SENSITIVE_TYPES or res.get("is_anomaly"))
        return {
            "type":   "asm_change",
            "source": "asm_diff",
            "data": {"target": target, "change": kind, "asset_type": rt,
                     "key": (result_key(res) or (rt, ""))[1],
                     "asset": res.get("data", {}), **(extra or {})},
            "confidence":      1.0,
            "relevance_score": 0.9 if alert else 0.5,
            "tags":            ["asm", "diff", kind, rt],
            "is_anomaly":      bool(alert),
        }

    for r in diff.added:
        results.append(change("new", r))
    for r in diff.removed:
        results.append(change("removed", r))
    for old, new in diff.modified:
        results.append(change("changed", new, {"changed_fields": changed_fields(old, new)}))

    results.append({
        "type":   "asm_diff_summary",
        "source": "asm_diff",
        "data": {
            "target":        target,
            "new_assets":    len(diff.added),
            "removed_assets": len(diff.removed),
            "changed_assets": len(diff.modified),
            "new_sensitive": sum(1 for r in diff.added if _rtype(r) in SENSITIVE_TYPES),
            "baseline_scan": (baseline or {}).get("id"),
            "current_scan":  (current or {}).get("id"),
        },
        "confidence":      1.0,
        "relevance_score": 0.9 if not diff.is_empty else 0.4,
        "tags":            ["asm", "diff", "summary"],
        "is_anomaly":      any(_rtype(r) in SENSITIVE_TYPES for r in diff.added),
    })
    return results


class ASMDiffer:
    """Diff the two most recent completed scans of a target (DB-backed)."""

    def __init__(self, config=None):
        self.config = config

    def diff_target(self, target: str) -> List[Dict]:
        from phantomsignal.core.database import get_db
        from phantomsignal.core.models import Scan, ScanStatus

        with get_db() as db:
            scans = (db.query(Scan)
                     .filter(Scan.target == target, Scan.status == ScanStatus.COMPLETE)
                     .order_by(Scan.completed_at.desc())
                     .limit(2).all())
            if len(scans) < 2:
                logger.info("ASM diff needs 2 completed scans of %s (have %d)",
                            target, len(scans))
                return []
            current, baseline = scans[0], scans[1]
            new_results = [r.to_dict() for r in current.results]
            old_results = [r.to_dict() for r in baseline.results]
            meta_new = {"id": current.id}
            meta_old = {"id": baseline.id}

        diff = diff_results(old_results, new_results)
        return build_diff_findings(target, diff, meta_old, meta_new)
