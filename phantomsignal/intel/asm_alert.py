"""
PhantomSignal ASM Alert — New-Asset Alerting for Continuous Monitoring

Phase 5b. Companion to asm_diff: once a scan auto-diffs against its baseline, the
new *sensitive* assets (a fresh subdomain, open port, leak, credential exposure)
are the things an operator wants pushed to them — not buried in a report. This
module turns diff findings into an alert payload and delivers it to the webhook
configured under `notifications.webhook_url`.

Design mirrors asm_diff: the payload builder is pure (works on the finding dicts,
no network/DB) and fully unit-tested; `send_alert` is the thin async HTTP layer.
The payload carries both `text` (Slack incoming-webhook shape) and `content`
(Discord shape) so a single generic POST works against either, plus structured
fields for a custom endpoint.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger("phantomsignal.intel.asm_alert")

# Cap how many assets we enumerate in the human-readable message so a big diff
# doesn't produce a wall of text (the structured `assets` list stays complete).
_MSG_ASSET_LIMIT = 25


def diff_summary(findings: List[Dict]) -> Dict:
    """Pull the asm_diff_summary payload out of a diff finding list ({} if none)."""
    for f in findings or []:
        if f.get("type") == "asm_diff_summary":
            return f.get("data") or {}
    return {}


def new_sensitive_changes(findings: List[Dict]) -> List[Dict]:
    """The asm_change findings that are *new sensitive* assets — the alerts."""
    return [
        f for f in findings or []
        if f.get("type") == "asm_change"
        and (f.get("data") or {}).get("change") == "new"
        and f.get("is_anomaly")
    ]


def build_alert_payload(target: str, findings: List[Dict]) -> Optional[Dict]:
    """Render diff findings as a webhook payload, or None if nothing to alert on."""
    sensitive = new_sensitive_changes(findings)
    if not sensitive:
        return None

    summary = diff_summary(findings)
    assets = [
        {"type": (c.get("data") or {}).get("asset_type", ""),
         "key":  (c.get("data") or {}).get("key", "")}
        for c in sensitive
    ]
    bullets = "\n".join(f"• {a['type']}: {a['key']}" for a in assets[:_MSG_ASSET_LIMIT])
    if len(assets) > _MSG_ASSET_LIMIT:
        bullets += f"\n• …and {len(assets) - _MSG_ASSET_LIMIT} more"
    text = (f"\U0001F6D1 PhantomSignal ASM alert — {len(sensitive)} new sensitive "
            f"asset(s) on {target}\n{bullets}")

    return {
        "text":           text,   # Slack incoming-webhook
        "content":        text,   # Discord webhook
        "target":         target,
        "new_sensitive":  len(sensitive),
        "new_assets":     summary.get("new_assets", 0),
        "changed_assets": summary.get("changed_assets", 0),
        "removed_assets": summary.get("removed_assets", 0),
        "assets":         assets,
    }


async def send_alert(url: str, payload: Optional[Dict], timeout: float = 10.0) -> bool:
    """POST an alert payload to a webhook. Best-effort — never raises."""
    if not url or not payload:
        return False
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload)
        ok = 200 <= resp.status_code < 300
        if not ok:
            logger.warning("ASM alert webhook returned HTTP %s", resp.status_code)
        return ok
    except Exception as exc:  # network error, bad URL, DNS, timeout…
        logger.warning("ASM alert webhook delivery failed: %s", exc)
        return False
