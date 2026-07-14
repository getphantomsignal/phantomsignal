"""
Case retention (spec §10). A person Locate case can carry a ``retention_until``
horizon; past it the case is flagged for purge (evidence isn't kept indefinitely).
Pure date logic — no DB — so it's easy to test and reuse.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

# Retention presets offered at case open (days). None = keep until manual purge.
PRESETS = [30, 90, 180, 365]
# Minor subjects default to a conservative horizon when none is chosen (§10).
MINOR_DEFAULT_DAYS = 90


def until_iso(days: Optional[int]) -> Optional[str]:
    """A retention horizon ``days`` from today as an ISO date, or None for keep."""
    try:
        d = int(days)
    except (TypeError, ValueError):
        return None
    if d <= 0:
        return None
    return (datetime.now(timezone.utc).date() + timedelta(days=d)).isoformat()


def status(retention_until: Optional[str], *, now: Optional[datetime] = None) -> Dict:
    """{'set', 'until', 'expired', 'days_left'} for a stored retention date."""
    today = (now or datetime.now(timezone.utc)).date()
    if not retention_until:
        return {"set": False, "until": None, "expired": False, "days_left": None}
    try:
        until = datetime.fromisoformat(str(retention_until)[:10]).date()
    except ValueError:
        return {"set": False, "until": None, "expired": False, "days_left": None}
    days_left = (until - today).days
    return {"set": True, "until": until.isoformat(),
            "expired": days_left < 0, "days_left": days_left}
