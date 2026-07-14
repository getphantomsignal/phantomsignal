"""
Export a footprint to handoff formats (spec §9): GeoJSON and KML for mapping
tools, and a sourced Markdown report for an investigator / LE handoff. Every
point carries its source, timestamp, and confidence.
"""
from __future__ import annotations

import io
import json
import zipfile
from typing import Dict, List


def to_geojson(footprint: Dict) -> str:
    features = []
    for c in footprint.get("clusters", []):
        if c.get("lat") is None or c.get("lon") is None:
            continue
        features.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [c["lon"], c["lat"]]},
            "properties": {
                "label": c["label"],
                "confidence": c["combined_confidence"],
                "signals": c["signal_count"],
                "sources": c["sources"],
                "kinds": c["kinds"],
                "eliminated": c.get("eliminated", False),
            },
        })
    return json.dumps({"type": "FeatureCollection", "features": features}, indent=2)


def to_kml(footprint: Dict) -> str:
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>',
             f'<name>Footprint — {_esc(footprint.get("subject", "subject"))}</name>']
    lk = footprint.get("last_known")
    for c in footprint.get("clusters", []):
        if c.get("lat") is None or c.get("lon") is None:
            continue
        is_lk = lk and lk.get("label") == c["label"]
        parts.append(
            "<Placemark>"
            f"<name>{_esc(c['label'])}{' (last known)' if is_lk else ''}</name>"
            f"<description>confidence {c['combined_confidence']:.2f} · "
            f"{c['signal_count']} signal(s) · {_esc(', '.join(c['sources']))}</description>"
            f"<Point><coordinates>{c['lon']},{c['lat']},0</coordinates></Point>"
            "</Placemark>"
        )
    parts.append("</Document></kml>")
    return "".join(parts)


def to_report(footprint: Dict) -> str:
    lines: List[str] = []
    subj = footprint.get("subject", "subject")
    lines.append(f"# Location footprint — {subj}")
    lines.append("")
    if footprint.get("sensitivity") == "minor":
        lines.append("> **⚠ MINOR SUBJECT — extra-sensitive.** Handle per child-protection "
                     "protocol: minimize distribution and route to law enforcement.")
        lines.append("")
    ret = footprint.get("retention") or {}
    if ret.get("expired"):
        lines.append(f"> **⚑ Past retention** ({ret['until']}) — this case is due for purge.")
        lines.append("")
    elif ret.get("set"):
        lines.append(f"_Retention until {ret['until']} ({ret['days_left']} days left)._")
        lines.append("")
    lk = footprint.get("last_known")
    if lk:
        lines.append(f"**Last-known:** {lk['label']} — confidence {lk['confidence']:.2f}, "
                     f"±{lk['radius_km']:.0f} km, {lk['corroboration']} corroborating signal(s)"
                     f"{', as of ' + lk['as_of'] if lk.get('as_of') else ''}.")
    else:
        lines.append("**Last-known:** insufficient signal.")
    lines.append("")

    grid = footprint.get("search_grid", [])
    if grid:
        lines.append("## Prioritized search grid (where to look next)")
        for i, g in enumerate(grid, 1):
            lines.append(f"{i}. **{g['label']}** — {g['pol']} "
                         f"(score {g['score']:.2f}, confidence {g['confidence']:.2f}"
                         f"{', ±%.0f km' % g['radius_km'] if g.get('radius_km') else ''}) — {g['why']}")
        lines.append("")

    conflicts = footprint.get("conflicts", [])
    if conflicts:
        lines.append("## ⚠ Conflicts")
        for cf in conflicts:
            lines.append(f"- {cf.get('detail', cf.get('type'))}")
        lines.append("")

    lines.append("## Candidate areas (ranked)")
    for c in footprint.get("clusters", []):
        tag = " — ELIMINATED" if c.get("eliminated") else ""
        lines.append(f"- **{c['label']}**{tag} — confidence {c['combined_confidence']:.2f}, "
                     f"{c['signal_count']} signal(s) [{', '.join(c['kinds'])}]")
    lines.append("")

    scrubbed = [s for s in footprint.get("signals", []) if s.get("scrubbed")]
    if scrubbed:
        lines.append("## ⚑ Scrubbed locations (archived, now removed)")
        for s in scrubbed:
            loc = s["place"] or {}
            label = ", ".join(str(v) for v in (loc.get("city"), loc.get("region"), loc.get("country")) if v) or "—"
            lines.append(f"- **{label}** — seen {s.get('observed_at') or 'undated'} in {s['source']}"
                         f"{', ' + s['source_url'] if s.get('source_url') else ''}, absent from the current profile.")
        lines.append("")

    lines.append("## Signals (sourced)")
    for s in footprint.get("signals", []):
        loc = s["place"] or {}
        label = ", ".join(str(v) for v in (loc.get("city"), loc.get("region"), loc.get("country")) if v) or "—"
        src = s["source"] + (f" — {s['source_url']}" if s.get("source_url") else "")
        when = s.get("observed_at") or "undated"
        pol = "NEG " if s.get("polarity") == "negative" else ""
        flag = " ⚑scrubbed" if s.get("scrubbed") else ""
        lines.append(f"- {pol}[{s['kind']}]{flag} {label} · eff {s['effective_confidence']:.2f} "
                     f"(kind {s['kind_confidence']:.2f} × attr {s['attribution_confidence']:.2f}) · "
                     f"{when} · {src}")
    lines.append("")
    lines.append("_Historical footprint reconstructed from public/licensed signals. "
                 "Verify before action._")
    return "\n".join(lines)


def audit_log_text(audit: List[Dict]) -> str:
    """Chain of custody as a plain-text log for the handoff bundle."""
    lines = ["Chain of custody", "================", ""]
    for a in audit:
        src = f" [{a['source']}]" if a.get("source") else ""
        detail = f" — {a['detail']}" if a.get("detail") else ""
        lines.append(f"{a.get('at', '')} · {a.get('action', '')}{src}{detail} · {a.get('actor') or '—'}")
    return "\n".join(lines) + "\n"


def bundle_zip(footprint: Dict, audit: List[Dict]) -> bytes:
    """One handoff artifact: sourced report + GeoJSON + KML + chain of custody."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.md", to_report(footprint))
        z.writestr("footprint.geojson", to_geojson(footprint))
        z.writestr("footprint.kml", to_kml(footprint))
        z.writestr("chain-of-custody.txt", audit_log_text(audit))
    return buf.getvalue()


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
