"""PhantomSignal Locate Routes — person geographic-footprint cases (spec §13)."""
from __future__ import annotations

import asyncio

from flask import (
    Blueprint, Response, flash, redirect, render_template, request, url_for,
)

from phantomsignal.core.config import config
from phantomsignal.core.database import get_db
from phantomsignal.intel.geo import store
from phantomsignal.intel.geo.engine import GeoEngine
from phantomsignal.intel.geo.export import to_geojson, to_kml, to_report

locate_bp = Blueprint("locate", __name__)


def _map_cfg():
    return {
        "enabled": bool(config.get("geo", "map_tiles", default=True)),
        "tile_url": config.get("geo", "tile_url",
                               default="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"),
        "attribution": config.get("geo", "tile_attribution", default="© OpenStreetMap contributors"),
    }


@locate_bp.route("/")
def list_cases():
    with get_db() as db:
        cases = store.list_cases(db)
    return render_template("locate/list.html", cases=cases)


@locate_bp.route("/new", methods=["POST"])
def new_case():
    ids = {k: (request.form.get(k) or "").strip() or None
           for k in ("first_name", "last_name", "email", "username")}
    if not any(ids.values()):
        flash("At least one identifier is required to open a case.", "error")
        return redirect(url_for("locate.list_cases"))

    purpose = (request.form.get("purpose") or "").strip()
    opened_by = (request.form.get("opened_by") or "operator").strip()
    sensitivity = "minor" if request.form.get("minor") == "on" else "normal"
    subject = " ".join(filter(None, [ids.get("first_name"), ids.get("last_name")])) \
        or ids.get("email") or ids.get("username") or "subject"

    # Collection: run the Profiler (degrades to public fallback without keys),
    # then extract + geocode geo signals. Best-effort; the case opens regardless.
    from phantomsignal.intel.people.aggregator import ShadowProfileBuilder
    profile, signals = {}, []
    loop = asyncio.new_event_loop()
    try:
        profile = loop.run_until_complete(asyncio.wait_for(
            ShadowProfileBuilder(config).build_profile(
                first_name=ids.get("first_name"), last_name=ids.get("last_name"),
                email=ids.get("email"), username=ids.get("username")),
            timeout=45)) or {}
    except Exception:
        profile = {}
    try:
        if profile:
            signals = loop.run_until_complete(GeoEngine(config).signals_for(profile, geocode=True))
    except Exception:
        signals = []
    finally:
        loop.close()

    with get_db() as db:
        case_id = store.open_case(db, subject=subject, identifiers=ids, purpose=purpose,
                                  opened_by=opened_by, sensitivity=sensitivity)
        n = store.persist_signals(db, case_id, signals, actor=opened_by) if signals else 0
    flash(f"Case opened for {subject} — {n} geo signal(s) collected.", "success")
    return redirect(url_for("locate.case_view", case_id=case_id))


@locate_bp.route("/<case_id>")
def case_view(case_id):
    with get_db() as db:
        from phantomsignal.core.models import LocateCase
        case = db.query(LocateCase).filter(LocateCase.id == case_id).first()
        if not case:
            flash("Case not found.", "error")
            return redirect(url_for("locate.list_cases"))
        case_dict = case.to_dict()
        footprint = store.footprint_for_case(db, case_id, subject=case.subject or "subject")
        audit = store.list_audit(db, case_id)
    return render_template("locate/case.html", case=case_dict, footprint=footprint,
                           audit=audit, mapcfg=_map_cfg())


@locate_bp.route("/<case_id>/signal", methods=["POST"])
def add_signal(case_id):
    kind = request.form.get("kind", "stated_location")
    polarity = "negative" if request.form.get("polarity") == "negative" else "positive"
    place = {k: (request.form.get(k) or "").strip() or None
             for k in ("city", "region", "country", "zip")}
    actor = (request.form.get("opened_by") or "operator").strip()
    if not any(place.values()):
        flash("A place is required for a manual signal.", "error")
        return redirect(url_for("locate.case_view", case_id=case_id))
    with get_db() as db:
        store.add_manual_signal(db, case_id, kind=kind, place=place, polarity=polarity,
                                source="manual", actor=actor,
                                observed_at=(request.form.get("observed_at") or None))
    flash("Signal added.", "success")
    return redirect(url_for("locate.case_view", case_id=case_id))


@locate_bp.route("/<case_id>/signal/<signal_id>/delete", methods=["POST"])
def delete_signal(case_id, signal_id):
    actor = (request.form.get("opened_by") or "operator").strip()
    with get_db() as db:
        removed = store.delete_signal(db, case_id, signal_id, actor=actor)
    flash("Signal removed." if removed else "Signal not found.",
          "success" if removed else "error")
    return redirect(url_for("locate.case_view", case_id=case_id))


@locate_bp.route("/<case_id>/delete", methods=["POST"])
def delete_case(case_id):
    with get_db() as db:
        removed = store.delete_case(db, case_id)
    flash("Case purged." if removed else "Case not found.",
          "success" if removed else "error")
    return redirect(url_for("locate.list_cases"))


_EXPORTS = {
    "geojson": (to_geojson, "application/geo+json", "footprint.geojson"),
    "kml": (to_kml, "application/vnd.google-earth.kml+xml", "footprint.kml"),
    "report": (to_report, "text/markdown; charset=utf-8", "footprint.md"),
}


@locate_bp.route("/<case_id>/export/<fmt>")
def export(case_id, fmt):
    if fmt not in _EXPORTS:
        flash("Unknown export format.", "error")
        return redirect(url_for("locate.case_view", case_id=case_id))
    render, mime, fname = _EXPORTS[fmt]
    with get_db() as db:
        footprint = store.footprint_for_case(db, case_id)
        store.audit(db, case_id, "operator", "exported", source=fmt, detail=fname)
    body = render(footprint)
    return Response(body, mimetype=mime,
                    headers={"Content-Disposition": f"attachment; filename={case_id[:8]}-{fname}"})
