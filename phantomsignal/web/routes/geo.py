"""PhantomSignal Geo Recon routes — place → internet-facing assets (spec §13)."""
from __future__ import annotations

import asyncio

from flask import Blueprint, render_template, request

from phantomsignal.core.config import config
from phantomsignal.intel.geo.geo_recon import GeoReconEngine, parse_latlon
from phantomsignal.web.routes.locate import _map_cfg

geo_bp = Blueprint("geo", __name__)


@geo_bp.route("/", methods=["GET", "POST"])
def recon():
    result, form = None, {}
    if request.method == "POST":
        form = {k: (request.form.get(k) or "").strip() for k in
                ("country", "city", "coords", "radius_km", "org", "domain")}
        latlon = parse_latlon(form.get("coords"))
        kwargs = {
            "country": form.get("country") or None,
            "city": form.get("city") or None,
            "org": form.get("org") or None,
            "domain": form.get("domain") or None,
            "lat": latlon[0] if latlon else None,
            "lon": latlon[1] if latlon else None,
            "radius_km": float(form["radius_km"]) if form.get("radius_km") else None,
        }
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                asyncio.wait_for(GeoReconEngine(config).recon(**kwargs), timeout=40))
        except Exception:
            result = {"query": None, "assets": [], "summary": {}, "configured": False,
                      "center": None, "error": "recon failed"}
        finally:
            loop.close()
    return render_template("geo/recon.html", result=result, form=form, mapcfg=_map_cfg())
